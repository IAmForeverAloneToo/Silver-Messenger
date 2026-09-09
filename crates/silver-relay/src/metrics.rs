//! What an operator can watch: a Prometheus endpoint on a listener of its
//! own, meant for loopback or a private network and never the public one,
//! and a count of failed logins per address behind a warning and two
//! aggregate numbers.
//!
//! Client addresses appear in the warning line at `warn`, where alerting
//! on the log can pick them up, and never in the metrics: a time series
//! is a place an address would sit for a long time, and the hourly
//! summary already keeps addresses out of the journal for the same reason.
//! The text format is written by hand; it is a dozen lines of `# HELP`,
//! `# TYPE` and samples, not worth a dependency.

use std::collections::HashMap;
use std::fmt::Display;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, UNIX_EPOCH};

use axum::Router;
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse;
use axum::routing::get;
use tokio::net::TcpListener;

use crate::RelayState;
use crate::tls::{self, CertStore};

/// Failed logins from one address within [`AUTH_FAILURE_WINDOW`] that
/// earn a warning in the log.
pub const AUTH_FAILURE_WARN: u32 = 20;
pub const AUTH_FAILURE_WINDOW: Duration = Duration::from_secs(3600);
/// Addresses tracked at most; past that the oldest window goes, so a
/// flood from many addresses cannot grow memory without bound.
const MAX_TRACKED: usize = 10_000;

/// Failed logins, in total and per address over the last hour.
#[derive(Default)]
pub struct AuthFailures {
    total: AtomicU64,
    windows: Mutex<HashMap<IpAddr, Window>>,
}

struct Window {
    count: u32,
    since: Instant,
    warned: bool,
}

fn prune(windows: &mut HashMap<IpAddr, Window>, now: Instant) {
    windows.retain(|_, w| now.duration_since(w.since) < AUTH_FAILURE_WINDOW);
}

impl AuthFailures {
    /// Record a failure from `addr`. `Some(count)` the first time the
    /// address reaches [`AUTH_FAILURE_WARN`] within its window, so the
    /// caller can warn once rather than on every further attempt.
    pub fn note(&self, addr: IpAddr, now: Instant) -> Option<u32> {
        self.total.fetch_add(1, Ordering::Relaxed);
        let mut windows = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        prune(&mut windows, now);
        if windows.len() >= MAX_TRACKED
            && !windows.contains_key(&addr)
            && let Some(oldest) = windows.iter().min_by_key(|(_, w)| w.since).map(|(a, _)| *a)
        {
            windows.remove(&oldest);
        }
        let window = windows.entry(addr).or_insert(Window {
            count: 0,
            since: now,
            warned: false,
        });
        window.count += 1;
        if window.count >= AUTH_FAILURE_WARN && !window.warned {
            window.warned = true;
            Some(window.count)
        } else {
            None
        }
    }

    /// Failed logins since the relay started.
    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    /// Addresses with failures in the current window, and the most from
    /// any one of them.
    pub fn in_window(&self, now: Instant) -> (usize, u32) {
        let mut windows = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        prune(&mut windows, now);
        (
            windows.len(),
            windows.values().map(|w| w.count).max().unwrap_or(0),
        )
    }
}

/// Prometheus text exposition, version 0.0.4.
pub const CONTENT_TYPE_TEXT: &str = "text/plain; version=0.0.4; charset=utf-8";

struct Text(String);

impl Text {
    fn header(&mut self, name: &str, kind: &str, help: &str) {
        self.0
            .push_str(&format!("# HELP {name} {help}\n# TYPE {name} {kind}\n"));
    }

    fn sample(&mut self, name: &str, labels: &[(&str, &str)], value: impl Display) {
        self.0.push_str(name);
        if !labels.is_empty() {
            self.0.push('{');
            for (i, (k, v)) in labels.iter().enumerate() {
                if i > 0 {
                    self.0.push(',');
                }
                self.0.push_str(&format!("{k}=\"{}\"", escape(v)));
            }
            self.0.push('}');
        }
        self.0.push_str(&format!(" {value}\n"));
    }

    fn gauge(&mut self, name: &str, help: &str, value: impl Display) {
        self.header(name, "gauge", help);
        self.sample(name, &[], value);
    }

    fn counter(&mut self, name: &str, help: &str, value: impl Display) {
        self.header(name, "counter", help);
        self.sample(name, &[], value);
    }
}

fn escape(label: &str) -> String {
    label
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Everything the relay can say about itself right now.
pub fn render(state: &RelayState, tls: Option<&CertStore>) -> String {
    let now = Instant::now();
    let c = state.counters();
    let s = state.stats();
    let policy = state.policy();
    let (failing_addresses, failures_max) = state.auth_failures().in_window(now);
    let mut t = Text(String::new());

    t.header(
        "silver_relay_info",
        "gauge",
        "The relay's version, as a label.",
    );
    t.sample(
        "silver_relay_info",
        &[("version", env!("CARGO_PKG_VERSION"))],
        1,
    );
    t.gauge(
        "silver_relay_uptime_seconds",
        "Seconds since the relay started.",
        state.uptime().as_secs(),
    );
    t.gauge(
        "silver_relay_connections_open",
        "Client connections open right now.",
        c.open_connections,
    );
    t.gauge(
        "silver_relay_connections_limit",
        "Client connections allowed at once (0 for no limit).",
        policy.max_connections,
    );
    t.gauge(
        "silver_relay_connected_addresses",
        "Distinct client addresses with a connection open or recently closed.",
        c.addresses,
    );
    t.header(
        "silver_relay_refused_total",
        "counter",
        "Requests the limits refused since start, by what was refused.",
    );
    t.sample(
        "silver_relay_refused_total",
        &[("reason", "connection")],
        c.refused_connections,
    );
    t.sample(
        "silver_relay_refused_total",
        &[("reason", "registration")],
        c.refused_registrations,
    );
    t.sample(
        "silver_relay_refused_total",
        &[("reason", "upload")],
        c.refused_uploads,
    );
    t.counter(
        "silver_relay_idle_closed_total",
        "Connections closed for staying silent past the idle timeout.",
        c.idle_closed,
    );
    t.counter(
        "silver_relay_slow_closed_total",
        "Connections closed because the client stopped reading what was written to it.",
        c.slow_closed,
    );
    t.counter(
        "silver_relay_anonymous_submissions_total",
        "Envelopes submitted on connections that never authenticated.",
        state.anonymous_submission_count(),
    );
    t.counter(
        "silver_relay_auth_failures_total",
        "Logins refused for a bad signature or an unsupported login form.",
        state.auth_failures().total(),
    );
    t.gauge(
        "silver_relay_auth_failure_addresses",
        "Addresses with a failed login in the last hour.",
        failing_addresses,
    );
    t.gauge(
        "silver_relay_auth_failures_max_per_address",
        "Most failed logins from any one address in the last hour.",
        failures_max,
    );
    t.gauge(
        "silver_relay_identities",
        "Identities with a key bundle on this relay.",
        s.bundles,
    );
    t.gauge(
        "silver_relay_mailboxes",
        "Recipients with at least one envelope waiting.",
        s.mailboxes,
    );
    t.gauge(
        "silver_relay_messages_queued",
        "Envelopes waiting to be acknowledged.",
        s.messages,
    );
    t.gauge(
        "silver_relay_mailbox_bytes",
        "Bytes of envelopes waiting.",
        s.bytes,
    );
    t.gauge("silver_relay_blobs", "Encrypted files on deposit.", s.blobs);
    t.gauge(
        "silver_relay_blob_bytes",
        "Bytes of encrypted file chunks on deposit.",
        s.blob_bytes,
    );
    t.gauge(
        "silver_relay_blob_bytes_limit",
        "Bytes of encrypted file chunks the relay keeps at most.",
        u64::from(policy.blob_storage_mib) * 1024 * 1024,
    );
    t.gauge(
        "silver_relay_key_packages",
        "MLS key packages on deposit, last-resort ones not counted.",
        s.key_packages,
    );
    t.gauge(
        "silver_relay_groups",
        "Groups with a live epoch sequencer entry.",
        s.groups,
    );
    t.gauge(
        "silver_relay_retired_groups",
        "Sequencer entries retired for sitting still, kept so the group ids stay taken.",
        s.retired_groups,
    );
    t.gauge(
        "silver_relay_groups_limit",
        "Group sequencer entries kept at most (0 for no limit).",
        policy.max_groups,
    );
    t.counter(
        "silver_relay_group_commits_total",
        "Group commits the epoch sequencer accepted.",
        c.group_commits,
    );
    t.counter(
        "silver_relay_group_rejections_total",
        "Group commits the epoch sequencer refused (stale, unknown or wrong token).",
        c.group_rejections,
    );
    t.gauge(
        "silver_relay_devices",
        "Linked devices: identities whose bundle carries a device certificate.",
        s.devices,
    );
    t.counter(
        "silver_relay_device_revocations_total",
        "Device revocations held, which nothing removes.",
        s.device_revocations,
    );
    if let Some(store) = tls {
        let expiry = store
            .current()
            .and_then(|k| tls::not_after(&k.cert[0]).ok())
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        t.gauge(
            "silver_relay_certificate_expiry_seconds",
            "When the certificate being served expires, as Unix time; 0 while there is none.",
            expiry,
        );
        t.counter(
            "silver_relay_acme_failures_total",
            "Attempts to obtain or renew the certificate that failed.",
            store.acme_failures(),
        );
    }
    t.0
}

#[derive(Clone)]
struct MetricsState {
    state: Arc<RelayState>,
    tls: Option<Arc<CertStore>>,
}

async fn metrics(State(m): State<MetricsState>) -> impl IntoResponse {
    (
        [(CONTENT_TYPE, CONTENT_TYPE_TEXT)],
        render(&m.state, m.tls.as_deref()),
    )
}

/// `GET /metrics`, and nothing else.
pub fn router(state: Arc<RelayState>, tls: Option<Arc<CertStore>>) -> Router {
    Router::new()
        .route("/metrics", get(metrics))
        .with_state(MetricsState { state, tls })
}

/// Connections the metrics listener serves at once. It answers one small
/// document; anything beyond a handful at a time is a scrape that has
/// stopped reading or something that is not a scraper.
const METRICS_MAX_CONNECTIONS: usize = 16;
/// A metrics connection gets this long to make its request and read the
/// answer, all in.
const METRICS_TIMEOUT: Duration = Duration::from_secs(15);

/// Serve the metrics on `listener` until the task is dropped.
///
/// Bounded, unlike the plain `axum::serve` this replaced. The main
/// listener installs a timer and a header-read timeout for a reason
/// [`crate::set_http_timeouts`] spells out -- a connection that says
/// nothing holds a socket and a task until the process runs out of file
/// descriptors, below every limit the relay counts -- and this listener
/// was never given either, nor a cap on how many connections it would
/// take at once. Running out of descriptors stops the relay, not merely
/// the metrics. The port is meant to be bound to loopback or a management
/// network; this is what makes an operator who binds it somewhere else
/// wrong about their monitoring rather than wrong about their relay.
pub async fn serve(
    listener: TcpListener,
    state: Arc<RelayState>,
    tls: Option<Arc<CertStore>>,
) -> anyhow::Result<()> {
    let app = router(state, tls);
    let permits = Arc::new(tokio::sync::Semaphore::new(METRICS_MAX_CONNECTIONS));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            // Out of descriptors, or the peer went away between the
            // kernel accepting and us asking. Neither is a reason to stop
            // serving metrics for the life of the process.
            Err(e) => {
                tracing::debug!("metrics accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            // Dropping the stream closes it. A scraper retries; a client
            // holding connections open learns nothing.
            tracing::debug!(%peer, "metrics connection refused: too many at once");
            continue;
        };
        let service = app.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let mut builder =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
            // The same header-read timeout the main listener sets, for the
            // same reason its comment gives.
            crate::set_http_timeouts(&mut builder);
            let served = tokio::time::timeout(
                METRICS_TIMEOUT,
                builder.serve_connection(
                    hyper_util::rt::TokioIo::new(stream),
                    hyper_util::service::TowerToHyperService::new(service),
                ),
            )
            .await;
            if served.is_err() {
                tracing::debug!(%peer, "metrics connection timed out");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, n])
    }

    /// A connection that says nothing must not hold the metrics listener,
    /// and there is a limit to how many it will hold at once.
    ///
    /// This used to be a bare `axum::serve`: no connection cap, and no
    /// timer installed, so hyper discarded its own header-read default
    /// and a silent connection held a socket and a task for ever. Enough
    /// of them and the process runs out of file descriptors, which stops
    /// the relay and not just its metrics.
    #[tokio::test]
    async fn the_metrics_listener_does_not_hold_silent_connections() {
        use tokio::io::AsyncReadExt as _;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(super::serve(listener, RelayState::new(), None));

        // A scrape works.
        let body = tokio::time::timeout(Duration::from_secs(10), async {
            let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
            tokio::io::AsyncWriteExt::write_all(
                &mut c,
                b"GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
            let mut out = String::new();
            c.read_to_string(&mut out).await.unwrap();
            out
        })
        .await
        .expect("a scrape is answered");
        assert!(body.contains("silver_relay"), "{body}");

        // Connections that open and say nothing are dropped rather than
        // held: each read returns end-of-file within the timeout, so none
        // of them is still occupying the listener at the end.
        let mut silent = Vec::new();
        for _ in 0..METRICS_MAX_CONNECTIONS + 8 {
            if let Ok(c) = tokio::net::TcpStream::connect(addr).await {
                silent.push(c);
            }
        }
        let opened = silent.len();
        for (i, mut c) in silent.into_iter().enumerate() {
            let mut buf = [0u8; 1];
            // Either the connection is refused outright (past the cap) or
            // it is closed when it fails to make a request in time. Both
            // end in end-of-file; the failure this guards against is
            // neither happening, which reads as a connection that stays
            // open with nothing to say.
            let ended = tokio::time::timeout(METRICS_TIMEOUT * 2, c.read(&mut buf)).await;
            assert!(
                matches!(ended, Ok(Ok(0))),
                "silent connection {i} of {opened} was still held: {ended:?}"
            );
        }

        // And the listener still serves afterwards, so nothing leaked.
        let again = tokio::time::timeout(Duration::from_secs(10), async {
            let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
            tokio::io::AsyncWriteExt::write_all(
                &mut c,
                b"GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
            let mut out = String::new();
            c.read_to_string(&mut out).await.unwrap();
            out
        })
        .await
        .expect("the listener still answers after a flood of silent connections");
        assert!(again.contains("silver_relay"), "{again}");
    }

    #[test]
    fn failures_warn_once_per_window_and_expire() {
        let failures = AuthFailures::default();
        let start = Instant::now();
        for i in 1..AUTH_FAILURE_WARN {
            assert_eq!(failures.note(addr(1), start), None, "attempt {i}");
        }
        assert_eq!(failures.note(addr(1), start), Some(AUTH_FAILURE_WARN));
        assert_eq!(failures.note(addr(1), start), None, "warned once");
        assert_eq!(failures.note(addr(2), start), None);
        assert_eq!(failures.total(), u64::from(AUTH_FAILURE_WARN) + 2);
        assert_eq!(failures.in_window(start), (2, AUTH_FAILURE_WARN + 1));

        // An hour on, the windows are gone and a new streak warns again.
        let later = start + AUTH_FAILURE_WINDOW;
        assert_eq!(failures.in_window(later), (0, 0));
        for _ in 1..AUTH_FAILURE_WARN {
            failures.note(addr(1), later);
        }
        assert_eq!(failures.note(addr(1), later), Some(AUTH_FAILURE_WARN));
    }

    #[test]
    fn tracked_addresses_are_bounded() {
        let failures = AuthFailures::default();
        let start = Instant::now();
        for i in 0..(MAX_TRACKED + 5) {
            let octets = (i as u32).to_be_bytes();
            let ip = IpAddr::from([octets[0], octets[1], octets[2], octets[3]]);
            failures.note(ip, start + Duration::from_millis(i as u64));
        }
        assert!(failures.in_window(start + Duration::from_secs(1)).0 <= MAX_TRACKED);
        assert_eq!(failures.total(), (MAX_TRACKED + 5) as u64);
    }

    #[test]
    fn the_text_format_is_well_formed() {
        let state = RelayState::new();
        state.note_auth_failure(addr(9));
        let text = render(&state, None);
        for name in [
            "silver_relay_info",
            "silver_relay_uptime_seconds",
            "silver_relay_connections_open",
            "silver_relay_refused_total",
            "silver_relay_auth_failures_total",
            "silver_relay_identities",
            "silver_relay_blob_bytes_limit",
            "silver_relay_devices",
            "silver_relay_device_revocations_total",
        ] {
            assert!(text.contains(&format!("# TYPE {name} ")), "{name} typed");
        }
        assert!(text.contains(&format!(
            "silver_relay_info{{version=\"{}\"}} 1\n",
            env!("CARGO_PKG_VERSION")
        )));
        assert!(text.contains("silver_relay_refused_total{reason=\"registration\"} 0\n"));
        assert!(text.contains("silver_relay_auth_failures_total 1\n"));
        assert!(text.contains("silver_relay_auth_failure_addresses 1\n"));
        assert!(
            !text.contains("10.0.0.9"),
            "addresses stay out of the metrics"
        );
        assert!(!text.contains("silver_relay_certificate_expiry_seconds"));
        // Every non-comment line is `name[{labels}] value`.
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let (name, value) = line.rsplit_once(' ').expect(line);
            assert!(name.starts_with("silver_relay_"), "{line}");
            assert!(value.parse::<f64>().is_ok(), "{line}");
        }
        assert_eq!(escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");

        // With a certificate store, the expiry and the failure count appear.
        let store = CertStore::new();
        store.note_acme_failure();
        let with_tls = render(&state, Some(&store));
        assert!(with_tls.contains("silver_relay_certificate_expiry_seconds 0\n"));
        assert!(with_tls.contains("silver_relay_acme_failures_total 1\n"));
    }
}
