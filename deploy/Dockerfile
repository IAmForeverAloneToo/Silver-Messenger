# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
# The relay in a container: a static binary and a CA bundle on an empty
# base, run as an unprivileged user, the database on a volume, the admin
# socket in /run/silver-relay.
#
# Build it at the repository root. Two ways to get the binary in:
#
#   * from source (the default): `docker build -f deploy/Dockerfile .`
#     builds the relay for the machine's own architecture, with the same
#     flags as a release, so the binary matches a release of the same
#     commit: `--build-arg SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)`;
#
#   * prebuilt: put release binaries at prebuilt/linux/amd64/silver-relay
#     and prebuilt/linux/arm64/silver-relay and build with
#     `--build-arg BINARY_FROM=prebuilt` for both platforms at once. The
#     release workflow does this, so the image carries the very binaries
#     the release publishes.
#
# With SOURCE_DATE_EPOCH set and BuildKit's `rewrite-timestamp=true` output
# option, the image is reproducible layer for layer.

ARG BINARY_FROM=source
# Pinned by digest, not by tag: a tag can be moved, and "a rebuild of the
# same release gives the same layers" only holds while the base resolves
# to the same image (SM-S-05). The Rust image matches the compiler
# rust-toolchain.toml pins; both are moved by hand.
ARG RUST_IMAGE=rust:1.98-alpine@sha256:a10e64dd139b7387337c7fbe8aca31b959b57b2fd4c8ae20a02cf1d6ea424dce
ARG ALPINE_IMAGE=alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce

# The CA bundle the ACME client needs to reach the certificate authority,
# and the two directories the relay writes to, owned by its user.
FROM --platform=$BUILDPLATFORM ${ALPINE_IMAGE} AS base
RUN apk add --no-cache ca-certificates \
    && mkdir -p -m 700 /out/var/lib/silver-relay /out/run/silver-relay

# A binary built elsewhere, chosen by the target architecture.
FROM --platform=$BUILDPLATFORM ${ALPINE_IMAGE} AS prebuilt
ARG TARGETARCH
COPY prebuilt/ /prebuilt/
RUN install -D -m 755 "/prebuilt/linux/${TARGETARCH}/silver-relay" /out/silver-relay

# Built here, natively for the target platform.
FROM ${RUST_IMAGE} AS source
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
ARG SOURCE_DATE_EPOCH=0
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    CARGO_INCREMENTAL=0 \
    RUSTFLAGS="--remap-path-prefix=/usr/local/cargo=/cargo"
RUN cargo build --release --locked -p silver-relay \
    && install -D -m 755 target/release/silver-relay /out/silver-relay

FROM ${BINARY_FROM} AS binary

FROM scratch
COPY --from=base /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=base --chown=1000:1000 /out/var/lib/silver-relay /var/lib/silver-relay
COPY --from=base --chown=1000:1000 /out/run/silver-relay /run/silver-relay
COPY --from=binary /out/silver-relay /usr/local/bin/silver-relay
ENV SILVER_RELAY_DATA=/var/lib/silver-relay \
    SILVER_RELAY_ADMIN_SOCKET=/run/silver-relay/admin.sock
USER 1000:1000
VOLUME ["/var/lib/silver-relay"]
# 443 with the built-in TLS (SILVER_RELAY_LISTEN=0.0.0.0:443 and
# SILVER_RELAY_ACME_DOMAIN), 7777 for plain WebSocket behind a TLS front.
EXPOSE 443 7777
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD ["/usr/local/bin/silver-relay", "admin", "status"]
ENTRYPOINT ["/usr/local/bin/silver-relay"]
