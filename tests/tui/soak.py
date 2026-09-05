#!/usr/bin/env python3
"""A soak: a relay and two clients exchanging messages for as long as
asked, a reaction, an edit and a deletion mixed in, and each process's
resident memory sampled on the way (docs/design/robustness.md section
6). It passes when every process is alive at the end, the last lines
sent each way arrived, each client's memory at the end is within a tenth
of what it was at the half (plus a few MiB of noise) and under the
ceiling, and the relay's is under the ceiling.

    tests/tui/soak.py --minutes 3        # what CI runs on every push
    tests/tui/soak.py --minutes 1440     # the day-long run, by hand

Not part of run.sh: it takes as long as it is told. Linux only, for the
memory figures come from /proc."""

import argparse
import sys
import time

from harness import *

CEILING_KIB = 256 * 1024
NOISE_KIB = 4 * 1024
SAMPLE_EVERY_S = 30.0
PAUSE_S = 0.15


def rss_kib(pid):
    """Resident memory of `pid` in KiB, or None once it is gone."""
    try:
        with open(f"/proc/{pid}/status") as status:
            for line in status:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except OSError:
        return None
    return None


def show(elapsed, n, sample):
    figures = "  ".join(
        f"{name}={kib // 1024 if kib else '?'}MiB" for name, kib in sample.items()
    )
    print(f"{elapsed:7.0f}s  messages={n:<7d} {figures}", flush=True)


def main():
    parser = argparse.ArgumentParser(description="soak the client")
    parser.add_argument("--minutes", type=float, default=3.0, help="how long to run (default 3)")
    args = parser.parse_args()

    # The relay's abuse limits (item 28) are for people, not for a soak
    # that sends several messages a second on purpose.
    generous = ("--sends-per-minute", "1000000", "--anonymous-sends-per-minute", "1000000",
                "--lookups-per-minute", "1000000")
    pair = Pair("soak", relay_extra=generous)
    pair.befriend()
    a, b = pair.alice, pair.bob
    pids = {"alice": a.p.pid, "bob": b.p.pid, "relay": pair.relay.p.pid}
    started = time.time()
    deadline = started + args.minutes * 60
    samples = [(0.0, {name: rss_kib(pid) for name, pid in pids.items()})]
    show(0, 0, samples[0][1])
    next_sample = started + SAMPLE_EVERY_S
    n = 0
    last = {"alice": None, "bob": None}

    while time.time() < deadline:
        n += 1
        sender, receiver, who = (a, b, "alice") if n % 2 else (b, a, "bob")
        text = f"soak {n}"
        sender.type(text + "\r")
        last[who] = text
        if n % 50 == 0:
            receiver.type("/react +1\r")
        if n % 100 == 0:
            sender.type(f"/edit {text} edited\r")
            last[who] = f"{text} edited"
        if n % 150 == 0:
            sender.type("/delete\r")
            last[who] = None
        Term.pump_all()
        if time.time() >= next_sample:
            for name, term in (("alice", b), ("bob", a)):
                if last[name]:
                    assert term.wait(last[name], timeout=30), f"{name}'s last line did not arrive"
            for term in (a, b):
                term.take_raw()  # not kept: a day of screen output is gigabytes
            sample = {name: rss_kib(pid) for name, pid in pids.items()}
            samples.append((time.time() - started, sample))
            show(time.time() - started, n, sample)
            for name, pid in pids.items():
                proc = {"alice": a.p, "bob": b.p, "relay": pair.relay.p}[name]
                assert proc.poll() is None, f"{name} died"
            next_sample += SAMPLE_EVERY_S
        time.sleep(PAUSE_S)

    # The end: everything alive, the last lines each way there, and the
    # memory flat since the half and under the ceiling.
    for name, term in (("alice", b), ("bob", a)):
        if last[name]:
            assert term.wait(last[name], timeout=30), f"{name}'s last line did not arrive"
    end = {name: rss_kib(pid) for name, pid in pids.items()}
    samples.append((time.time() - started, end))
    show(time.time() - started, n, end)
    for name, kib in end.items():
        assert kib is not None, f"{name} died"
    half = samples[len(samples) // 2][1]
    for name in ("alice", "bob"):
        assert end[name] <= half[name] * 1.1 + NOISE_KIB, (
            f"{name} grew from {half[name]} KiB at the half to {end[name]} KiB"
        )
        assert end[name] <= CEILING_KIB, f"{name} at {end[name]} KiB is over the ceiling"
    assert end["relay"] <= CEILING_KIB, f"the relay at {end['relay']} KiB is over the ceiling"
    print(f"{n} messages in {(time.time() - started) / 60:.1f} minutes; memory flat", flush=True)
    pair.stop()


if __name__ == "__main__":
    run(main)
