# Silver Messenger

Open-source, end-to-end encrypted messaging for the terminal. Rust, cross
platform (Windows, Linux, macOS), with a self-hosted relay that only ever
sees encrypted blobs.

The code lives in [`Silver Message/`](Silver%20Message/), a Cargo workspace:

* `silver-relay` – the relay server
* `silver` – the terminal client (full TUI)
* `silver-protocol` / `silver-client` – shared crypto, wire types and client core

See [`Silver Message/README.md`](Silver%20Message/README.md) for the quick
start, the command reference, and how the encryption works.

```sh
cd "Silver Message"
cargo run --release --bin silver-relay          # on a machine everyone can reach
cargo run --release --bin silver -- --relay ws://<relay-host>:7777/ws
```
