# Contributing to Chorrent

Thanks for looking! Chorrent is small (about 6k lines of Rust), so it's a good
place to learn iroh, QUIC and peer-to-peer file transfer. Questions, bug
reports and pull requests are all welcome.

## Where to start

- Issues labelled [`good first issue`](https://github.com/mrsarthi/Chorrent/labels/good%20first%20issue)
  are small and self-contained. Comment on one to claim it so two people don't
  do the same work.
- Found a bug? Open an issue with what you ran, what you expected, and the
  output of `chorrent doctor` (remove your IP addresses first). The issue
  form asks for each of these.
- Keep issues and PR descriptions short: a few lines is plenty. Exact
  commands and error messages help more than long explanations.
- Bigger idea or a change to the wire protocol? Open an issue to talk it
  through before writing code.

## Layout

| Path | What's there |
|---|---|
| `crates/chorrent/src/client.rs` | `Client` and its builder: the public API |
| `crates/chorrent/src/download.rs` | download loop, peer connections, endgame |
| `crates/chorrent/src/scheduler.rs` | which piece to ask which peer for (in-order start, then rarest-first) |
| `crates/chorrent/src/protocol.rs` | the `chorrent/2` wire messages (postcard frames) |
| `crates/chorrent/src/manifest.rs` | share codes, share ids, file lists |
| `crates/chorrent/src/chunker.rs` | 64 KiB pieces and BLAKE3/Bao verification |
| `crates/chorrent/src/handler.rs` | answers other peers (manifests, progress, pieces) |
| `crates/chorrent/src/local.rs` | a share as this node holds it: files, verified pieces, access |
| `crates/chorrent/src/storage.rs` | where bytes live: plain files or the encrypted store |
| `crates/chorrent/src/store.rs` | saved state in redb (identity, seeds, resume data) |
| `crates/chorrent/src/discovery.rs` | finding other seeders via iroh-gossip |
| `crates/chorrent-cli/src/main.rs` | the `chorrent` command-line program |

## Building and testing

You need Rust 1.91 or newer.

```bash
cargo build
cargo test --workspace --lib --bins    # unit tests, no network needed
cargo test --workspace --tests         # integration tests, need internet (iroh relays)
cargo run -p chorrent-cli -- --help
```

On a machine with little memory, add `-j 2` to cargo commands.

Before opening a pull request:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

CI runs both, plus the tests on Linux, Windows and macOS.

## Pull requests

- Keep each PR to one change, and link the issue it fixes (`Fixes #12`).
- Add a test when you fix a bug, if one fits.
- Changes to the wire protocol must keep working with peers on the current
  version, or bump the ALPN. Say which in the PR.
- Using AI is fine, but say so clearly: in the issue form or the PR
  template, tick that you used it and say what for (the fix, the tests, the
  docs, the description...). You should understand and be able to explain
  every line you submit.

## License

By contributing you agree your work is released under the Apache-2.0 license,
like the rest of the project.
