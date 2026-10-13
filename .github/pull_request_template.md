<!-- Please keep this short: a few lines per section is plenty. -->

## What this changes

<!-- One or two sentences. -->

Fixes #

## How you tested it

<!-- The commands you ran, e.g. `cargo test --workspace`. -->

## AI use

<!-- Fine either way, but say so clearly. Tick one, and say what it did. -->

- [ ] I didn't use AI for this PR.
- [ ] I used AI for: <!-- e.g. "writing the fix", "the tests", "the docs", "this description" -->

I understand every line in this PR and can explain it.

## Checklist

- [ ] `cargo fmt --all` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` pass
- [ ] Added a test, if one fits
- [ ] If this changes the wire protocol: it still works with the current version, or the ALPN is bumped (say which)
