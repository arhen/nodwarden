# NodWarden: notes for agents

## Versions

- The version lives in `core/Cargo.toml` only; `build.sh` copies it into the app's Info.plist.
- Every pushed update bumps the patch number: 0.0.2 → 0.0.3 → … → 0.0.10. Bump in the same
  commit as the change.
- Stay on 0.0.x. Never move to 0.1.0 or higher unless the owner asks.

## Before a push

- `cd core && cargo test --release && cargo clippy --release --all-targets` (0 warnings).
- `swiftc -typecheck -swift-version 5 -parse-as-library -target arm64-apple-macos14.0 Sources/*.swift`
- `./build.sh`, then `launchctl kickstart -k gui/$(id -u)/dev.arhen.nodwarden`.
- Check `git show --stat HEAD` before pushing: the commit should hold only the files you meant
  to change.
- No personal data in the repo. Known limits go to GitHub issues, not the README.
