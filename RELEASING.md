# Releasing fat

CI (`.github/workflows/ci.yml`) runs on every push and pull request:

- `cargo fmt --check` and clippy with warnings as errors.
- Tests on Linux x86_64, Linux aarch64 and macOS, plus a smoke run of the read-only commands as an unprivileged user.
- `cargo deny` for advisories, licenses, duplicate crates and sources (config: `deny.toml`).
- Static musl builds for x86_64 and aarch64, run inside a busybox container to prove they need no libc.

## Cutting a release

1. Bump `version` in `Cargo.toml`, run `cargo check` so `Cargo.lock` follows, and commit.
2. Tag and push:
   ```sh
   git tag -a v0.2.0 -m "fat 0.2.0"
   git push origin main v0.2.0
   ```
3. `.github/workflows/release.yml` then:
   - checks that the tag matches `Cargo.toml`;
   - builds `fat-<version>-<target>.tar.gz` for x86_64/aarch64 Linux (static musl) and x86_64/aarch64 macOS;
   - writes `SHA256SUMS`;
   - signs every archive and the checksum file with a GitHub build-provenance attestation (Sigstore, keyless:
     there is no signing key to store or rotate);
   - opens a **draft** release with generated notes.
4. Review the draft on GitHub, edit the notes, and publish it. Nothing is public before that.

To rebuild an existing tag, run the Release workflow by hand (Actions → Release → Run workflow) with that tag.

## Notes

- The x86_64 macOS binary is cross-built on an Apple silicon runner and not executed in CI.
- Third-party actions are pinned to commit SHAs. Update them deliberately, checking the release notes.
- When `cargo deny` reports a new advisory, update the dependency. If no fix exists and fat is not exposed,
  add the advisory to `deny.toml`'s `ignore` list with the reason.
