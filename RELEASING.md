# Releasing lsnet

A release is a version tag on this repo, a formula update in the Homebrew tap ([sanford/homebrew-tap](https://github.com/sanford/homebrew-tap)), and a GitHub Release with notes and a Windows binary. Homebrew builds from the source tarball GitHub serves for each tag, so macOS and Linux need no binaries. Windows has no Homebrew, so its `lsnet.exe` is built from the tag and attached to the release.

The examples below release `0.2.0` after `0.1.0`. Substitute the real versions.

## 1. Prepare

Start from an up-to-date `main` with no uncommitted changes:

```sh
git checkout main && git pull
git status          # should be clean
```

Optionally refresh the MAC vendor database. Wireshark asks that it not be downloaded more than once a week.

```sh
python3 scripts/update-oui.py
```

Check that everything passes:

```sh
cargo test
cargo clippy --release --all-targets    # expect no warnings
./run.sh                                # scan your own network and look it over
```

If anything platform-specific changed, also check the Linux build (see "Testing on Linux" below).

## 2. Bump the version

Pick the new version using [semver](https://semver.org): patch (`0.1.1`) for fixes and new identification rules, minor (`0.2.0`) for new features or output changes, major once the output format is promised to be stable.

Update `version` in `Cargo.toml`, then rebuild so `Cargo.lock` picks up the change:

```sh
cargo build --release
./target/release/lsnet --version    # should print the new version
```

Commit both files:

```sh
git add Cargo.toml Cargo.lock
git commit -m "Release 0.2.0"
git push
```

## 3. Tag

```sh
git tag -a v0.2.0 -m "lsnet 0.2.0"
git push origin v0.2.0
```

Tags start with `v`. The formula's download URL depends on it.

## 4. Get the tarball checksum

GitHub generates the source tarball from the tag. Download it, record its SHA-256, and confirm it builds on its own, exactly as Homebrew will build it:

```sh
cd "$(mktemp -d)"
curl -sSfLO https://github.com/sanford/lsnet/archive/refs/tags/v0.2.0.tar.gz
shasum -a 256 v0.2.0.tar.gz
tar xzf v0.2.0.tar.gz
cargo install --locked --root ./out --path lsnet-0.2.0
./out/bin/lsnet --version
```

Never move or recreate a tag after publishing it. The tarball would change, its checksum would no longer match, and every `brew install` would fail. If a release is broken, release a new version.

## 5. Update the Homebrew formula

The tap's working copy lives at `~/dev/homebrew-tap`. In `Formula/lsnet.rb`, update the two lines:

```ruby
  url "https://github.com/sanford/lsnet/archive/refs/tags/v0.2.0.tar.gz"
  sha256 "<checksum from step 4>"
```

Lint it, then commit and push:

```sh
cd ~/dev/homebrew-tap
git pull
brew style Formula/lsnet.rb
git commit -am "lsnet 0.2.0"
git push
```

Use the commit message `lsnet 0.2.0`. That's the Homebrew convention for version bumps. A brand-new formula uses `lsnet 0.1.0 (new formula)`.

## 6. Verify the published release

Install from the tap the way a user would:

```sh
brew update
brew upgrade sanford/tap/lsnet      # or: brew install sanford/tap/lsnet
brew test sanford/tap/lsnet
brew audit --strict --online sanford/tap/lsnet
"$(brew --prefix)/bin/lsnet" --version
```

`brew audit` should print nothing. If `~/.local/bin/lsnet` from `run.sh` is on your PATH, a plain `lsnet` runs that copy instead, so the last command gives the full path.

If something is wrong, fix it and push to the tap again. If the source itself is broken, cut a new patch release instead of changing the tag.

## 7. Publish release notes

Every release gets a GitHub Release with notes written by hand. Changes go straight to `main` without pull requests, so `gh release create --generate-notes` would produce little more than a compare link.

List what changed since the last release:

```sh
git log --oneline v0.1.0..v0.2.0
```

Write the notes for people who use `lsnet`, not for people who work on it. Leave out refactors and README-only commits. A good layout:

- **A short section for each notable change,** saying what it does and how to use it.
- **"Upgrading from 0.1.0",** if a default, flag or output format changed. Say what to run to get the old behavior, and whether scripts need changes.
- **A compare link** on the last line: `https://github.com/sanford/lsnet/compare/v0.1.0...v0.2.0`

Build the Windows binary from the same tarball, on a Windows machine with Rust (see "Testing on Windows"). Build from inside the unpacked source: Cargo reads `.cargo/config.toml`, which links the C runtime statically, from the current directory, not from `--manifest-path`.

```powershell
cd (New-Item -ItemType Directory -Force "$env:TEMP\lsnet-release")
curl.exe -sSfLO https://github.com/sanford/lsnet/archive/refs/tags/v0.2.0.tar.gz
tar xzf v0.2.0.tar.gz
cd lsnet-0.2.0
cargo build --locked --release
.\target\release\lsnet.exe --version
Compress-Archive target\release\lsnet.exe, README.md, LICENSE ..\lsnet-windows-x64.zip -Force
```

Keep the name `lsnet-windows-x64.zip`: the README's install command downloads it by that name from the latest release.

Save the notes to a file outside the repo, then publish them with the zip. This needs the GitHub CLI logged in with an account that can write to `sanford/lsnet`. `gh api repos/sanford/lsnet --jq .permissions.push` should print `true`.

```sh
gh release create v0.2.0 -R sanford/lsnet --title "lsnet 0.2.0" --notes-file /tmp/notes-0.2.0.md --verify-tag lsnet-windows-x64.zip
```

`--verify-tag` makes `gh` fail if the tag hasn't been pushed, rather than creating a new tag. To fix a typo afterwards, use `gh release edit v0.2.0 -R sanford/lsnet --notes-file ...`. Editing the notes doesn't touch the tag or the tarball.

[The 0.2.0 release](https://github.com/sanford/lsnet/releases/tag/v0.2.0) is an example.

## Testing on Linux

The Linux-specific code paths (`/proc` parsing, raw sockets) can be checked from a Mac with Docker:

```sh
docker run --rm -v "$PWD":/src:ro -v lsnet-build:/build -e CARGO_TARGET_DIR=/build \
  -w /src rust:latest cargo build --release
docker network create --subnet 172.30.0.0/24 lsnet-test
docker run -d --rm --name web --network lsnet-test nginx:alpine
docker run --rm --network lsnet-test -v lsnet-build:/build debian:stable-slim /build/release/lsnet -v
docker run --rm --network lsnet-test --user 65534:65534 --cap-drop ALL \
  -v lsnet-build:/build debian:stable-slim /build/release/lsnet -v
docker stop web && docker network rm lsnet-test && docker volume rm lsnet-build
```

The first scan runs as root and uses raw ARP. The second runs unprivileged and should still show MAC addresses from `/proc/net/arp`.

## Testing on Windows

The Windows code paths (IP Helper API, `SendARP`, the clipboard) are exercised by the `windows` CI job, which runs on a self-hosted runner, and can be run by hand on any Windows 10 or later machine with Rust and the Visual Studio Build Tools:

```powershell
cargo test --release
cargo clippy --release --all-targets    # expect no warnings
.\run.ps1 -v                            # no administrator rights needed
```

The scan should show MAC addresses and vendors, and finish in about the same time as on macOS. The CI job uploads the built `lsnet.exe` as an artifact.

## Checklist

- [ ] `cargo test` and `cargo clippy` are clean, and `./run.sh` looks right
- [ ] `version` bumped in `Cargo.toml`; `Cargo.lock` rebuilt and committed
- [ ] `vX.Y.Z` tag pushed
- [ ] Tarball checksum taken, and the tarball builds with `--locked`
- [ ] `Formula/lsnet.rb` `url` and `sha256` updated; `brew style` clean; tap pushed
- [ ] `brew upgrade`, `brew test` and `brew audit --strict --online` pass
- [ ] `lsnet-windows-x64.zip` built from the tag's tarball
- [ ] GitHub Release published with hand-written notes, including upgrade notes if any behavior changed, and the Windows zip attached
