# Releasing lsnet

A release is a version tag on this repo plus a formula update in the Homebrew tap, [sanford/homebrew-tap](https://github.com/sanford/homebrew-tap). Homebrew builds from the source tarball GitHub serves for each tag, so no binaries need to be uploaded.

The examples below use `0.2.0`. Substitute the real version.

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

## 7. Optional: GitHub release notes

A GitHub Release adds a changelog page for the tag. Homebrew doesn't need it. Using the GitHub CLI, logged in with an account that can write to `sanford/lsnet` (check with `gh auth status`):

```sh
gh release create v0.2.0 --title "lsnet 0.2.0" --generate-notes
```

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

## Checklist

- [ ] `cargo test` and `cargo clippy` are clean, and `./run.sh` looks right
- [ ] `version` bumped in `Cargo.toml`; `Cargo.lock` rebuilt and committed
- [ ] `vX.Y.Z` tag pushed
- [ ] Tarball checksum taken, and the tarball builds with `--locked`
- [ ] `Formula/lsnet.rb` `url` and `sha256` updated; `brew style` clean; tap pushed
- [ ] `brew upgrade`, `brew test` and `brew audit --strict --online` pass
