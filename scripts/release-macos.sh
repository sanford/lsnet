#!/usr/bin/env bash
# Build, sign and notarize the macOS binary, and attach it to a GitHub release.
#
#   scripts/release-macos.sh v0.7.0              # build, sign, notarize, upload
#   scripts/release-macos.sh v0.7.0 --no-upload  # everything but the upload
#
# Run it on an Apple Silicon Mac, from the release commit, after the GitHub
# release for the tag exists. It prints the tarball's SHA-256 for the
# Homebrew formula.
#
# Why sign: macOS hides the ARP table from binaries that aren't signed with a
# Developer ID, even through `arp`. Signed, lsnet sees MAC addresses, vendors
# and silent devices without sudo.
#
# One-time setup:
#   - The "Developer ID Application: Awesome Machinery, LLC" certificate and
#     its private key in the login keychain.
#   - Notary credentials, stored in the keychain under the profile name
#     "lsnet-notary". With an app-specific password from account.apple.com:
#       xcrun notarytool store-credentials lsnet-notary \
#         --apple-id <apple-id> --team-id Q8QUDQ638Y
#
# LSNET_SIGN_IDENTITY (a certificate's SHA-1 hash) and LSNET_NOTARY_PROFILE
# override the defaults.
set -euo pipefail

TEAM_ID=Q8QUDQ638Y
ASSET=lsnet-macos-arm64.tar.gz

die() {
    echo "error: $*" >&2
    exit 1
}

tag=${1:-}
[[ $tag == v* ]] || die "usage: $0 vX.Y.Z [--no-upload]"
upload=true
[[ ${2:-} == --no-upload ]] && upload=false

cd "$(dirname "$0")/.."
[[ $(uname -s) == Darwin && $(uname -m) == arm64 ]] || die "run this on an Apple Silicon Mac"
git diff --quiet HEAD || die "there are uncommitted changes"
[[ $(git rev-parse HEAD) == $(git rev-parse "$tag^{commit}" 2>/dev/null) ]] ||
    die "HEAD isn't $tag (git checkout $tag first)"
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
[[ v$version == "$tag" ]] || die "Cargo.toml says $version, not ${tag#v}"

# Several certificates can share the name, which makes signing by name
# ambiguous, so pick one by its hash.
identity=${LSNET_SIGN_IDENTITY:-$(security find-identity -v -p codesigning |
    awk "/Developer ID Application: .*\\($TEAM_ID\\)/ { print \$2; exit }")}
[[ -n $identity ]] || die "no Developer ID Application certificate for team $TEAM_ID in the keychain"
profile=${LSNET_NOTARY_PROFILE:-lsnet-notary}

cargo build --release --locked

dist=target/dist
rm -rf "$dist"
mkdir -p "$dist/lsnet"
cp target/release/lsnet README.md LICENSE "$dist/lsnet/"
# The bundled themes' MIT license asks for its notice to go with every copy.
cp themes/LICENSE "$dist/lsnet/LICENSE-themes"
bin=$dist/lsnet/lsnet

echo "Signing with $identity"
# Notarization requires the hardened runtime and a secure timestamp.
codesign --force --options runtime --timestamp --sign "$identity" "$bin"
codesign --verify --strict --verbose=2 "$bin"
# Read it all before matching: grep -q stops at the first match, and under
# pipefail the codesign it cut off would fail the check.
details=$(codesign -dv "$bin" 2>&1)
grep -q "^TeamIdentifier=$TEAM_ID$" <<<"$details" || die "signed by the wrong team"
[[ $("$bin" --version) == "lsnet $version" ]] || die "the signed binary doesn't run"

echo "Notarizing (this usually takes a minute or two)"
ditto -c -k "$bin" "$dist/notarize.zip"
result=$(xcrun notarytool submit "$dist/notarize.zip" --keychain-profile "$profile" \
    --wait --output-format json) || true
status=$(plutil -extract status raw - <<<"$result" 2>/dev/null || true)
if [[ $status != Accepted ]]; then
    echo "$result" >&2
    id=$(plutil -extract id raw - <<<"$result" 2>/dev/null || true)
    [[ -n $id ]] && echo "details: xcrun notarytool log $id --keychain-profile $profile" >&2
    die "notarization failed: ${status:-no status}"
fi
# A bare binary can't be stapled; Gatekeeper finds the ticket online.

tar -czf "$dist/$ASSET" -C "$dist" lsnet
sha=$(shasum -a 256 "$dist/$ASSET" | cut -d' ' -f1)

if $upload; then
    gh release upload "$tag" "$dist/$ASSET" --clobber
    echo "Attached $ASSET to $tag"
else
    echo "Built $dist/$ASSET (not uploaded)"
fi
echo "sha256 $sha"
