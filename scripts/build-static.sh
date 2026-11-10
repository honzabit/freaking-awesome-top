#!/bin/sh
# Static Linux binaries of fat (musl, fully static: copy anywhere with scp, no glibc version
# coupling, no runtime deps). OWNER: fleet agent.
#
# Usage: scripts/build-static.sh [TARGET...]
#   default TARGET: the musl target matching this machine's arch.
#   e.g. scripts/build-static.sh x86_64-unknown-linux-musl aarch64-unknown-linux-musl
#   Any <arch>-unknown-linux-musl target Rust supports works the same way.
#
# Toolchain, first that works per target:
#   1. `cargo zigbuild` if installed (cross-arch from any host, macOS included);
#   2. plain `cargo build` when the rustup target is installed and a musl C compiler for it is
#      on PATH (musl-gcc for the native arch, <arch>-linux-musl-gcc for cross), which
#      rusqlite's bundled SQLite needs;
#   3. docker (or podman): the official rust Alpine image for the target's platform, which is
#      musl-native. A foreign arch runs under the container runtime's emulation if it has one.
#      Image: FAT_STATIC_IMAGE (default rust:<local rustc version>-alpine). Crate downloads are
#      cached under target/static/, never in your ~/.cargo.
# The script never installs anything on this machine; it prints what is missing.
# FAT_STATIC_VIA=zigbuild|cargo|docker forces one method.
# Output: dist/fat-<version>-<target> plus a .sha256 next to it.
set -eu

cd "$(dirname "$0")/.."
ROOT=$(pwd)
VERSION=$(sed -n 's/^version *= *"\(.*\)"/\1/p' Cargo.toml | head -n 1)
mkdir -p dist
# Smaller binaries to scp around; does not change Cargo.toml.
export CARGO_PROFILE_RELEASE_STRIP=${CARGO_PROFILE_RELEASE_STRIP:-symbols}

host_arch() {
    case "$(uname -m)" in
        x86_64 | amd64) echo x86_64 ;;
        arm64 | aarch64) echo aarch64 ;;
        *) uname -m ;;
    esac
}

if [ "$#" -eq 0 ]; then
    set -- "$(host_arch)-unknown-linux-musl"
fi

have() { command -v "$1" >/dev/null 2>&1; }

sha() {
    if have sha256sum; then sha256sum "$1"; else shasum -a 256 "$1"; fi
}

# Upper-case, '-' -> '_' (cargo's env var spelling of a target triple).
envname() { echo "$1" | tr 'a-z-' 'A-Z_'; }

via_zigbuild() {
    have cargo-zigbuild || return 1
    rustup target list --installed 2>/dev/null | grep -qx "$1" || { echo "  zigbuild: rustup target $1 not installed (rustup target add $1)" >&2; return 1; }
    cargo zigbuild --release --target "$1" && cp "target/$1/release/fat" "$2"
}

via_cargo() {
    t=$1
    arch=${t%%-*}
    [ "$(uname -s)" = Linux ] || return 1
    rustup target list --installed 2>/dev/null | grep -qx "$t" || { echo "  cargo: rustup target $t not installed (rustup target add $t)" >&2; return 1; }
    if [ "$arch" = "$(host_arch)" ] && have musl-gcc; then
        cc=musl-gcc
    elif have "$arch-linux-musl-gcc"; then
        cc="$arch-linux-musl-gcc"
    else
        echo "  cargo: no musl C compiler for $t (musl-gcc or $arch-linux-musl-gcc)" >&2
        return 1
    fi
    E=$(envname "$t")
    env "CC_$(echo "$t" | tr '-' '_')=$cc" "CARGO_TARGET_${E}_LINKER=$cc" \
        cargo build --release --target "$t" && cp "target/$t/release/fat" "$2"
}

via_docker() {
    t=$1
    arch=${t%%-*}
    rt=""
    for c in docker podman; do have "$c" && { rt=$c; break; }; done
    [ -n "$rt" ] || { echo "  docker: neither docker nor podman found" >&2; return 1; }
    case "$arch" in
        x86_64) plat=linux/amd64 ;;
        aarch64) plat=linux/arm64 ;;
        armv7 | arm) plat=linux/arm/v7 ;;
        i686 | i586) plat=linux/386 ;;
        riscv64gc | riscv64) plat=linux/riscv64 ;;
        powerpc64le) plat=linux/ppc64le ;;
        s390x) plat=linux/s390x ;;
        *) echo "  docker: no container platform known for $t" >&2; return 1 ;;
    esac
    rustv=$(rustc --version 2>/dev/null | awk '{print $2}')
    image=${FAT_STATIC_IMAGE:-rust:${rustv:-1}-alpine}
    cache="target/static/$t"
    mkdir -p "$cache"
    echo "  docker: $image ($plat)" >&2
    # The image's native target is <arch>-unknown-linux-musl; static by default.
    "$rt" run --rm --platform "$plat" \
        -v "$ROOT:/src" -w /src \
        -e CARGO_HOME="/src/$cache/cargo-home" -e CARGO_TARGET_DIR="/src/$cache/build" \
        -e CARGO_PROFILE_RELEASE_STRIP \
        "$image" sh -c 'apk add --no-cache musl-dev >/dev/null 2>&1 || true; cargo build --release --locked' \
        && cp "$cache/build/release/fat" "$2"
}

status=0
for t in "$@"; do
    case "$t" in
        *-linux-musl*) ;;
        *) echo "$t: not a musl target (static linking needs *-linux-musl)" >&2; status=2; continue ;;
    esac
    out="dist/fat-$VERSION-$t"
    echo "== $t" >&2
    ok=""
    for m in ${FAT_STATIC_VIA:-zigbuild cargo docker}; do
        if "via_$m" "$t" "$out"; then ok=$m; break; fi
    done
    if [ -z "$ok" ]; then
        echo "$t: no way to build. Install one of: cargo-zigbuild (+ zig), a musl C compiler for $t, or docker/podman." >&2
        status=2
        continue
    fi
    sha "$out" > "$out.sha256"
    size=$(wc -c < "$out" | tr -d ' ')
    echo "$out  ($size bytes, via $ok)"
    if have file; then file "$out" | sed 's/^/  /'; fi
done
exit $status
