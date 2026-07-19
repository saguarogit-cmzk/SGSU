#!/usr/bin/env bash
# Builds the saguaro .deb. Runs in CI (or any Linux box with Go and dpkg-deb);
# the appliance itself never needs a Go toolchain.
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION=""
ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
OUT="$ROOT/dist"
SKIP_TESTS=false

usage() {
  cat <<'EOF'
Usage: scripts/build-deb.sh [--version X.Y.Z] [--arch amd64|arm64] [--output DIR] [--skip-tests]

Without --version the version is derived from `git describe --tags`
(falling back to 0.0.0+git<sha>). Cross-building arm64 from amd64 works
because the binary is pure Go (CGO_ENABLED=0).
EOF
}

die() { echo "ERROR: $*" >&2; exit 1; }

while (($#)); do
  case "$1" in
    --version) VERSION=${2:?}; shift 2 ;;
    --arch) ARCH=${2:?}; shift 2 ;;
    --output) OUT=${2:?}; shift 2 ;;
    --skip-tests) SKIP_TESTS=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
done

[[ $ARCH =~ ^(amd64|arm64)$ ]] || die "Supported architectures: amd64, arm64."
command -v go >/dev/null || die "Go toolchain is required."
command -v dpkg-deb >/dev/null || die "dpkg-deb is required."

if [[ -z $VERSION ]]; then
  if VERSION=$(git -C "$ROOT" describe --tags 2>/dev/null); then
    VERSION=${VERSION#v}
    VERSION=${VERSION//-/.}
  else
    VERSION="0.0.0+git$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  fi
fi
[[ $VERSION =~ ^[0-9][A-Za-z0-9.+~]*$ ]] || die "Not a valid Debian version: $VERSION"

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

echo "Building saguaro ${VERSION} for ${ARCH}"
if ! $SKIP_TESTS; then
  (cd "$ROOT" && go vet ./... && go test ./...)
fi
(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" \
  go build -trimpath -ldflags="-s -w" -o "$STAGE/usr/lib/saguaro/saguaro" ./cmd/saguaro)
(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" \
  go build -trimpath -ldflags="-s -w" -o "$STAGE/usr/lib/saguaro/saguaro-eventd" ./cmd/saguaro-eventd)

install -D -m 0644 "$ROOT/packaging/systemd/saguaro.service"        "$STAGE/usr/lib/systemd/system/saguaro.service"
install -D -m 0644 "$ROOT/packaging/systemd/saguaro-eventd.service" "$STAGE/usr/lib/systemd/system/saguaro-eventd.service"
install -D -m 0644 "$ROOT/packaging/systemd/saguaro-backup.service" "$STAGE/usr/lib/systemd/system/saguaro-backup.service"
install -D -m 0644 "$ROOT/packaging/systemd/saguaro-backup.timer"   "$STAGE/usr/lib/systemd/system/saguaro-backup.timer"
install -D -m 0755 "$ROOT/scripts/saguaro-backup.sh"                "$STAGE/usr/sbin/saguaro-backup"
install -D -m 0755 "$ROOT/scripts/saguaro-firewall"                 "$STAGE/usr/sbin/saguaro-firewall"
install -D -m 0755 "$ROOT/scripts/saguaro-ids"                      "$STAGE/usr/sbin/saguaro-ids"
install -D -m 0755 "$ROOT/scripts/saguaro-rpz"                      "$STAGE/usr/sbin/saguaro-rpz"
install -D -m 0755 "$ROOT/scripts/saguaro-proxy"                    "$STAGE/usr/sbin/saguaro-proxy"
install -D -m 0755 "$ROOT/scripts/saguaro-cert"                     "$STAGE/usr/sbin/saguaro-cert"
install -D -m 0755 "$ROOT/scripts/saguaro-vpn"                      "$STAGE/usr/sbin/saguaro-vpn"
install -D -m 0755 "$ROOT/scripts/saguaro-backup-config"            "$STAGE/usr/sbin/saguaro-backup-config"
install -D -m 0755 "$ROOT/scripts/saguaro-wan"                      "$STAGE/usr/sbin/saguaro-wan"
install -D -m 0755 "$ROOT/scripts/saguaro-net"                      "$STAGE/usr/sbin/saguaro-net"
install -D -m 0755 "$ROOT/scripts/saguaro-route"                    "$STAGE/usr/sbin/saguaro-route"
install -D -m 0755 "$ROOT/scripts/saguaro-s2s"                      "$STAGE/usr/sbin/saguaro-s2s"
install -D -m 0755 "$ROOT/scripts/saguaro-ipsec"                    "$STAGE/usr/sbin/saguaro-ipsec"
install -D -m 0755 "$ROOT/scripts/saguaro-svc"                      "$STAGE/usr/sbin/saguaro-svc"
install -D -m 0755 "$ROOT/scripts/saguaro-logs"                     "$STAGE/usr/sbin/saguaro-logs"
install -D -m 0755 "$ROOT/scripts/saguaro-tools"                    "$STAGE/usr/sbin/saguaro-tools"
install -D -m 0755 "$ROOT/scripts/saguaro-webproxy"                 "$STAGE/usr/sbin/saguaro-webproxy"
install -D -m 0644 "$ROOT/packaging/systemd/saguaro-routes.service" "$STAGE/usr/lib/systemd/system/saguaro-routes.service"
install -D -m 0644 "$ROOT/packaging/systemd/saguaro-wan-check.service" "$STAGE/usr/lib/systemd/system/saguaro-wan-check.service"
install -D -m 0644 "$ROOT/packaging/systemd/saguaro-wan-check.timer"   "$STAGE/usr/lib/systemd/system/saguaro-wan-check.timer"
install -D -m 0644 "$ROOT/packaging/systemd/saguaro-cert-renew.service" "$STAGE/usr/lib/systemd/system/saguaro-cert-renew.service"
install -D -m 0644 "$ROOT/packaging/systemd/saguaro-cert-renew.timer"   "$STAGE/usr/lib/systemd/system/saguaro-cert-renew.timer"
install -D -m 0440 "$ROOT/packaging/sudoers/saguaro-adapter"        "$STAGE/etc/sudoers.d/saguaro-adapter"
install -D -m 0644 "$ROOT/config/saguaro.env.example"               "$STAGE/usr/share/doc/saguaro/saguaro.env.example"
install -D -m 0644 "$ROOT/README.md"                                "$STAGE/usr/share/doc/saguaro/README.md"

install -d -m 0755 "$STAGE/DEBIAN"
sed -e "s/@VERSION@/$VERSION/" -e "s/@ARCH@/$ARCH/" \
  "$ROOT/packaging/deb/control.in" >"$STAGE/DEBIAN/control"
install -m 0755 "$ROOT/packaging/deb/postinst" "$STAGE/DEBIAN/postinst"
install -m 0755 "$ROOT/packaging/deb/prerm"    "$STAGE/DEBIAN/prerm"
install -m 0755 "$ROOT/packaging/deb/postrm"   "$STAGE/DEBIAN/postrm"
printf '/etc/sudoers.d/saguaro-adapter\n' >"$STAGE/DEBIAN/conffiles"

mkdir -p "$OUT"
DEB="$OUT/saguaro_${VERSION}_${ARCH}.deb"
dpkg-deb --build --root-owner-group "$STAGE" "$DEB"
dpkg-deb --info "$DEB"
echo "Built: $DEB"
