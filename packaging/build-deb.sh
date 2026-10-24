#!/usr/bin/env bash
# Builds the Debian/Ubuntu packages into artifacts/deb/:
#   uencrypt_<version>_<arch>.deb      the CLI (static, no dependencies; for servers and backups)
#   uencrypt-gui_<version>_<arch>.deb  the desktop app (needs GTK 3 and WebKitGTK 4.1)
#
# Usage: packaging/build-deb.sh [version] [cli|gui|all]
# The GUI needs the Wails CLI, Node.js, and libgtk-3-dev + libwebkit2gtk-4.1-dev to build. It is
# built for this machine's architecture; the CLI can be cross-built with GOARCH (e.g. arm64).
set -euo pipefail

VERSION="${1:-0.1.0}"
WHAT="${2:-all}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/artifacts/deb"
GOARCH="${GOARCH:-$(go env GOARCH)}"
export GOARCH
DEBARCH="$GOARCH" # Go and Debian agree on amd64, arm64 and riscv64
MAINTAINER="Stuart Millington <gitstm90@dsv1.co.uk>"
HOMEPAGE="https://github.com/StuMP90/uencrypt"
LDFLAGS="-s -w -X main.version=$VERSION"

mkdir -p "$OUT"

# copyright writes the Debian copyright file: our licence plus the third-party notices.
copyright() { # <stage> <package> <notices file>
  local doc="$1/usr/share/doc/$2"
  mkdir -p "$doc"
  {
    echo "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/"
    echo "Upstream-Name: uencrypt"
    echo "Source: $HOMEPAGE"
    echo
    echo "Files: *"
    echo "License: MIT"
    sed 's/^$/./; s/^/ /' "$ROOT/LICENSE"
  } > "$doc/copyright"
  gzip -9n < "$3" > "$doc/THIRD-PARTY-NOTICES.txt.gz"
}

# control writes DEBIAN/control; extra fields come on stdin.
control() { # <stage> <package> <description line>
  mkdir -p "$1/DEBIAN"
  {
    echo "Package: $2"
    echo "Version: $VERSION"
    echo "Architecture: $DEBARCH"
    echo "Maintainer: $MAINTAINER"
    echo "Installed-Size: $(du -sk --exclude=DEBIAN "$1" | cut -f1)"
    echo "Section: utils"
    echo "Priority: optional"
    echo "Homepage: $HOMEPAGE"
    cat
    echo "Description: $3"
    echo " uEncrypt encrypts files to post-quantum (ML-KEM-768 + X25519) or classic"
    echo " age keys, or to a passphrase, and signs them with hybrid Ed25519 + ML-DSA-65"
    echo " signatures. Encrypted files are standard age files (.age), readable by other"
    echo " age tools. It also decrypts files made by the older ppk-encrypt/oakcryptor"
    echo " tools (.enc)."
  } > "$1/DEBIAN/control"
}

package() { # <stage> <package>
  # Normal modes whatever the umask was.
  find "$1" -type d -exec chmod 755 {} +
  find "$1" -type f -exec chmod 644 {} +
  chmod 755 "$1"/usr/bin/*
  local deb="$OUT/${2}_${VERSION}_${DEBARCH}.deb"
  dpkg-deb --root-owner-group -Zxz --build "$1" "$deb" >/dev/null
  echo "Created $deb"
}

build_cli() {
  local stage="$OUT/stage/uencrypt"
  rm -rf "$stage"
  mkdir -p "$stage/usr/bin"
  (cd "$ROOT" && CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" -o "$stage/usr/bin/uencrypt" ./cmd/uencrypt)
  (cd "$ROOT" && GOARCH="$(go env GOHOSTARCH)" go run ./tools/notices -goarch "$GOARCH" -o "$OUT/stage/cli-notices.txt" ./cmd/uencrypt)
  copyright "$stage" uencrypt "$OUT/stage/cli-notices.txt"
  control "$stage" uencrypt "file encryption and signing with post-quantum keys (CLI)" </dev/null
  package "$stage" uencrypt
}

build_gui() {
  if [[ "$GOARCH" != "$(go env GOHOSTARCH)" ]]; then
    echo "The GUI can only be built for this machine's architecture ($(go env GOHOSTARCH))." >&2
    exit 1
  fi
  local stage="$OUT/stage/uencrypt-gui"
  rm -rf "$stage"
  (cd "$ROOT/gui" && wails build -clean -tags webkit2_41 -trimpath -ldflags "-X main.version=$VERSION" -o uencrypt-gui)
  install -Dm755 "$ROOT/gui/build/bin/uencrypt-gui" "$stage/usr/bin/uencrypt-gui"
  install -Dm644 "$ROOT/packaging/linux/uencrypt.png" "$stage/usr/share/icons/hicolor/256x256/apps/uencrypt.png"
  install -Dm644 "$ROOT/packaging/linux/uencrypt-gui.desktop" "$stage/usr/share/applications/uencrypt-gui.desktop"
  install -Dm644 "$ROOT/packaging/linux/uencrypt-mime.xml" "$stage/usr/share/mime/packages/uencrypt.xml"
  (cd "$ROOT" && GOARCH="$(go env GOHOSTARCH)" go run ./tools/notices -tags webkit2_41 -npm gui/frontend -o "$OUT/stage/gui-notices.txt" ./gui)
  copyright "$stage" uencrypt-gui "$OUT/stage/gui-notices.txt"
  # The desktop and MIME databases are refreshed by dpkg triggers, so no maintainer scripts.
  control "$stage" uencrypt-gui "file encryption and signing with post-quantum keys (desktop app)" <<EOF
Depends: libgtk-3-0t64 | libgtk-3-0, libwebkit2gtk-4.1-0
Recommends: uencrypt
EOF
  package "$stage" uencrypt-gui
}

case "$WHAT" in
  cli) build_cli ;;
  gui) build_gui ;;
  all) build_cli; build_gui ;;
  *) echo "usage: $0 [version] [cli|gui|all]" >&2; exit 2 ;;
esac
rm -rf "$OUT/stage"
