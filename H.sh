#!/bin/sh
# H bootstrapper for Linux:
#   curl -fsSL https://raw.githubusercontent.com/MRITARI/H/main/H.sh | sh
# Downloads the H binary (SHA-256 verified) into ~/.cache/H and opens the toolbox TUI.
#
# Optional env vars (set before running):
#   H_PATH=/home          folder the disk scanner starts on (default: /)
#   H_CLEAN=1             delete the downloaded binary when the TUI exits
# Arguments after "sh -s --" are passed to H:  curl -fsSL ... | sh -s -- /var

set -eu

RELEASE="https://github.com/MRITARI/H/releases/latest/download"

case "$(uname -m)" in
  x86_64 | amd64)  NAME="H-linux-amd64" ;;
  aarch64 | arm64) NAME="H-linux-arm64" ;;
  *) echo "H: unsupported CPU architecture: $(uname -m) (x86_64 and aarch64 are supported)" >&2; exit 1 ;;
esac
[ "$(uname -s)" = "Linux" ] || { echo "H.sh is for Linux. On Windows use: irm https://raw.githubusercontent.com/MRITARI/H/main/H.ps1 | iex" >&2; exit 1; }

DIR="${XDG_CACHE_HOME:-${HOME:-/tmp}/.cache}/H"
BIN="$DIR/$NAME"
mkdir -p "$DIR"

fetch() { # fetch URL -> stdout
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1"
  elif command -v wget >/dev/null 2>&1; then wget -qO- "$1"
  else echo "H: curl or wget is required" >&2; return 1; fi
}
download() { # download URL FILE
  if command -v curl >/dev/null 2>&1; then curl -fL --progress-bar -o "$2" "$1"
  else wget -q --show-progress -O "$2" "$1"; fi
}
sha256() { # sha256 FILE -> hash
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
  else echo "H: sha256sum or shasum is required to verify the download" >&2; return 1; fi
}

# Always fetch the published hash first; re-download when the cached binary is missing or outdated.
want="$(fetch "$RELEASE/$NAME.sha256" | tr -d '\r' | cut -d' ' -f1 | tr 'A-F' 'a-f')"
[ -n "$want" ] || { echo "H: could not read the published checksum" >&2; exit 1; }
have=""
[ -f "$BIN" ] && have="$(sha256 "$BIN")"
if [ "$have" != "$want" ]; then
  echo "  downloading $NAME ..."
  download "$RELEASE/$NAME" "$BIN.part"
  if [ "$(sha256 "$BIN.part")" != "$want" ]; then
    rm -f "$BIN.part"
    echo "H: SHA-256 mismatch for $NAME - aborting." >&2
    exit 1
  fi
  chmod +x "$BIN.part"
  mv -f "$BIN.part" "$BIN"
fi

# When piped from curl, stdin is the script itself: give the TUI the real terminal.
if [ ! -t 0 ]; then
  [ -r /dev/tty ] || { echo "H: no terminal available - run it from an interactive shell" >&2; exit 1; }
  exec_in=/dev/tty
else
  exec_in=/dev/stdin
fi

status=0
if [ "$#" -gt 0 ]; then
  "$BIN" "$@" <"$exec_in" || status=$?
elif [ -n "${H_PATH:-}" ]; then
  "$BIN" "$H_PATH" <"$exec_in" || status=$?
else
  "$BIN" <"$exec_in" || status=$?
fi

[ -z "${H_CLEAN:-}" ] || rm -rf "$DIR"
exit "$status"
