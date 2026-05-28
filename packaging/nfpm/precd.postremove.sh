#!/bin/sh
set -eu

# Refresh systemd unit cache after package removal.
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

# Stop precd only when the package is actually uninstalled.
# Avoid stopping on upgrade paths.
is_uninstall=0
if [ "${1:-}" != "" ]; then
  # deb postrm: "remove" or "purge" on uninstall.
  case "$1" in
    remove|purge)
      is_uninstall=1
      ;;
  esac

  # rpm %postun: 0=erase, 1=upgrade.
  case "$1" in
    ''|*[!0-9]*)
      ;;
    *)
      if [ "$1" -eq 0 ]; then
        is_uninstall=1
      fi
      ;;
  esac
fi

if [ "$is_uninstall" -eq 1 ] && command -v systemctl >/dev/null 2>&1; then
  systemctl stop precd.service >/dev/null 2>&1 || true
fi
