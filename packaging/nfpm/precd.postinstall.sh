#!/bin/sh
set -eu

# Create runtime directories required by precd at install time.
mkdir -p /etc/prec
chmod 0750 /etc/prec
mkdir -p /var/log/prec
chmod 0750 /var/log/prec

# Reload unit files when systemd exists on the host.
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

# Restart precd automatically on package upgrades.
# This enables seamless daemon refresh for updates such as:
# dnf update prec-<version>.x86_64.rpm
# apt upgrade (deb postinst configure with previous version)
is_upgrade=0
if [ "${1:-}" != "" ]; then
  # deb postinst: "configure <previous-version>" on upgrade.
  if [ "$1" = "configure" ] && [ "${2:-}" != "" ]; then
    is_upgrade=1
  fi

  # rpm %post: 1=install, 2=upgrade.
  case "$1" in
    ''|*[!0-9]*)
      ;;
    *)
      if [ "$1" -gt 1 ]; then
        is_upgrade=1
      fi
      ;;
  esac
fi

if [ "$is_upgrade" -eq 1 ] && command -v systemctl >/dev/null 2>&1; then
  if systemctl list-unit-files precd.service >/dev/null 2>&1; then
    systemctl restart precd.service >/dev/null 2>&1 || true
  fi
fi
