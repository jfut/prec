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
