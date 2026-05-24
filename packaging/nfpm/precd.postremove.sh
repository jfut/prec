#!/bin/sh
set -eu

# Refresh systemd unit cache after package removal.
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
