#!/bin/sh
# Read-only inspection; run from the user's interactive Terminal.
set -eu
umask 077
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT="$ROOT/analysis/network/hk6-lab/pf-inspection.txt"
sudo -v
{
  date
  /sbin/ifconfig bridge100
  /sbin/ifconfig ap1
  /sbin/route -n get default
  echo '=== PF status ==='
  sudo -n /sbin/pfctl -s info
  echo '=== Root filter rules ==='
  sudo -n /sbin/pfctl -sr
  echo '=== Recursive filter rules ==='
  sudo -n /sbin/pfctl -a '*' -sr
  echo '=== Recursive NAT rules ==='
  sudo -n /sbin/pfctl -a '*' -sn
  echo '=== Anchors ==='
  sudo -n /sbin/pfctl -s Anchors
} > "$OUT" 2>&1
printf 'Ispezione completata: %s\nNessuna regola modificata.\n' "$OUT"
