#!/bin/sh
# Temporary, scoped PF rules for the observed HK6-LAB setup.
set -eu
umask 077
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DIR="$ROOT/analysis/network/hk6-lab"
ANCHOR='com.apple/000.hk6-lab'
ACTION=${1:-status}
case "$ACTION" in apply|apply-ntp|status|remove) ;; *) echo 'Usage: sh tools/hk6_network_guard.sh apply|apply-ntp|status|remove' >&2; exit 2;; esac
sudo -v
status() {
  {
    date
    echo '=== PF status ==='
    sudo -n /sbin/pfctl -s info
    echo '=== Root rules ==='
    sudo -n /sbin/pfctl -sr
    echo '=== HK6 rules and counters ==='
    sudo -n /sbin/pfctl -a "$ANCHOR" -vvsr
    echo '=== Local destinations ==='
    sudo -n /sbin/pfctl -a "$ANCHOR" -t hk6_local_v4 -T show
    echo '=== Bridge ==='
    /sbin/ifconfig bridge100
    echo '=== ARP ==='
    /usr/sbin/arp -an -i bridge100
    echo '=== Default route ==='
    /sbin/route -n get default
  } > "$DIR/guard-status.txt" 2>&1
  echo "Stato salvato: $DIR/guard-status.txt"
}
case "$ACTION" in
apply|apply-ntp)
  /sbin/ifconfig bridge100 | /usr/bin/grep -q 'inet 192.168.2.1 netmask 0xffffff00' || { echo 'Rete cambiata; arresto.' >&2; exit 1; }
  sudo -n /sbin/pfctl -s info > "$DIR/pf-before-status.txt" 2>&1
  /usr/bin/grep -q '^Status: Enabled' "$DIR/pf-before-status.txt" || { echo 'PF non attivo; arresto.' >&2; exit 1; }
  sudo -n /sbin/pfctl -sr > "$DIR/root-before.txt" 2> "$DIR/root-before.stderr"
  # The first non-scrub rule must be the wildcard that evaluates this child.
  FIRST=$(/usr/bin/awk '!/^scrub/ && NF {print; exit}' "$DIR/root-before.txt")
  [ "$FIRST" = 'anchor "com.apple/*" all' ] || { echo 'Regole principali cambiate; arresto.' >&2; exit 1; }
  RULES="$DIR/isolate.pf"
  if [ "$ACTION" = 'apply-ntp' ]; then
    # Refuse this exception on an unverified firmware or different DHCP client.
    /usr/bin/grep -q '"installed_verified_at_patch_points": true' "$ROOT/analysis/uart/ota-exp2/20261018-151522/report.json"
    /usr/sbin/arp -an -i bridge100 | /usr/bin/grep -q '(192.168.2.3) at 0:4:b2:14:7b:a6 '
    RULES="$DIR/isolate-ntp.pf"
  fi
  sudo -n /sbin/pfctl -n -a "$ANCHOR" -f "$RULES"
  sudo -n /sbin/pfctl -a "$ANCHOR" -f "$RULES"
  # Existing IPv4 state could bypass new rules. Limit deletion to the lab subnet.
  sudo -n /sbin/pfctl -k 192.168.2.0/24
  sudo -n /sbin/pfctl -sr > "$DIR/root-after.txt" 2> "$DIR/root-after.stderr"
  /usr/bin/cmp "$DIR/root-before.txt" "$DIR/root-after.txt" || { echo 'Regole principali variate: mantenere camera spenta e controllare.' >&2; exit 1; }
  status
  echo 'Regole HK6 caricate. Se apply-ntp: eccezioni DNS/NTP della sola camera attive, da verificare in cattura.'
  ;;
status) status ;;
remove)
  # Flush only this project's filter rules and tables; never global PF state.
  sudo -n /sbin/pfctl -sr > "$DIR/cleanup-root-before.txt"
  sudo -n /sbin/pfctl -a "$ANCHOR" -F rules
  sudo -n /sbin/pfctl -a "$ANCHOR" -F Tables
  sudo -n /sbin/pfctl -a "$ANCHOR" -sr > "$DIR/guard-removed.txt"
  sudo -n /sbin/pfctl -a "$ANCHOR" -s Tables > "$DIR/guard-tables-removed.txt"
  [ ! -s "$DIR/guard-removed.txt" ] && [ ! -s "$DIR/guard-tables-removed.txt" ] || { echo 'Pulizia HK6 incompleta: controllare i rapporti.' >&2; exit 1; }
  sudo -n /sbin/pfctl -sr > "$DIR/cleanup-root-after.txt"
  /usr/bin/cmp "$DIR/cleanup-root-before.txt" "$DIR/cleanup-root-after.txt" || { echo 'Regole principali variate durante il controllo: verificare.' >&2; exit 1; }
  echo 'Verificato: nessuna regola o tabella HK6 residua; regole principali PF invariate.'
  ;;
esac
