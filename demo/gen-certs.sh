#!/usr/bin/env bash
# Generate self-signed demo certificates with deliberately awkward expiry dates.
#
#   demo/gen-certs.sh broken    ok=90d  warning=20d  critical=3d  expired=5 days ago   (default)
#   demo/gen-certs.sh renewed   every certificate valid for 90 days
#
# `openssl req -x509 -days N` cannot make an already-expired cert, so we use
# `openssl ca -selfsign` with explicit -startdate / -enddate instead.
set -euo pipefail

scenario="${1:-broken}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$here/certs"

case "$scenario" in
  broken)  spec=("ok:90" "warning:20" "critical:3" "expired:-5") ;;
  renewed) spec=("ok:90" "warning:90" "critical:90" "expired:90") ;;
  *) echo "usage: $0 [broken|renewed]" >&2; exit 2 ;;
esac

# Print "now + N days" (N may be negative) as YYYYMMDDHHMMSSZ, nudged one hour away
# from now so the checker (which rounds days down) reports a round "3" / "20" / "-5".
# GNU date first, then BSD/macOS date.
utc_in_days() {
  local nudge=3600
  [ "$1" -lt 0 ] && nudge=-3600
  local epoch=$(( $(date +%s) + $1 * 86400 + nudge ))
  date -u -d "@$epoch" +%Y%m%d%H%M%SZ 2>/dev/null || date -u -r "$epoch" +%Y%m%d%H%M%SZ
}

mkdir -p "$out"

for item in "${spec[@]}"; do
  name="${item%%:*}"
  days="${item##*:}"
  work="$(mktemp -d)"

  if [ "$days" -ge 0 ]; then start="$(utc_in_days -1)"; else start="$(utc_in_days $((days - 365)))"; fi
  end="$(utc_in_days "$days")"

  : > "$work/index.txt"
  echo 01 > "$work/serial"
  cat > "$work/ca.cnf" <<EOF
[ca]
default_ca = ca_default
[ca_default]
database = $work/index.txt
new_certs_dir = $work
serial = $work/serial
default_md = sha256
unique_subject = no
policy = policy_any
[policy_any]
commonName = supplied
organizationName = optional
[san]
subjectAltName = DNS:$name.demo.local,DNS:nginx,DNS:localhost
EOF

  openssl genrsa -out "$out/$name.key" 2048 2>/dev/null
  openssl req -new -key "$out/$name.key" -subj "/CN=$name.demo.local/O=TLS Monitor Demo" \
    -out "$work/req.csr"
  openssl ca -batch -selfsign -notext -config "$work/ca.cnf" -keyfile "$out/$name.key" \
    -in "$work/req.csr" -out "$out/$name.crt" -startdate "$start" -enddate "$end" \
    -extensions san 2>/dev/null
  rm -rf "$work"

  printf '%-9s valid until %s\n' "$name" "$(openssl x509 -in "$out/$name.crt" -noout -enddate | cut -d= -f2)"
done

echo "Scenario '$scenario': certificates written to $out"
