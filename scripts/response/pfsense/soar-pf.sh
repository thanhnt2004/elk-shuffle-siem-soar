#!/bin/sh
# /usr/local/sbin/soar-pf.sh — hanh dong SOAR tren pfSense (DATN, Goi A)
#
# Shuffle goi qua SSH (user soar, sudo chi cho script nay):
#   sudo /usr/local/sbin/soar-pf.sh add  <bang> <ip> <ttl_giay>   them IP (ttl 0 = khong tu go), cat ket noi dang mo
#   sudo /usr/local/sbin/soar-pf.sh del  <bang> <ip>              go IP
#   sudo /usr/local/sbin/soar-pf.sh test <bang> <ip>              in PRESENT hoac ABSENT
#   sudo /usr/local/sbin/soar-pf.sh show <bang>                   in noi dung bang + file trang thai
#   sudo /usr/local/sbin/soar-pf.sh sinkhole-add  <domain> <ttl_giay>
#   sudo /usr/local/sbin/soar-pf.sh sinkhole-del  <domain>
#   sudo /usr/local/sbin/soar-pf.sh sinkhole-test <domain>        in SINKHOLED hoac NOT-SINKHOLED
#   sudo /usr/local/sbin/soar-pf.sh sync                          (cron moi phut) go muc het han, nap lai muc con han
#
# Bang hop le: soar_block (chan vao o WAN), soar_egress (chan LAN di ra), soar_isolate (co lap host LAN).
#
# Vi sao co file trang thai + sync: khi pfSense nap lai filter (sua rule, khoi dong lai, ...), noi dung bang
# cua alias bi thay bang noi dung trong cau hinh, nen muc SOAR them luc chay se mat. sync nap lai trong
# vong 1 phut, dong thoi la noi thuc thi TTL doc lap voi Shuffle (Shuffle chet thi chan van tu go).

PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
STATE_DIR=/var/db/soar
TABLES="soar_block soar_egress soar_isolate"
UC="unbound-control -c /var/unbound/unbound.conf"

umask 077
mkdir -p "$STATE_DIR"

log() { logger -t datn-soar "$*"; }
out() { echo "$*"; log "$*"; }
die() { echo "ERROR $*"; log "ERROR $*"; exit 1; }

valid_table() { for t in $TABLES; do [ "$t" = "$1" ] && return 0; done; return 1; }
valid_ip() {
  echo "$1" | awk -F. 'NF != 4 { exit 1 } { for (i = 1; i <= 4; i++) if ($i !~ /^[0-9]+$/ || $i > 255) exit 1 }'
}
# Dia chi ha tang: khong bao gio chan/co lap (EC2, VPN, gateway, NAT VMware, WAN pfSense)
protected_ip() {
  case "$1" in
    10.99.0.*|127.*|0.*|255.*|192.168.100.1|192.168.173.1|192.168.173.2|192.168.173.10) return 0 ;;
  esac
  return 1
}
valid_ttl() { echo "$1" | grep -Eq '^[0-9]{1,7}$'; }
valid_domain() { echo "$1" | grep -Eq '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'; }
protected_domain() {
  case "$1" in
    lab.local|*.lab.local|*.arpa|localhost|*.localhost) return 0 ;;
  esac
  return 1
}

expiry_of() { if [ "$1" -gt 0 ]; then echo $(( $(date +%s) + $1 )); else echo 0; fi; }

# state_put <file> <khoa> <han> : ghi de dong cua khoa
state_put() { touch "$1"; grep -v "^$2 " "$1" > "$1.tmp"; echo "$2 $3" >> "$1.tmp"; mv "$1.tmp" "$1"; }
state_del() { [ -f "$1" ] || return 0; grep -v "^$2 " "$1" > "$1.tmp"; mv "$1.tmp" "$1"; }

cmd_add() {
  t=$1; ip=$2; ttl=${3:-0}
  valid_table "$t" || die "bang khong hop le: $t"
  valid_ip "$ip" || die "IP khong hop le: $ip"
  protected_ip "$ip" && die "IP ha tang, tu choi: $ip"
  valid_ttl "$ttl" || die "TTL khong hop le: $ttl"
  state_put "$STATE_DIR/$t.state" "$ip" "$(expiry_of "$ttl")"
  pfctl -q -t "$t" -T add "$ip" || die "pfctl add that bai"
  # Cat state dang co de lenh chan co hieu luc ngay voi ket noi da mo (reverse shell, beacon...)
  pfctl -q -k "$ip" >/dev/null 2>&1
  pfctl -q -k 0.0.0.0/0 -k "$ip" >/dev/null 2>&1
  out "OK add $t $ip ttl=$ttl"
}

cmd_del() {
  t=$1; ip=$2
  valid_table "$t" || die "bang khong hop le: $t"
  valid_ip "$ip" || die "IP khong hop le: $ip"
  state_del "$STATE_DIR/$t.state" "$ip"
  pfctl -q -t "$t" -T delete "$ip" >/dev/null 2>&1
  out "OK del $t $ip"
}

cmd_test() {
  t=$1; ip=$2
  valid_table "$t" || die "bang khong hop le: $t"
  valid_ip "$ip" || die "IP khong hop le: $ip"
  if pfctl -q -t "$t" -T test "$ip" >/dev/null 2>&1; then echo "PRESENT $t $ip"; else echo "ABSENT $t $ip"; fi
}

cmd_show() {
  t=$1
  valid_table "$t" || die "bang khong hop le: $t"
  echo "--- pfctl -t $t -T show"
  pfctl -q -t "$t" -T show
  echo "--- $STATE_DIR/$t.state (ip han_epoch; 0 = khong TTL)"
  cat "$STATE_DIR/$t.state" 2>/dev/null
}

sink_add() {
  d=$(echo "$1" | tr 'A-Z' 'a-z'); ttl=${2:-0}
  valid_domain "$d" || die "domain khong hop le: $d"
  protected_domain "$d" && die "domain noi bo, tu choi: $d"
  valid_ttl "$ttl" || die "TTL khong hop le: $ttl"
  state_put "$STATE_DIR/sinkhole.state" "$d" "$(expiry_of "$ttl")"
  $UC local_zone "$d" always_nxdomain >/dev/null || die "unbound-control local_zone that bai"
  $UC flush_zone "$d" >/dev/null 2>&1
  out "OK sinkhole-add $d ttl=$ttl"
}

sink_del() {
  d=$(echo "$1" | tr 'A-Z' 'a-z')
  valid_domain "$d" || die "domain khong hop le: $d"
  state_del "$STATE_DIR/sinkhole.state" "$d"
  $UC local_zone_remove "$d" >/dev/null 2>&1
  $UC flush_zone "$d" >/dev/null 2>&1
  out "OK sinkhole-del $d"
}

sink_test() {
  d=$(echo "$1" | tr 'A-Z' 'a-z')
  valid_domain "$d" || die "domain khong hop le: $d"
  if $UC list_local_zones 2>/dev/null | grep -q "^$d\. always_nxdomain"; then echo "SINKHOLED $d"; else echo "NOT-SINKHOLED $d"; fi
}

cmd_sync() {
  now=$(date +%s)
  for t in $TABLES; do
    f="$STATE_DIR/$t.state"
    [ -f "$f" ] || continue
    : > "$f.new"
    while read -r ip exp; do
      [ -n "$ip" ] || continue
      if [ "$exp" -ne 0 ] && [ "$exp" -le "$now" ]; then
        pfctl -q -t "$t" -T delete "$ip" >/dev/null 2>&1
        log "EXPIRE $t $ip"
      else
        echo "$ip $exp" >> "$f.new"
        pfctl -q -t "$t" -T add "$ip" >/dev/null 2>&1
      fi
    done < "$f"
    mv "$f.new" "$f"
  done
  f="$STATE_DIR/sinkhole.state"
  if [ -f "$f" ]; then
    : > "$f.new"
    while read -r d exp; do
      [ -n "$d" ] || continue
      if [ "$exp" -ne 0 ] && [ "$exp" -le "$now" ]; then
        $UC local_zone_remove "$d" >/dev/null 2>&1
        log "EXPIRE sinkhole $d"
      else
        echo "$d $exp" >> "$f.new"
        $UC local_zone "$d" always_nxdomain >/dev/null 2>&1
      fi
    done < "$f"
    mv "$f.new" "$f"
  fi
}

case "${1:-}" in
  add)           shift; cmd_add "$@" ;;
  del)           shift; cmd_del "$@" ;;
  test)          shift; cmd_test "$@" ;;
  show)          shift; cmd_show "$@" ;;
  sinkhole-add)  shift; sink_add "$@" ;;
  sinkhole-del)  shift; sink_del "$@" ;;
  sinkhole-test) shift; sink_test "$@" ;;
  sync)          cmd_sync ;;
  *) echo "Dung: $0 add|del|test|show <bang> ... | sinkhole-add|sinkhole-del|sinkhole-test <domain> | sync"; exit 2 ;;
esac
