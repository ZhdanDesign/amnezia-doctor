#!/usr/bin/env bash
# amnezia-doctor — серверный пробник.
#
# ТОЛЬКО ЧТЕНИЕ: ничего не устанавливает, не перезапускает и не меняет на сервере.
# Секреты (приватные ключи, PSK, пароли, ключи vpn://) вырезаются до вывода.
#
# Запуск (делает amnezia-doctor): ssh host 'bash -s -- <target_ip> <client_public_ip>' < server_probe.sh
# Вывод:  "@@FACT KEY=VALUE"          — факты для детерминированного анализа
#         "@@BEGIN name" ... "@@END name" — сырые логи для человека/LLM

export LC_ALL=C LANG=C
PROBE_VERSION="1.0.0"
TARGET_IP="${1:-}"
CLIENT_PUBLIC_IP="${2:-}"

SUDO=""
IS_ROOT=no
if [ "$(id -u)" = 0 ]; then
  IS_ROOT=yes
elif sudo -n true 2>/dev/null; then
  SUDO="sudo -n"
fi
export SUDO

have() { command -v "$1" >/dev/null 2>&1; }

t() {
  local s="$1"; shift
  if have timeout; then timeout "$s" "$@"; else "$@"; fi
}

fact() {
  local k="$1"; shift
  printf '@@FACT %s=%s\n' "$k" "$(printf '%s' "$*" | tr '\n\t\r' '   ')"
}

redact() {
  sed -E \
    -e 's/((private|preshared|psk|password|passwd|secret|token|priv_key|privkey)[A-Za-z_ ]*["'\'']?[[:space:]]*[:=][[:space:]]*["'\'']?)[^"'\''[:space:],}]+/\1<REDACTED>/Ig' \
    -e 's#vpn://[A-Za-z0-9_=-]+#vpn://<REDACTED>#g' \
    -e 's/(endpoint: [0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+/\1.x/' \
    -e '/-----BEGIN [A-Z ]*PRIVATE KEY-----/,/-----END [A-Z ]*PRIVATE KEY-----/c <REDACTED PRIVATE KEY BLOCK>'
}

# sec NAME 'shell command' — сырой блок, с таймаутом, редакцией и ограничением длины
sec() {
  local name="$1" cmd="$2"
  printf '@@BEGIN %s\n' "$name"
  { t 25 bash -c "$cmd" 2>&1; rc=$?; [ "$rc" -ne 0 ] && echo "[exit $rc]"; } | redact | head -n 400
  printf '@@END %s\n' "$name"
}

# ---------------------------------------------------------------- база
fact P_VERSION "$PROBE_VERSION"
fact S_USER "$(id -un)"
fact S_IS_ROOT "$IS_ROOT"
if [ "$IS_ROOT" = yes ]; then fact S_SUDO not_needed
elif [ -n "$SUDO" ]; then fact S_SUDO nopass
else fact S_SUDO none
fi
fact S_NOW "$(date +%s)"
fact S_SSH_CLIENT_IP "${SSH_CLIENT%% *}"

if [ -r /etc/os-release ]; then . /etc/os-release; fi
fact S_OS "${PRETTY_NAME:-unknown}"
fact S_KERNEL "$(uname -r)"
fact S_ARCH "$(uname -m)"
fact S_NPROC "$(nproc 2>/dev/null)"
fact S_UPTIME_SEC "$(cut -d. -f1 /proc/uptime 2>/dev/null)"
fact S_REBOOT_REQUIRED "$([ -f /var/run/reboot-required ] && echo yes || echo no)"
fact S_MEM_TOTAL_MB "$(awk '/^MemTotal:/{print int($2/1024)}' /proc/meminfo 2>/dev/null)"
fact S_MEM_AVAIL_MB "$(awk '/^MemAvailable:/{print int($2/1024)}' /proc/meminfo 2>/dev/null)"
fact S_SWAP_TOTAL_MB "$(awk '/^SwapTotal:/{print int($2/1024)}' /proc/meminfo 2>/dev/null)"
fact S_DISK_FREE_MB "$(df -Pm / 2>/dev/null | awk 'NR==2{print $4}')"
fact S_LOAD1 "$(cut -d' ' -f1 /proc/loadavg 2>/dev/null)"
fact S_IP_FORWARD "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)"
fact S_NTP_SYNC "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)"

DEF_IF="$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
fact S_DEFAULT_IF "$DEF_IF"
[ -n "$DEF_IF" ] && fact S_DEFAULT_IF_MTU "$(cat "/sys/class/net/$DEF_IF/mtu" 2>/dev/null)"
if [ -n "$TARGET_IP" ]; then
  if ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -qx "$TARGET_IP"; then
    fact S_TARGET_IP_ON_IF yes
  else
    fact S_TARGET_IP_ON_IF no
  fi
fi

code="$(t 8 curl -s -o /dev/null -m 6 -w '%{http_code}' https://1.1.1.1/ 2>/dev/null)"
fact S_OUT_HTTP "${code:-000}"
fact S_DNS_OK "$(t 8 getent hosts one.one.one.one >/dev/null 2>&1 && echo yes || echo no)"

for tool in awg wg docker tcpdump ufw fail2ban-client iptables nft; do
  key="$(printf '%s' "$tool" | tr 'a-z-' 'A-Z_')"
  fact "S_HAS_$key" "$(have "$tool" && echo yes || echo no)"
done
fact S_AWG_MODULE "$(lsmod 2>/dev/null | awk '$1=="amneziawg"{f=1} END{print f?"loaded":"not_loaded"}')"
fact S_WG_MODULE "$(lsmod 2>/dev/null | awk '$1=="wireguard"{f=1} END{print f?"loaded":"not_loaded"}')"
have dkms && fact S_DKMS "$(dkms status 2>/dev/null | grep -iE 'amnezia|wireguard' | tr '\n' ';')"

if out="$(t 10 $SUDO sshd -T 2>/dev/null)"; then
  printf '%s\n' "$out" | awk '$1=="port"||$1=="passwordauthentication"||$1=="permitrootlogin"||$1=="pubkeyauthentication" {print "@@FACT S_SSHD_" toupper($1) "=" $2}'
fi

# ---------------------------------------------------------------- порты
LISTEN="$($SUDO ss -H -tulnp 2>/dev/null | awk '
  $1!="tcp" && $1!="udp" {next}
  {
    proto=$1; loc=$5; proc="kernel"
    if (match($0, /\(\("[^"]+"/)) proc=substr($0, RSTART+3, RLENGTH-4)
    n=split(loc, a, ":"); port=a[n]
    host=substr(loc, 1, length(loc)-length(port)-1)
    if (host ~ /^127\./ || host ~ /^\[?::1\]?$/ || host ~ /%lo$/) next
    print proto "/" port "/" proc
  }' | sort -u | tr '\n' ' ')"
fact S_LISTEN "$LISTEN"

# ---------------------------------------------------------------- docker
CONTAINERS_RUNNING=""
if have docker; then
  if t 10 $SUDO docker info >/dev/null 2>&1; then
    fact S_DOCKER_DAEMON yes
    ps_out="$(t 15 $SUDO docker ps -a --format '{{.Names}}|{{.Status}}|{{.Image}}' 2>/dev/null | sort)"
    amz=""; down=""; flap=""; all=""
    while IFS='|' read -r name status image; do
      [ -z "$name" ] && continue
      all="$all $name"
      if printf '%s %s' "$name" "$image" | grep -qiE 'amnezia|awg|wireguard|xray|openvpn'; then
        printf '%s %s' "$name" "$image" | grep -qi amnezia && amz="$amz $name"
        rc="$(t 10 $SUDO docker inspect -f '{{.RestartCount}}' "$name" 2>/dev/null)"
        case "$status" in
          Up*) CONTAINERS_RUNNING="$CONTAINERS_RUNNING $name" ;;
          *) down="$down $name" ;;
        esac
        case "$status" in Restarting*) flap="$flap $name:restarting" ;; esac
        [ -n "$rc" ] && [ "$rc" -ge 3 ] 2>/dev/null && flap="$flap $name:$rc"
      fi
    done <<EOF
$ps_out
EOF
    fact S_CONTAINERS "$(echo $all)"
    fact S_AMNEZIA_CONTAINERS "$(echo $amz)"
    fact S_CONTAINERS_DOWN "$(echo $down)"
    fact S_CONTAINERS_FLAPPING "$(echo $flap)"
    sec docker_ps "$SUDO docker ps -a --format '{{.Names}} | {{.Status}} | {{.Image}} | {{.Ports}}'"
    for c in $amz; do
      sec "docker_logs_$c" "$SUDO docker logs --tail 80 $c"
    done
  else
    fact S_DOCKER_DAEMON no
  fi
fi

# ---------------------------------------------------------------- VPN-интерфейсы
# строки "scope|container|tool|ifname"
IFLIST=""
seen=" "
for tool in awg wg; do
  have "$tool" || continue
  for ifn in $(t 10 $SUDO "$tool" show interfaces 2>/dev/null); do
    case "$seen" in *" host:$ifn "*) continue ;; esac
    seen="$seen host:$ifn "
    IFLIST="$IFLIST
host||$tool|$ifn"
  done
done
for c in $CONTAINERS_RUNNING; do
  for tool in awg wg; do
    for ifn in $(t 10 $SUDO docker exec "$c" "$tool" show interfaces 2>/dev/null); do
      case "$seen" in *" $c:$ifn "*) continue ;; esac
      seen="$seen $c:$ifn "
      IFLIST="$IFLIST
container|$c|$tool|$ifn"
    done
  done
done

i=0
while IFS='|' read -r scope c tool ifn; do
  [ -z "$ifn" ] && continue
  i=$((i + 1))
  pre=""
  [ "$scope" = container ] && pre="docker exec $c"
  fact "S_IF_${i}_NAME" "$ifn"
  if [ "$scope" = container ]; then fact "S_IF_${i}_SCOPE" "container:$c"; else fact "S_IF_${i}_SCOPE" host; fi
  fact "S_IF_${i}_TOOL" "$tool"

  t 15 $SUDO $pre "$tool" show "$ifn" 2>/dev/null | awk -v i="$i" '
    /^peer:/ {exit}
    /^[[:space:]]+[a-z][a-z0-9 ]*:/ {
      line=$0; sub(/^[[:space:]]+/, "", line)
      k=line; sub(/:.*/, "", k)
      v=line; sub(/^[^:]*:[[:space:]]*/, "", v)
      if (k=="public key") print "@@FACT S_IF_" i "_PUBKEY=" v
      else if (k=="listening port") print "@@FACT S_IF_" i "_PORT=" v
      else if (k=="private key") next
      else if (k ~ /^[a-z][a-z0-9]*$/) print "@@FACT S_IF_" i "_K_" toupper(k) "=" v
    }'

  # dump: первая строка — интерфейс с приватным ключом, пропускается; у пиров PSK (поле 2) не выводится
  t 15 $SUDO $pre "$tool" show "$ifn" dump 2>/dev/null | awk -F'\t' -v i="$i" -v now="$(date +%s)" '
    NR==1 {next}
    {
      n++
      if ($5==0) never++; else if (now-$5<=180) recent++
      if (n>64) next
      ep=$3
      if (ep ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$/) {
        split(ep, hp, ":"); split(hp[1], o, ".")
        ep=o[1] "." o[2] "." o[3] ".x:" hp[2]
      } else if (ep ~ /^\[/) {
        sub(/\].*/, "", ep); ep=ep "]"
      }
      age = ($5==0) ? "never" : now-$5
      p="@@FACT S_IF_" i "_PEER_" n "_"
      print p "PUB8=" substr($1, 1, 8)
      print p "ALLOWED=" $4
      print p "ENDPOINT=" ep
      print p "HS_AGE=" age
      print p "RX=" $6
      print p "TX=" $7
    }
    END {
      print "@@FACT S_IF_" i "_PEERS=" n+0
      print "@@FACT S_IF_" i "_PEERS_RECENT=" recent+0
      print "@@FACT S_IF_" i "_PEERS_NEVER=" never+0
    }'

  sec "if_${i}_${ifn}_show" "$SUDO $pre $tool show $ifn"
done <<EOF
$IFLIST
EOF
fact S_IF_COUNT "$i"

# ---------------------------------------------------------------- файрвол
if have ufw; then
  if out="$(t 10 $SUDO ufw status 2>/dev/null)"; then
    if printf '%s\n' "$out" | head -n 1 | grep -q 'Status: active'; then fact S_UFW_ACTIVE yes; else fact S_UFW_ACTIVE no; fi
    fact S_UFW_ALLOW "$(printf '%s\n' "$out" | awk '/ALLOW/ && !/\(v6\)/ {print $1}' | sort -u | tr '\n' ' ')"
  fi
fi
if have iptables; then
  out="$(t 10 $SUDO iptables -S INPUT 2>/dev/null)" && fact S_IPT_INPUT_POLICY "$(printf '%s\n' "$out" | awk 'NR==1{print $3}')"
  out="$(t 10 $SUDO iptables -S FORWARD 2>/dev/null)" && fact S_IPT_FORWARD_POLICY "$(printf '%s\n' "$out" | awk 'NR==1{print $3}')"
  out="$(t 10 $SUDO iptables -t nat -S 2>/dev/null)" && fact S_NAT_MASQ_COUNT "$(printf '%s\n' "$out" | grep -c MASQUERADE)"
  out="$(t 10 $SUDO iptables -S 2>/dev/null)" && fact S_IPT_UDP_DPORTS "$(printf '%s\n' "$out" | grep -- '-p udp' | grep -- '-j ACCEPT' | grep -oE -- '--dport [0-9:]+' | awk '{print $2}' | sort -u | tr '\n' ' ')"
fi

if have fail2ban-client; then
  if out="$(t 10 $SUDO fail2ban-client status 2>/dev/null)"; then
    fact S_F2B_ACTIVE yes
    jails="$(printf '%s\n' "$out" | sed -n 's/.*Jail list:[[:space:]]*//p' | tr ',' ' ')"
    banned=""
    for j in $jails; do
      banned="$banned $(t 10 $SUDO fail2ban-client status "$j" 2>/dev/null | sed -n 's/.*Banned IP list:[[:space:]]*//p')"
    done
    fact S_F2B_JAILS "$(echo $jails)"
    fact S_F2B_BANNED_COUNT "$(echo $banned | wc -w | tr -d ' ')"
    ssh_ip="${SSH_CLIENT%% *}"
    is_banned() { [ -n "$1" ] && printf ' %s ' "$banned" | grep -q " $1 "; }
    fact S_F2B_BANS_SSH_CLIENT "$(is_banned "$ssh_ip" && echo yes || echo no)"
    [ -n "$CLIENT_PUBLIC_IP" ] && fact S_F2B_BANS_CLIENT_PUBLIC "$(is_banned "$CLIENT_PUBLIC_IP" && echo yes || echo no)"
  else
    fact S_F2B_ACTIVE no
  fi
fi

# ---------------------------------------------------------------- сырые логи
sec os 'cat /etc/os-release; echo; uname -a; echo; uptime'
sec memory_disk 'free -m; echo; df -h /'
sec ip_addr 'ip -brief addr'
sec ip_route 'ip route'
sec listening "$SUDO ss -tulnp"
sec sysctl_forward 'sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding'
sec iptables_filter "$SUDO iptables -S"
sec iptables_nat "$SUDO iptables -t nat -S"
sec ufw "$SUDO ufw status verbose"
sec fail2ban "$SUDO fail2ban-client status"
sec sshd_effective "$SUDO sshd -T | grep -E '^(port|passwordauthentication|permitrootlogin|pubkeyauthentication|maxauthtries) '"
sec timedate 'timedatectl'
sec dkms 'dkms status'
sec journal_vpn "$SUDO journalctl --no-pager -n 150 -p warning -u 'awg-quick@*' -u 'wg-quick@*' -u docker.service -u fail2ban.service"
sec dmesg_vpn "$SUDO dmesg | grep -iE 'amnezia|wireguard|oom|out of memory|segfault|martian' | tail -n 60"

fact P_DONE yes
