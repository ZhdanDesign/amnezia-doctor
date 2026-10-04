#!/bin/bash
# Интеграционный тест на Mac с Docker Desktop.
# Поднимает контейнер-сервер (sshd + WireGuard wg0 + NAT + tcpdump), запускает amnezia-doctor
# через настоящий SSH и настоящую UDP-пробу, проверяет находки, отсутствие секретов в выводе
# и детерминированность повторного анализа.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
W="$(mktemp -d /tmp/amzd-e2e.XXXXXX)"
NAME=amnezia-doctor-e2e
HOSTKEY_ID="[127.0.0.1]:2222"
FAILS=0

cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1
  ssh-keygen -R "$HOSTKEY_ID" >/dev/null 2>&1
  [ -n "${KEEP:-}" ] && echo "результаты: $W" || rm -rf "$W"
}
trap cleanup EXIT

check() {  # описание, команда...
  local d="$1"; shift
  if "$@"; then echo "  ok   $d"; else echo "  FAIL $d"; FAILS=$((FAILS + 1)); fi
}
has() { grep -q "^$1	$2	" "$3/findings.tsv"; }

echo "== сборка образа"
docker build -q -t "$NAME" - >/dev/null <<'EOF' || exit 1
FROM ubuntu:24.04
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
      openssh-server wireguard-tools iproute2 iptables tcpdump curl kmod procps >/dev/null \
 && mkdir -p /run/sshd /root/.ssh
CMD ["/usr/sbin/sshd", "-D", "-e"]
EOF

echo "== запуск сервера"
ssh-keygen -R "$HOSTKEY_ID" >/dev/null 2>&1
ssh-keygen -q -t ed25519 -N "" -f "$W/key"
docker run -d --name "$NAME" --cap-add NET_ADMIN --cap-add NET_RAW \
  -p 127.0.0.1:2222:22 -p 127.0.0.1:51820:51820/udp "$NAME" >/dev/null || exit 1
docker exec -i "$NAME" sh -c 'cat > /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys' < "$W/key.pub"
docker exec "$NAME" sh -c '
  umask 077
  wg genkey > /root/s.key; wg pubkey < /root/s.key > /root/s.pub
  wg genkey > /root/c.key; wg pubkey < /root/c.key > /root/c.pub
  ip link add wg0 type wireguard
  wg set wg0 listen-port 51820 private-key /root/s.key peer "$(cat /root/c.pub)" allowed-ips 10.9.0.2/32
  ip addr add 10.9.0.1/24 dev wg0
  ip link set wg0 up
  iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o eth0 -j MASQUERADE
' || exit 1
SPUB="$(docker exec "$NAME" cat /root/s.pub)"
sleep 2

cat > "$W/good.conf" <<EOF
[Interface]
Address = 10.9.0.2/32
PrivateKey = TEST_PRIVATE_KEY_MUST_NOT_LEAK
DNS = 1.1.1.1
MTU = 1280

[Peer]
PublicKey = $SPUB
PresharedKey = TEST_PSK_MUST_NOT_LEAK
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 127.0.0.1:51820
EOF

sed -e 's#^Address = .*#Address = 10.9.0.99/32#' -e 's#^MTU = 1280#MTU = 1280\nJc = 4\nJmin = 40\nJmax = 70#' \
  "$W/good.conf" > "$W/bad.conf"

run() {  # out_dir config
  mkdir -p "$1"
  /bin/bash "$ROOT/amnezia-doctor" -p 2222 -i "$W/key" -c "$2" -o "$1" root@127.0.0.1 >/dev/null 2>&1
  ls -d "$1"/amnezia-doctor_*/ | head -n 1
}

echo "== сценарий 1: исправный сервер, верный конфиг"
R1="$(run "$W/r1" "$W/good.conf")"
check "SSH-вход"                    has OK SSH02 "$R1"
check "найден интерфейс wg0"        has OK VPN05 "$R1"
check "UDP доходит до сервера"      has OK PRB03 "$R1"
check "нет ложной тревоги по порту sshd" bash -c "! grep -q '	PRB04	' '$R1/findings.tsv'"
check "конфиг совпал, клиент ещё не подключался" has WARN CFG07 "$R1"
check "нет ложного несовпадения параметров" bash -c "! grep -q '	CFG05	' '$R1/findings.tsv'"
check "секреты не утекли"           bash -c "! grep -rqE 'TEST_PRIVATE_KEY_MUST_NOT_LEAK|TEST_PSK_MUST_NOT_LEAK' '$R1'"
check "приватный ключ сервера не утёк" bash -c "! grep -rqF \"\$(docker exec $NAME cat /root/s.key)\" '$R1'"
check "report.json валиден"         perl -MJSON::PP -e 'local $/; open my $f, "<", shift or die; JSON::PP->new->decode(<$f>)' "$R1/report.json"
check "архив создан"                test -f "${R1%/}.zip"

echo "== сценарий 2: чужой конфиг (AmneziaWG-параметры на WireGuard-сервере, удалённый пир)"
R2="$(run "$W/r2" "$W/bad.conf")"
check "несовпадение обфускации"     has FAIL CFG05 "$R2"
check "пир не найден"               has FAIL CFG06 "$R2"

echo "== детерминированность"
cp "$R1/report.md" "$W/a.md"; cp "$R1/report.json" "$W/a.json"
/bin/bash "$ROOT/amnezia-doctor" --analyze "$R1" >/dev/null 2>&1
check "report.md повторяется байт-в-байт"   cmp -s "$W/a.md" "$R1/report.md"
check "report.json повторяется байт-в-байт" cmp -s "$W/a.json" "$R1/report.json"

echo
if [ "$FAILS" -eq 0 ]; then echo "E2E: все проверки пройдены"; else echo "E2E: провалено проверок: $FAILS"; fi
exit "$FAILS"
