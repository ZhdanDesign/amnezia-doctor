#!/bin/bash
# Офлайн-тесты правил анализа: для каждой фикстуры facts.txt → находки должны совпасть с expected.txt
# (уровень и ID, в том же порядке), а повторный анализ — дать байт-в-байт тот же отчёт.
# Плюс разбор ключа vpn:// приложения Amnezia. Docker и сеть не нужны.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FAILS=0
ok()   { echo "  ok   $1"; }
fail() { echo "  FAIL $1"; FAILS=$((FAILS + 1)); }

for d in "$ROOT"/tests/fixtures/*/; do
  name="$(basename "$d")"
  t="$(mktemp -d)"
  cp "$d/facts.txt" "$t/"
  /bin/bash "$ROOT/amnezia-doctor" --analyze "$t" >/dev/null 2>&1
  if cut -f1,2 "$t/findings.tsv" | cmp -s - "$d/expected.txt"; then ok "$name: находки"; else
    fail "$name: находки"; diff <(cut -f1,2 "$t/findings.tsv") "$d/expected.txt" | sed 's/^/       /'
  fi
  cp "$t/report.md" "$t/a.md"; cp "$t/report.json" "$t/a.json"
  /bin/bash "$ROOT/amnezia-doctor" --analyze "$t" >/dev/null 2>&1
  if cmp -s "$t/a.md" "$t/report.md" && cmp -s "$t/a.json" "$t/report.json"; then ok "$name: детерминированность"; else fail "$name: детерминированность"; fi
  if perl -MJSON::PP -e 'local $/; open my $f, "<", shift or die; JSON::PP->new->decode(<$f>)' "$t/report.json" 2>/dev/null; then
    ok "$name: report.json валиден"; else fail "$name: report.json валиден"; fi
  rm -rf "$t"
done

# ключ vpn:// в формате приложения Amnezia: base64url(qCompress(json)), конфиг лежит строкой внутри JSON
t="$(mktemp -d)"
perl -MCompress::Zlib -MMIME::Base64 -e '
  my $cfg = "[Interface]\nAddress = 10.8.1.5/32\nPrivateKey = SECRET_MUST_NOT_LEAK\nJc = 4\nH1 = 777\n\n[Peer]\nPublicKey = SRVPUB=\nEndpoint = 203.0.113.10:443\n";
  (my $esc = $cfg) =~ s/\n/\\n/g;
  my $json = "{\"containers\":[{\"container\":\"amnezia-awg\",\"awg\":{\"last_config\":\"{\\\"config\\\":\\\"" . ($esc =~ s/\\n/\\\\n/gr) . "\\\"}\"}}],\"hostName\":\"203.0.113.10\"}";
  my $bin = pack("N", length $json) . compress($json);
  (my $b = encode_base64($bin, "")) =~ tr{+/}{-_}; $b =~ s/=+$//;
  print "vpn://$b\n";' > "$t/key.txt"
out="$(perl "$ROOT/lib/parse_client_config.pl" "$t/key.txt")"
for want in K_SOURCE=vpnkey K_PARSE=ok K_JC=4 K_H1=777 K_ENDPOINT_PORT=443 K_SERVER_PUBKEY=SRVPUB= K_ADDRESS=10.8.1.5/32 K_PROTOCOL=amneziawg K_HAS_PRIVATE_KEY=yes; do
  if printf '%s\n' "$out" | grep -qx "$want"; then ok "vpn:// → $want"; else fail "vpn:// → $want"; fi
done
if printf '%s' "$out" | grep -q SECRET_MUST_NOT_LEAK; then fail "vpn://: приватный ключ утёк"; else ok "vpn://: приватный ключ не выводится"; fi
rm -rf "$t"

echo
if [ "$FAILS" -eq 0 ]; then echo "Тесты: все пройдены"; else echo "Тесты: провалено $FAILS"; fi
exit "$FAILS"
