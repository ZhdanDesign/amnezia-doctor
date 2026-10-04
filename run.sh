#!/bin/bash
# Загрузчик amnezia-doctor: скачивает пакет скриптов с GitHub во временную папку и запускает проверку.
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/ZhdanDesign/amnezia-doctor/main/run.sh)
#
# Без аргументов проверяется Mac. С IP сервера — ещё и сервер: … run.sh) IP
#
# Версию можно закрепить: AMNEZIA_DOCTOR_REF=v1.4.1 bash <(curl -fsSL …/run.sh)
set -euo pipefail

REPO="ZhdanDesign/amnezia-doctor"
REF="${AMNEZIA_DOCTOR_REF:-main}"

dir="$(mktemp -d /tmp/amnezia-doctor.XXXXXX)"
trap 'rm -rf "$dir"' EXIT

echo "Загружаю $REPO@$REF …" >&2
curl -fsSL "https://codeload.github.com/$REPO/tar.gz/$REF" | tar -xz -C "$dir" --strip-components 1

/bin/bash "$dir/amnezia-doctor" "$@"
