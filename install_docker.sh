#!/usr/bin/env bash
set -euo pipefail

install_dir="3x-ui"
compose_url="https://raw.githubusercontent.com/WINGS-N/3x-ui/main/docker-compose.yml"

if [[ ${EUID} -ne 0 ]]; then
    echo "Please run this script as root"
    exit 1
fi

mkdir -p "${install_dir}/db" "${install_dir}/cert"
cd "${install_dir}"

curl -fLSo docker-compose.yml "${compose_url}"
curl -sSL https://get.docker.com/ | CHANNEL=stable bash

docker compose up -d
