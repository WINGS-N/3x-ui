#!/bin/sh

set -eu

arch="$1"
variant="$2"
XRAY_VERSION="v26.3.27-wv"

case "${arch}${variant:+/${variant}}" in
    amd64)
        ARCH="64"
        FNAME="amd64"
        ;;
    386|i386)
        ARCH="32"
        FNAME="i386"
        ;;
    arm64 | arm64/* | aarch64 | aarch64/*)
        ARCH="arm64-v8a"
        FNAME="arm64"
        ;;
    arm/v7 | armv7 | arm | arm32)
        ARCH="arm32-v7a"
        FNAME="arm32"
        ;;
    arm/v6 | armv6)
        ARCH="arm32-v6"
        FNAME="armv6"
        ;;
    *)
        ARCH="64"
        FNAME="amd64"
        ;;
esac
mkdir -p build/bin
cd build/bin
curl -sfLRO "https://github.com/WINGS-N/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-${ARCH}.zip"
unzip "Xray-linux-${ARCH}.zip"
rm -f "Xray-linux-${ARCH}.zip" geoip.dat geosite.dat
mv xray "xray-linux-${FNAME}"
printf '%s\n' "${XRAY_VERSION}" > "xray-linux-${FNAME}.release"
case "${FNAME}" in
    amd64|arm64)
        VKTURN_VERSION="$(curl -fsSL https://api.github.com/repos/WINGS-N/vk-turn-proxy/releases/latest | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
        [ -n "${VKTURN_VERSION}" ] || { echo "Failed to resolve vk-turn-proxy latest release tag" >&2; exit 1; }
        curl -sfLRo "vk-turn-proxy-server-linux-${FNAME}" "https://github.com/WINGS-N/vk-turn-proxy/releases/download/${VKTURN_VERSION}/server-linux-${FNAME}"
        chmod +x "vk-turn-proxy-server-linux-${FNAME}"
        printf '%s\n' "${VKTURN_VERSION}" > "vk-turn-proxy-server-linux-${FNAME}.release"
        ;;
esac
curl -sfLRO https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat
curl -sfLRO https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat
curl -sfLRo geoip_IR.dat https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download/geoip.dat
curl -sfLRo geosite_IR.dat https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download/geosite.dat
curl -sfLRo geoip_RU.dat https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat
curl -sfLRo geosite_RU.dat https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat
cd ../../
