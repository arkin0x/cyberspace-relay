#!/bin/sh
# One-time setup of a fresh Ubuntu 24.04 droplet for the ONOSENDAI default
# relay. Run as root on the droplet:
#   curl -fsSL https://raw.githubusercontent.com/arkin0x/cyberspace-relay/main/deploy/onosendai/setup-droplet.sh | GRAIN_OWNER_PUBKEY=<npub> sh
# Needs the DNS A record for relay.onosendai.tech pointing at this droplet
# before Caddy can get a certificate (it retries until it can).
set -eu
: "${GRAIN_OWNER_PUBKEY:?set GRAIN_OWNER_PUBKEY to the operator npub}"

apt-get update
apt-get install -y ca-certificates curl git ufw
# Docker from Docker's own repository (Ubuntu's docker.io lacks compose v2).
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Only SSH and the web ports.
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 443/udp
ufw --force enable

mkdir -p /opt && cd /opt
[ -d cyberspace-relay ] || git clone --recurse-submodules https://github.com/arkin0x/cyberspace-relay.git
cd cyberspace-relay
git pull --ff-only
git submodule update --init --recursive
GRAIN_OWNER_PUBKEY="$GRAIN_OWNER_PUBKEY" docker compose -f deploy/onosendai/docker-compose.yml up -d --build
docker compose -f deploy/onosendai/docker-compose.yml ps
