#!/bin/sh
# Install or update the web demo on an Ubuntu VM that already has Docker,
# gVisor (runsc), Caddy and uv. Run as a sudo-capable user from the repo root.
# The inference key is read from stdin only on first install; it is never echoed.
set -eu
HOST="${HOST:?set HOST, e.g. 45-77-141-253.sslip.io}"
SRC=/opt/airlock/src
UV="${UV:-$HOME/.local/bin/uv}"

sudo mkdir -p /opt/airlock
sudo rsync -a --delete --exclude .git --exclude .venv ./ "$SRC/"
sudo chown -R root:root /opt/airlock
sudo "$UV" venv --quiet --allow-existing --python /usr/bin/python3.12 /opt/airlock/venv
sudo VIRTUAL_ENV=/opt/airlock/venv "$UV" pip install --quiet "$SRC[web]"

if ! sudo test -f /etc/airlock/airlock.env; then
  sudo install -d -m 0700 -o root -g root /etc/airlock
  printf 'VULTR_INFERENCE_API_KEY=' | sudo tee /etc/airlock/airlock.env >/dev/null
  sudo sh -c 'umask 077; cat >> /etc/airlock/airlock.env'
  sudo chmod 600 /etc/airlock/airlock.env
fi

sudo install -m 0644 deploy/airlock-web.service deploy/airlock-prune.service deploy/airlock-prune.timer /etc/systemd/system/
sed "s/{HOST}/$HOST/g" deploy/Caddyfile | sudo tee /etc/caddy/Caddyfile >/dev/null
sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
sudo systemctl daemon-reload
sudo systemctl enable --now airlock-prune.timer
sudo systemctl enable airlock-web.service
sudo systemctl restart airlock-web.service
sudo systemctl reload caddy
