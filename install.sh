#!/usr/bin/env bash
set -Eeuo pipefail
# Installer is intentionally explicit about automatic patching.
if [[ ${EUID} -ne 0 ]]; then
  echo 'ERROR: ejecuta con sudo: sudo ./install.sh' >&2
  exit 1
fi
if [[ "$(uname -s)" != "Linux" ]] || ! command -v systemctl >/dev/null; then
  echo 'ERROR: esta versión requiere Linux con systemd.' >&2
  exit 1
fi
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
python3 -m py_compile "$ROOT/sentinel_ym.py" "$ROOT/sentinel_ext.py" "$ROOT/sentinel_console.py" "$ROOT/sentinel_correlation.py"
install -d -m 0755 -o root -g root /opt/sentinel-ym /etc/sentinel-ym
install -d -m 0700 -o root -g root /var/lib/sentinel-ym
install -m 0644 -o root -g root "$ROOT/sentinel_ym.py" /opt/sentinel-ym/sentinel_ym.py
install -m 0644 -o root -g root "$ROOT/sentinel_ext.py" /opt/sentinel-ym/sentinel_ext.py
install -m 0644 -o root -g root "$ROOT/sentinel_console.py" /opt/sentinel-ym/sentinel_console.py
install -m 0644 -o root -g root "$ROOT/sentinel_correlation.py" /opt/sentinel-ym/sentinel_correlation.py
if [[ ! -e /etc/sentinel-ym/config.json ]]; then
  install -m 0600 -o root -g root "$ROOT/config.example.json" /etc/sentinel-ym/config.json
else
  echo 'Se conserva /etc/sentinel-ym/config.json'
fi
cat >/usr/local/bin/sentinel-ym <<'EOF'
#!/bin/sh
exec /usr/bin/python3 /opt/sentinel-ym/sentinel_ym.py "$@"
EOF
chmod 0755 /usr/local/bin/sentinel-ym
cat >/etc/systemd/system/sentinel-ym.service <<'EOF'
[Unit]
Description=SENTINEL-YM Linux defensive monitoring agent
After=multi-user.target systemd-journald.service
Wants=systemd-journald.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/sentinel-ym/sentinel_ym.py --state-dir /var/lib/sentinel-ym --config /etc/sentinel-ym/config.json daemon
WorkingDirectory=/opt/sentinel-ym
Restart=on-failure
RestartSec=10
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/sentinel-ym
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 /etc/systemd/system/sentinel-ym.service
systemctl daemon-reload
systemctl enable --now sentinel-ym.service
systemctl restart sentinel-ym.service

echo 'SENTINEL-YM instalado. Estado: sudo sentinel-ym status'
echo 'Logs servicio: sudo journalctl -u sentinel-ym -f'
if [[ ${1:-} == "--enable-security-updates" ]]; then
  /usr/local/bin/sentinel-ym patch enable-updates --apply
else
  echo 'Parches APT opcionales: sudo sentinel-ym patch enable-updates --apply'
fi
