#!/usr/bin/env bash
set -Eeuo pipefail
if (( EUID != 0 )); then echo 'Ejecuta con sudo'; exit 1; fi
systemctl disable --now sentinel-ym.service 2>/dev/null || true
rm -f /etc/systemd/system/sentinel-ym.service /usr/local/bin/sentinel-ym
systemctl daemon-reload
rm -rf /opt/sentinel-ym
printf 'Agente desinstalado. Se CONSERVAN /var/lib/sentinel-ym y /etc/sentinel-ym.\n'
printf 'Configuración APT, si se activó, también se conserva por seguridad.\n'
