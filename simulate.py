#!/usr/bin/env python3
"""Prueba defensiva controlada: señales sintéticas, cero intentos de intrusión."""
from pathlib import Path
from tempfile import TemporaryDirectory
from sentinel_ym import Store, parse_auth_events
from sentinel_ext import EnsembleOnlineDetector, classify_barriers, record_incident, record_finding

print('=== SENTINEL-YM v0.2: SIMULACIÓN SIN ATAQUES REALES ===')
events = [{'message':f'Failed password for invalid user demo from 198.51.100.77 port {5050+i} ssh2'} for i in range(7)]
events += [{'message':'[UFW BLOCK] IN=wlan0 SRC=198.51.100.77 DST=192.0.2.5 DPT=2222 PROTO=TCP'} for _ in range(3)]
with TemporaryDirectory(prefix='sentinel-demo-') as tmp:
    store = Store(tmp)
    for result in parse_auth_events(events, 5):
        sev, cat, title, details, advice, fingerprint = result
        record_incident(store, outcome='detectado', severity=sev, category=cat, source='simulador', title=title,
                        evidence=details, fingerprint=fingerprint)
    for blocked in classify_barriers(events):
        record_incident(store, **blocked)
    record_finding(store,'unattended_missing','medium','Actualizaciones automáticas no preparadas',
                   'Paquete no instalado (FICTICIO)','Instalar y habilitar unattended-upgrades')
    print('Eventos detectados: 1 ráfaga de accesos fallidos (no bloqueada por el programa)')
    print('Eventos UFW BLOCK registrados: 3 bloqueos de un control externo')
    print('Hallazgo: 1 propuesta de actualización que REQUIERE aprobación')
    print('Datos reales del sistema modificados: ninguno')
    print('Registros en base temporal:', store.db.execute('SELECT COUNT(*) FROM incidents').fetchone()[0])
    print('Propuestas pendientes:',store.db.execute('SELECT COUNT(*) FROM findings').fetchone()[0])
    store.close()

model = EnsembleOnlineDetector()
normal = {'load_per_core':.2,'process_count':100,'listen_count':5,'ssh_failures':0,'suspect_processes':0}
for _ in range(48):
    model.observe(normal, safe=True)
attack = {**normal,'load_per_core':5.,'process_count':155,'ssh_failures':8}
print('Ensamble IA, muestra atípica:',model.observe(attack,safe=False))
print('Muestras normales integradas:', model.state['accepted'])
print('Fin de la simulación; sin intrusiones ni reparaciones ejecutadas.')
