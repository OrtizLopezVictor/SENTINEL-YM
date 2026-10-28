"""Synthetic dashboard data, confined to a temporary database."""
import tempfile
from sentinel_ym import Store, now
from sentinel_ext import record_incident, record_finding
from sentinel_console import dashboard

if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='sentinel-demo-') as directory:
        store = Store(directory)
        try:
            store.put('last_scan',now())
            store.put('journal_health',{'ok':False,'detail':'DEMO · datos sintéticos; no se está vigilando el equipo'})
            for i,(outcome,title,sev) in enumerate([
                ('detectado','DEMO · Fallos SSH correlacionados entre escaneos','high'),
                ('bloqueado','DEMO · Registro de bloqueo UFW','medium'),
                ('detectado','DEMO · Archivo de persistencia modificado','high')]):
                record_incident(store,outcome=outcome,severity=sev,category='demo',source='simulación',
                                title=title,evidence='DEMO · 198.51.100.8 · evidencia ficticia',fingerprint=str(i),count=3)
            record_finding(store,'unattended_missing','medium','DEMO · Revisar actualizaciones',
                           'Dato sintético; no se comprobó APT','Revisar el plan antes de aprobar')
            print('DEMO: no monitorea ni modifica el sistema. Ctrl+C para cerrar.')
            dashboard(store)
        except KeyboardInterrupt:
            pass
        finally:
            store.close()
