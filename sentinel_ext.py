#!/usr/bin/env python3
"""SENTINEL-YM v0.2: local audit, approval workflow, read-only console and ML ensemble.

Never executes a command found in telemetry, advice or a model output.
"""
from __future__ import annotations

import collections
import csv
import datetime as dt
import html
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import ipaddress
import json
import math
from pathlib import Path
import re
import statistics
import sys
from urllib.parse import parse_qs, urlparse

# Finite action catalog. 'manual' means the application MUST NOT alter the host.
FINDING_POLICY = {
    'ssh_empty_passwords': ('manual', 'Revisar y corregir la configuración efectiva SSH; verificar primero otra sesión activa.'),
    'ssh_root_allowed': ('manual', 'Deshabilitar el ingreso remoto de root solo tras verificar otra cuenta administradora.'),
    'ssh_password_enabled': ('manual', 'Evaluar claves SSH y MFA. No desactivar contraseñas sin acceso alternativo.'),
    'shadow_permissions': ('manual', 'Auditar /etc/shadow y restaurar propietario/permisos según política de distribución.'),
    'unattended_missing': ('enable-updates', 'Instalar unattended-upgrades y activar su timer (puede cambiar paquetes).'),
    'unattended_timer': ('enable-updates', 'Habilitar revisiones automáticas de seguridad mediante APT.'),
    'apt_updates_pending': ('apply-security-updates', 'Ejecutar unattended-upgrade según repositorios y reglas APT configuradas.'),
}
SEV = {'info': 0, 'medium': 1, 'high': 2, 'critical': 3}


def utcnow():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')


def initialize(store):
    store.db.executescript('''
    CREATE TABLE IF NOT EXISTS incidents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
      outcome TEXT NOT NULL CHECK(outcome IN ('detectado','bloqueado','incierto')),
      severity TEXT NOT NULL, category TEXT NOT NULL, source TEXT NOT NULL,
      title TEXT NOT NULL, evidence TEXT NOT NULL, fingerprint TEXT NOT NULL UNIQUE,
      occurrences INTEGER NOT NULL DEFAULT 1
    );
    CREATE INDEX IF NOT EXISTS idx_incidents_last ON incidents(last_seen);
    CREATE TABLE IF NOT EXISTS findings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, fingerprint TEXT NOT NULL UNIQUE,
      severity TEXT NOT NULL, title TEXT NOT NULL, evidence TEXT NOT NULL,
      advice TEXT NOT NULL, action TEXT NOT NULL, status TEXT NOT NULL,
      reviewed_at TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
    CREATE TABLE IF NOT EXISTS audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
      kind TEXT NOT NULL, subject TEXT NOT NULL, result TEXT NOT NULL, detail TEXT NOT NULL
    );
    ''')
    store.db.commit()


def audit(store, kind, subject, result, detail):
    store.db.execute('INSERT INTO audit(timestamp,kind,subject,result,detail) VALUES (?,?,?,?,?)',
                     (utcnow(), kind[:60], subject[:180], result[:32], detail[:1000]))
    store.db.commit()


def record_incident(store, *, outcome, severity, category, source, title, evidence, fingerprint, count=1):
    if outcome not in ('detectado', 'bloqueado', 'incierto'):
        raise ValueError('Estado de incidente no soportado')
    instant = utcnow()
    store.db.execute('''INSERT INTO incidents(first_seen,last_seen,outcome,severity,category,source,title,evidence,fingerprint,occurrences)
        VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(fingerprint) DO UPDATE SET
        last_seen=excluded.last_seen, evidence=excluded.evidence, occurrences=incidents.occurrences+excluded.occurrences''',
        (instant, instant, outcome, severity, category, source, title[:180], evidence[:700], fingerprint[:256], max(1, int(count))))
    store.db.commit()


def record_finding(store, fingerprint, severity, title, evidence, advice):
    if fingerprint not in FINDING_POLICY:
        return
    action, _ = FINDING_POLICY[fingerprint]
    instant = utcnow()
    status = 'pendiente' if action != 'manual' else 'revision_manual'
    row = store.db.execute('SELECT id,status FROM findings WHERE fingerprint=?', (fingerprint,)).fetchone()
    if row:
        # Preserve human rejection/approval; never automatically authorize a rejected fix.
        store.db.execute('''UPDATE findings SET last_seen=?, severity=?, title=?, evidence=?, advice=? WHERE id=?''',
                         (instant, severity, title[:180], evidence[:700], advice[:700], row[0]))
    else:
        store.db.execute('''INSERT INTO findings(first_seen,last_seen,fingerprint,severity,title,evidence,advice,action,status)
                            VALUES(?,?,?,?,?,?,?,?,?)''',
                         (instant, instant, fingerprint, severity, title[:180], evidence[:700], advice[:700], action, status))
        audit(store, 'hallazgo', title, status, 'Nueva configuración o actualización que necesita revisión')
    store.db.commit()


def classify_barriers(events):
    """Only a BLOCK / DENIED / Ban actually logged by a control counts as blocked.

    We cannot claim a full attack was stopped, merely that a control logged a block.
    """
    grouped = {}
    for item in events:
        msg = str(item.get('message', ''))[:500]
        unit = str(item.get('unit', ''))[:128]
        block = re.search(r'\[UFW BLOCK\]', msg, re.I)
        deny = re.search(r'apparmor=(?:"DENIED"|DENIED)', msg, re.I)
        ban = re.search(r'\bBan\s+([0-9a-f:.]+)\b', msg, re.I) if 'fail2ban' in (unit + msg[:100]).lower() else None
        if block:
            source, title, category, severity = 'UFW', 'Tráfico bloqueado por firewall', 'firewall', 'medium'
            m = re.search(r'\bSRC=([^\s]+)', msg)
            dest = re.search(r'\bDPT=(\d+)', msg)
            source_ip = m.group(1) if m else 'desconocido'
            port = dest.group(1) if dest else 'desconocido'
            fingerprint = f'ufw:{source_ip}:{port}'
            evidence = f'IP origen={source_ip}; puerto destino={port}. Registro UFW BLOCK.'
        elif deny:
            source, title, category, severity = 'AppArmor', 'Operación denegada por AppArmor', 'control_acceso', 'medium'
            operation = re.search(r'operation="([^"]{1,100})"', msg)
            profile = re.search(r'profile="([^"]{1,100})"', msg)
            name = operation.group(1) if operation else 'desconocida'
            prof = profile.group(1) if profile else 'desconocido'
            fingerprint = f'apparmor:{prof}:{name}'
            evidence = f'Perfil={prof}; operación={name}. Registro DENIED.'
        elif ban:
            source, title, category, severity = 'fail2ban', 'Dirección IP bloqueada por fail2ban', 'autenticacion', 'high'
            try:
                ip = str(ipaddress.ip_address(ban.group(1)))
            except ValueError:
                continue
            fingerprint = 'fail2ban:' + ip
            evidence = f'IP={ip}; registro Ban de fail2ban. Verifica reglas aplicadas.'
        else:
            continue
        if fingerprint in grouped:
            grouped[fingerprint]['count'] += 1
        else:
            grouped[fingerprint] = dict(outcome='bloqueado', severity=severity, category=category,
                                         source=source, title=title, evidence=evidence,
                                         fingerprint=fingerprint, count=1)
    return list(grouped.values())


class EnsembleOnlineDetector:
    """Online robust ensemble: median/MAD, mean/variance, EWMA, optional IsolationForest.

    Learns only samples marked 'safe'; a suspicious scan cannot poison baseline.
    The decision is an anomaly score, NOT proof of malicious activity.
    """
    KEYS = ('load_per_core', 'process_count', 'listen_count', 'ssh_failures', 'suspect_processes')
    FLOOR = {'load_per_core': .25, 'process_count': 4., 'listen_count': 2., 'ssh_failures': 2., 'suspect_processes': 1.}

    def __init__(self, state=None):
        self.state = state if isinstance(state, dict) else {}
        if not isinstance(self.state.get('history'), list):
            self.state['history'] = []
        self.state.setdefault('accepted', len(self.state['history']))
        self.state.setdefault('ewma', {})
        self.state.setdefault('rejected', 0)

    def observe(self, features, safe=True):
        current = {key: float(features.get(key, 0.0)) for key in self.KEYS}
        history = self.state['history'][-192:]
        vectors = [x for x in history if isinstance(x, dict) and all(k in x for k in self.KEYS)]
        explanations, votes = {}, set()
        if len(vectors) >= 16:
            for key in self.KEYS:
                vals = [float(x[key]) for x in vectors]
                m = statistics.median(vals)
                mad = statistics.median([abs(v-m) for v in vals])
                sigma_robust = max(self.FLOOR[key], mad * 1.4826)
                mean = statistics.fmean(vals)
                sigma_std = max(self.FLOOR[key], statistics.pstdev(vals))
                r = (current[key]-m) / sigma_robust
                z = (current[key]-mean) / sigma_std
                previous_ewma = float(self.state['ewma'].get(key, mean))
                momentum = (current[key]-previous_ewma) / max(self.FLOOR[key], sigma_std)
                # Only elevated observations; sharp decreases are not treated as attacks.
                count = int(r >= 3.8) + int(z >= 3.8) + int(momentum >= 3.8)
                if count >= 2:
                    votes.add(key)
                    explanations[key] = {'robust_z': round(r, 2), 'z': round(z, 2),
                                         'ewma_deviation': round(momentum, 2), 'votes': count}
            # IsolationForest is optional. Refits only when a fresh set of clean data has arrived.
            if len(vectors) >= 40:
                try:
                    from sklearn.ensemble import IsolationForest
                    clean = [[float(item[k]) for k in self.KEYS] for item in vectors]
                    detector = IsolationForest(n_estimators=70, contamination=0.05,
                                               max_samples=min(128, len(clean)), random_state=42, n_jobs=1)
                    detector.fit(clean)
                    if int(detector.predict([[current[k] for k in self.KEYS]])[0]) == -1:
                        explanations['isolation_forest'] = {'model': 'outlier (evaluar junto con señales)'}
                        # Preserve lower false alarm rate: no automatic alert on IF alone.
                        if votes:
                            explanations['ensemble_confirmed'] = True
                except ImportError:
                    pass
                except (ValueError, TypeError):
                    pass
        anomaly = bool(votes)
        # Do not learn from known bad intervals or any sample flagged as an anomaly.
        if safe and not anomaly:
            history.append(current)
            self.state['history'] = history[-192:]
            self.state['accepted'] = int(self.state['accepted']) + 1
            for key in self.KEYS:
                previous = float(self.state['ewma'].get(key, current[key]))
                self.state['ewma'][key] = round(previous * .88 + current[key] * .12, 5)
        else:
            self.state['rejected'] = int(self.state['rejected']) + 1
        return explanations


def print_incidents(store, outcome='todos', limit=30):
    query = 'SELECT id,last_seen,outcome,severity,title,evidence,occurrences,source FROM incidents'
    args = []
    if outcome != 'todos':
        if outcome not in ('detectado', 'bloqueado', 'incierto'):
            raise ValueError('Filtro no válido')
        query += ' WHERE outcome=?'
        args.append(outcome)
    rows = store.db.execute(query+' ORDER BY last_seen DESC LIMIT ?', (*args, min(500,limit))).fetchall()
    for r in rows:
        print(f'#{r[0]} {r[1]} [{r[2]}] {r[3]} {r[4]} x{r[6]} ({r[7]})\n   {r[5]}')
    if not rows:
        print('No hay eventos de ese tipo. Cero registros no demuestra ausencia de ataque.')


def print_findings(store):
    rows = store.db.execute('SELECT id,status,severity,title,action,evidence FROM findings ORDER BY last_seen DESC').fetchall()
    for r in rows:
        print(f'#{r[0]} [{r[1]}] {r[2]} {r[3]} | acción: {r[4]}\n   Evidencia: {r[5]}')
    if not rows:
        print('Todavía no hay hallazgos de configuración o actualización registrados.')


def review_finding(store, finding_id, decision, patcher, *, require_prompt=True):
    row = store.db.execute('SELECT fingerprint,status,title,action,evidence,advice FROM findings WHERE id=?', (finding_id,)).fetchone()
    if not row:
        raise ValueError('No existe ese hallazgo')
    fingerprint, status, title, action, evidence, advice = row
    if decision not in ('aprobar', 'rechazar'):
        raise ValueError('Decisión no soportada')
    if status not in ('pendiente', 'rechazado', 'fallido'):
        raise ValueError(f'Este hallazgo está en estado {status}; requiere revisión manual o ya se procesó.')
    if action == 'manual' or FINDING_POLICY.get(fingerprint, (None,))[0] != action:
        raise ValueError('No existe una remediación automatizada permitida para el hallazgo')
    print(f'HALLAZGO #{finding_id}: {title}\nEvidencia: {evidence}\nRecomendación: {advice}')
    print('Plan autorizado por catálogo: ' + FINDING_POLICY[fingerprint][1])
    if require_prompt:
        phrase = 'APROBAR' if decision == 'aprobar' else 'RECHAZAR'
        confirm = input(f'Para {decision.upper()}, escribe exactamente {phrase}: ').strip()
        if confirm != phrase:
            print('Cancelado; sin cambios.')
            audit(store, 'revision', str(finding_id), 'cancelado', 'Confirmación no recibida')
            return False
    if decision == 'rechazar':
        changed = store.db.execute("UPDATE findings SET status='rechazado',reviewed_at=? WHERE id=? AND status=?", (utcnow(),finding_id,status)).rowcount
        store.db.commit()
        if changed != 1:
            raise ValueError('El hallazgo cambió durante la revisión.')
        audit(store,'revision',str(finding_id),'rechazado','El administrador rechazó la remediación')
        return True
    claimed = store.db.execute("UPDATE findings SET status='en_ejecucion',reviewed_at=? WHERE id=? AND status=?",
                               (utcnow(), finding_id, status)).rowcount
    store.db.commit()
    if claimed != 1:
        raise ValueError('El hallazgo cambió durante la revisión.')
    # Log before operation so even an interrupted process leaves an approval trail.
    audit(store,'revision',str(finding_id),'aprobado',f'Se autorizó la acción permitida {action}')
    try:
        patcher(action, True)
    except Exception as exc:
        store.db.execute("UPDATE findings SET status='fallido', reviewed_at=? WHERE id=?", (utcnow(),finding_id))
        store.db.commit()
        audit(store,'reparacion',str(finding_id),'fallido',f'{type(exc).__name__}: {str(exc)[:500]}')
        raise
    store.db.execute("UPDATE findings SET status='aplicado_no_verificado',reviewed_at=? WHERE id=?", (utcnow(),finding_id))
    store.db.commit()
    audit(store,'reparacion',str(finding_id),'ejecutado','Acción terminó sin error; falta verificar el hallazgo nuevamente')
    return True


def json_export(store, kind):
    allowed = {
        'incidents': ('incidents', ['id','first_seen','last_seen','outcome','severity','category','source','title','evidence','occurrences']),
        'findings': ('findings', ['id','first_seen','last_seen','severity','title','evidence','advice','action','status','reviewed_at']),
        'audit': ('audit', ['id','timestamp','kind','subject','result','detail']),
    }
    if kind not in allowed:
        raise ValueError('Colección no admitida')
    table, cols = allowed[kind]
    # Identifiers are from a fixed literal whitelist; values are never SQL syntax.
    rows = store.db.execute(f'SELECT {",".join(cols)} FROM {table} ORDER BY id DESC LIMIT 5000').fetchall()
    return [dict(zip(cols, row)) for row in rows]


def dashboard(store, port=8765):
    if not (1024 <= int(port) <= 65535):
        raise ValueError('Usa un puerto entre 1024 y 65535')
    port = int(port)
    tabs = {'incidents': 'Incidentes', 'findings': 'Vulnerabilidades', 'audit': 'Auditoría', 'model': 'Aprendizaje IA'}
    html_escape = lambda x: html.escape(str(x), quote=True)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.headers.get('Host','') not in (f'127.0.0.1:{port}', f'localhost:{port}'):
                self.send_error(403)
                return
            parsed = urlparse(self.path)
            if parsed.path not in ('/', '/health'):
                self.send_error(404)
                return
            if parsed.path == '/health':
                data=b'OK'
                self.send_response(200); self.send_header('Content-Type','text/plain; charset=utf-8')
                self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
                return
            tab = parse_qs(parsed.query).get('tab', ['incidents'])[0]
            if tab not in tabs:
                tab = 'incidents'
            try:
                counts = dict(store.db.execute('SELECT outcome,SUM(occurrences) FROM incidents GROUP BY outcome').fetchall())
                pending = store.db.execute("SELECT COUNT(*) FROM findings WHERE status IN ('pendiente','fallido')").fetchone()[0]
                manual = store.db.execute("SELECT COUNT(*) FROM findings WHERE status='revision_manual'").fetchone()[0]
                last_scan = store.get('last_scan', 'nunca')
                model_state = store.get('hybrid_ml',{})
                if tab == 'incidents':
                    data = json_export(store, 'incidents')[:160]
                    heads = ('Hora (UTC)','Estado','Severidad','Categoría','Origen','Incidente','Evidencia','Ocurrencias')
                    rows = [[x['last_seen'], x['outcome'],x['severity'],x['category'],x['source'],x['title'],x['evidence'],x['occurrences']] for x in data]
                elif tab == 'findings':
                    data = json_export(store,'findings')[:160]
                    heads = ('ID','Estado','Severidad','Hallazgo','Evidencia','Acción','Recomendación')
                    rows = [[x['id'],x['status'],x['severity'],x['title'],x['evidence'],x['action'],x['advice']] for x in data]
                elif tab == 'audit':
                    data = json_export(store,'audit')[:160]
                    heads = ('Hora (UTC)','Tipo','Elemento','Resultado','Detalle')
                    rows = [[x['timestamp'],x['kind'],x['subject'],x['result'],x['detail']] for x in data]
                else:
                    heads = ('Indicador','Valor')
                    rows = [
                        ['Muestras limpias aceptadas', model_state.get('accepted', 0)],
                        ['Muestras rechazadas o no confiables', model_state.get('rejected', 0)],
                        ['Ventana de aprendizaje', len(model_state.get('history',[]))],
                        ['Señales del último análisis', json.dumps(store.get('last_ml_analysis',{}), ensure_ascii=False)],
                        ['Escaneos completos', store.get('scanned',0)],
                    ]
                th=''.join('<th>'+html_escape(x)+'</th>' for x in heads)
                trs=''.join('<tr>'+''.join('<td>'+html_escape(v)+'</td>' for v in row)+'</tr>' for row in rows)
                links=''.join(f'<a class="{"active" if tab==key else ""}" href="/?tab={key}">{html_escape(name)}</a>' for key,name in tabs.items())
                body=f'''<!doctype html><html lang="es"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="20">
<title>SENTINEL-YM | Seguridad local</title><style>
:root{{color-scheme:dark}}body{{margin:0;background:#0b101b;color:#dce6f7;font-family:Inter,system-ui,Arial,sans-serif}}
main{{max-width:1380px;margin:auto;padding:28px}}header{{display:flex;justify-content:space-between;align-items:center;gap:15px;flex-wrap:wrap}}
small, .muted{{color:#8ea0b7}}h1{{font-size:29px;margin:0}}h2{{font-size:19px}}.brand{{color:#60d4d8}}.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:13px;margin:24px 0}}
.stat{{background:#121e2d;border:1px solid #2a374a;border-radius:14px;padding:19px}}.n{{font-size:32px;font-weight:800;margin-top:7px}}
nav{{display:flex;gap:9px;flex-wrap:wrap;margin:12px 0 19px}}a{{color:#a2c7ff;text-decoration:none}}nav a{{padding:10px 14px;border-radius:10px;background:#132137}}nav .active{{background:#235c84;color:white}}
.panel{{background:#111c2a;border:1px solid #263749;border-radius:14px;padding:17px;overflow:auto}}table{{width:100%;border-collapse:collapse;font-size:13px}}th,td{{padding:12px;text-align:left;border-bottom:1px solid #283646;max-width:360px;overflow-wrap:anywhere;vertical-align:top}}th{{color:#99a9c5;text-transform:uppercase;font-size:11px;letter-spacing:.04em}}.notice{{margin-top:17px;border-left:3px solid #68b9c3;padding:10px 15px;background:#132334;line-height:1.6}}code{{color:#8ae1df}}.red{{color:#ffaaaa}}.green{{color:#74e3b8}}
</style></head><body><main><header><div><h1><span class="brand">◈</span> SENTINEL-YM</h1><small>Centro de ciberdefensa local · v0.2 · solo lectura</small></div><small>Último escaneo: {html_escape(last_scan)} UTC</small></header>
<section class="stats"><div class="stat"><small>Señales detectadas (registros)</small><div class="n">{int(counts.get('detectado',0))}</div></div>
<div class="stat"><small>Bloqueos confirmados por logs</small><div class="n green">{int(counts.get('bloqueado',0))}</div></div>
<div class="stat"><small>Reparaciones que requieren aprobación</small><div class="n">{int(pending)}</div></div><div class="stat"><small>Hallazgos de revisión manual</small><div class="n red">{int(manual)}</div></div></section>
<nav>{links}</nav><div class="panel"><h2>{html_escape(tabs[tab])}</h2><table><thead><tr>{th}</tr></thead><tbody>{trs or '<tr><td colspan="8">Sin registros aún</td></tr>'}</tbody></table></div>
<div class="notice">Un <b>bloqueo confirmado</b> significa que UFW, AppArmor o fail2ban registró un bloqueo; no demuestra por sí solo que fuera un ciberataque ni que toda la intrusión haya sido detenida.<br>
Para aprobar o rechazar cambios, usa la terminal: <code>sudo sentinel-ym findings</code> y <code>sudo sentinel-ym review ID aprobar</code>. La consola web <b>nunca</b> ejecuta reparaciones ni recibe contraseñas.</div>
<p class="muted">Se actualiza cada 20 segundos. Accesible únicamente en este equipo (127.0.0.1). Eventos en SQLite privado; tiempos UTC.</p></main></body></html>'''
                response=body.encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
                self.send_header('X-Content-Type-Options','nosniff')
                self.send_header('X-Frame-Options','DENY')
                self.send_header('Cache-Control','no-store')
                self.send_header('Content-Length',str(len(response)))
                self.end_headers();self.wfile.write(response)
            except (OSError, ValueError, RuntimeError) as exc:
                print('Error al renderizar la consola:',type(exc).__name__,file=sys.stderr)
                self.send_error(500)

        def do_POST(self):
            self.send_error(405, 'Panel de solo lectura')

        def log_message(self, format, *args):
            pass

    with HTTPServer(('127.0.0.1',port), Handler) as server:
        print(f'Panel local: http://127.0.0.1:{port}  (Ctrl+C para cerrar)')
        server.serve_forever()
