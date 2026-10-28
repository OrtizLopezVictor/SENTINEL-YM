"""Local read-only console; no remote assets, command endpoints or credentials."""
import datetime as dt
import html
import json
import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlparse
from sentinel_ext import json_export


def health(store):
    last = store.get('last_scan')
    age = None
    try:
        stamp = dt.datetime.fromisoformat(last)
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=dt.timezone.utc)
        age = max(0, (dt.datetime.now(dt.timezone.utc)-stamp).total_seconds())
    except (TypeError, ValueError):
        pass
    journal = store.get('journal_health', {'ok': False, 'detail': 'Sin evaluación de logs'})
    return {'last_scan': last, 'age_seconds': age,
            'status': 'sin_datos' if age is None else 'sin_actualizar' if age > 180 else 'reciente',
            'journal': journal}


def select_rows(store, tab, params):
    data = json_export(store, tab)
    needle = params.get('q', [''])[0][:160].casefold()
    severity = params.get('severity', [''])[0]
    outcome = params.get('outcome', [''])[0]
    return [row for row in data if (not needle or needle in json.dumps(row, ensure_ascii=False).casefold())
            and (not severity or row.get('severity') == severity)
            and (not outcome or row.get('outcome') == outcome)]


def render(store, params):
    esc = lambda value: html.escape(str(value), quote=True)
    tabs = {'incidents': 'Incidentes', 'findings': 'Hallazgos', 'audit': 'Auditoría', 'model': 'Aprendizaje'}
    tab = params.get('tab', ['incidents'])[0]
    if tab not in tabs:
        tab = 'incidents'
    state = health(store)
    counts = dict(store.db.execute('SELECT outcome,SUM(occurrences) FROM incidents GROUP BY outcome'))
    pending = store.db.execute("SELECT COUNT(*) FROM findings WHERE status IN ('pendiente','fallido','revision_manual')").fetchone()[0]
    model = store.get('hybrid_ml', {})
    accepted = model.get('accepted', 0)
    nav = ''.join(f'<a class="{"active" if tab == k else ""}" href="/?tab={k}">{v}</a>' for k,v in tabs.items())
    fields = {'incidents': ['last_seen','outcome','severity','title','evidence','occurrences'],
              'findings': ['id','status','severity','title','evidence','advice','action'],
              'audit': ['timestamp','kind','subject','result','detail']}
    labels = dict(last_seen='Última vez · UTC', outcome='Resultado', severity='Severidad', title='Descripción',
                  evidence='Evidencia', occurrences='Registros', id='ID', status='Estado', advice='Siguiente paso',
                  action='Acción', timestamp='Hora · UTC', kind='Tipo', subject='Elemento', result='Resultado', detail='Detalle')
    filters = ''
    if tab == 'model':
        rows = [('Muestras aceptadas', accepted), ('Muestras excluidas', model.get('rejected',0)),
                ('Ventana conservada', len(model.get('history',[]))),
                ('Estado del modelo', 'Calentamiento: requiere 16 muestras' if len(model.get('history',[])) < 16 else 'Modelo estadístico disponible'),
                ('Últimas señales', json.dumps(store.get('last_ml_analysis',{}),ensure_ascii=False)),
                ('Últimas métricas', json.dumps(store.get('last_features',{}),ensure_ascii=False))]
        content = '<dl>' + ''.join(f'<dt>{esc(k)}</dt><dd>{esc(v)}</dd>' for k,v in rows) + '</dl>'
        content += '<p class="muted">Ensamble estadístico local; Isolation Forest es opcional. Una anomalía requiere investigación. El aprendizaje automático no garantiza que una muestra esté libre de amenazas.</p>'
    else:
        data = select_rows(store, tab, params)
        cols = fields[tab]
        content = '<div class="scroll"><table><thead><tr>'+''.join(f'<th>{labels[k]}</th>' for k in cols)+'</tr></thead><tbody>'
        for row in data[:200]:
            content += '<tr>'+''.join('<td>'+ (f'<span class="badge {esc(row[k])}">{esc(row[k])}</span>' if k in ('outcome','severity','status') else esc(row[k])) +'</td>' for k in cols)+'</tr>'
        content += '</tbody></table></div>' if data else '</tbody></table><div class="empty">Sin registros para estos filtros.<small>La ausencia de eventos no demuestra ausencia de amenazas.</small></div></div>'
        content += f'<p class="muted">{min(200,len(data))} de {len(data)} coincidencias · búsqueda sobre los últimos 5,000 registros.</p>'
        def options(key, values):
            return ''.join(f'<option value="{esc(v)}" {"selected" if params.get(key,[""])[0] == v else ""}>{esc(label)}</option>' for v,label in values)
        filters = f'''<form method="get"><input type="hidden" name="tab" value="{tab}"><input aria-label="Buscar" name="q" placeholder="Buscar IP, evidencia o descripción…" value="{esc(params.get('q',[''])[0])}">
<select aria-label="Severidad" name="severity">{options('severity',[('','Toda severidad'),('critical','Crítica'),('high','Alta'),('medium','Media'),('info','Informativa')])}</select>
<select aria-label="Resultado" name="outcome">{options('outcome',[('','Todo resultado'),('detectado','Detectado'),('bloqueado','Bloqueado'),('incierto','Incierto')])}</select><button>Filtrar</button><a class="download" href="/export?{esc(urlencode({'kind':tab}))}">Exportar JSON</a></form>'''
    return f'''<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="refresh" content="30"><title>SENTINEL-YM · Centro de defensa</title>
<style>
:root{{color-scheme:dark;font-family:system-ui,sans-serif;background:#080e19;color:#e1e9f5}}*{{box-sizing:border-box}}body{{margin:0}}a{{color:inherit;text-decoration:none}}.shell{{display:grid;grid-template-columns:220px 1fr;min-height:100vh}}aside{{padding:34px 20px;background:#0d1523;border-right:1px solid #243249}}.logo{{font-size:19px;font-weight:850;letter-spacing:1px}}.logo b{{color:#55e0c2}}.sub{{font-size:11px;color:#8395b0;letter-spacing:2px;margin:9px 0 40px}}nav a{{display:block;padding:14px;margin:7px 0;border-radius:9px;color:#a4b4cd}}nav a.active{{background:#183b3f;color:#6af0ce;border-left:3px solid #6af0ce}}.local{{margin-top:48px;font-size:12px;line-height:1.9;color:#8498b5}}main{{padding:38px;min-width:0}}header{{display:flex;justify-content:space-between;gap:20px;align-items:center}}.eyebrow{{color:#62ddc3;font-size:11px;letter-spacing:2px}}h1{{font-size:32px;margin:10px 0}}h2{{font-size:19px}}.muted,small{{color:#96a7c0;font-size:12px;line-height:1.7}}.status{{padding:10px 16px;border:1px solid #465473;border-radius:22px;font-size:12px;color:#c6d6ec}}.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin:28px 0}}.card{{background:linear-gradient(145deg,#142237,#0e192b);padding:22px;border:1px solid #253750;border-radius:14px}}.number{{font-size:36px;font-weight:750;margin:10px 0}}.card:nth-child(2) .number{{color:#5fe2ba}}.card:nth-child(3) .number{{color:#f4bf6d}}.panel{{padding:22px;border:1px solid #253750;border-radius:14px;background:#0e1828}}.scroll{{overflow:auto}}table{{width:100%;border-collapse:collapse;font-size:12px}}th{{font-size:10px;color:#8da4c3;text-transform:uppercase;letter-spacing:1px;text-align:left}}td,th{{padding:16px 12px;border-bottom:1px solid #223047;vertical-align:top}}td{{max-width:380px;overflow-wrap:anywhere;line-height:1.6}}.badge{{display:inline-block;border:1px solid #39506c;border-radius:6px;padding:3px 7px;white-space:nowrap}}.high,.critical{{color:#ffb1b4;background:#4a202e}}.bloqueado{{color:#6be5c1;background:#123b34}}.medium,.pendiente{{color:#ffd28c;background:#3a3021}}form{{display:flex;gap:9px;flex-wrap:wrap;margin:20px 0}}input,select,button,.download{{font:inherit;font-size:12px;border:1px solid #354b68;border-radius:8px;padding:11px;background:#121f33;color:#d9e8fb}}input{{flex:1;min-width:190px}}button{{background:#68e1c4;color:#082a24;font-weight:bold;cursor:pointer}}.notice{{margin:20px 0;padding:16px;border-left:3px solid #71a0db;background:#112239;font-size:12px;line-height:1.8;color:#b9cde6}}code{{color:#72e7cf}}.empty{{text-align:center;padding:48px;color:#c4d4e8}}.empty small{{display:block;margin-top:10px}}dt{{color:#8da4c3;margin-top:18px;font-size:12px}}dd{{margin:8px 0;overflow-wrap:anywhere}}footer{{margin-top:20px}}@media(max-width:1000px){{.shell{{grid-template-columns:1fr}}aside{{padding:20px}}nav{{display:flex;flex-wrap:wrap}}.sub,.local{{display:none}}main{{padding:20px}}.stats{{grid-template-columns:repeat(2,1fr)}}}}@media(max-width:500px){{header{{display:block}}.stats{{grid-template-columns:1fr}}}}
</style></head><body><div class="shell"><aside><div class="logo"><b>◈</b> SENTINEL-YM</div><div class="sub">SECURITY CONSOLE / 0.3</div><nav>{nav}</nav><div class="local">● Entorno local<br>127.0.0.1 · Solo lectura<br>Reparaciones supervisadas</div></aside><main><header><div><div class="eyebrow">CENTRO DE CIBERDEFENSA</div><h1>Visibilidad para decidir.</h1><small>Señales, evidencias y cambios bajo tu control.</small></div><div class="status">Escaneo: {esc(state['status'])}</div></header>
<div class="stats"><div class="card"><small>Señales detectadas · registros</small><div class="number">{counts.get('detectado',0)}</div><small>Requieren investigación</small></div><div class="card"><small>Bloqueos registrados</small><div class="number">{counts.get('bloqueado',0)}</div><small>Reportados por controles externos</small></div><div class="card"><small>Hallazgos por revisar</small><div class="number">{pending}</div><small>Acciones sujetas a aprobación</small></div><div class="card"><small>Muestras de aprendizaje</small><div class="number">{accepted}</div><small>{model.get('rejected',0)} excluidas</small></div></div>
<div class="notice">Último escaneo (UTC): {esc(state['last_scan'] or 'Todavía no ejecutado')} · Logs: {esc(state['journal']['detail'])}<br>“Reciente” significa menos de 180 s desde el último escaneo; no certifica que el equipo esté protegido.</div>
<section class="panel"><h2>{tabs[tab]}</h2>{filters}{content}</section><div class="notice"><b>Tú autorizas las reparaciones.</b> Revisa <code>sudo sentinel-ym findings</code> y usa <code>sudo sentinel-ym review ID aprobar</code> o <code>rechazar</code>. La consola no aplica cambios al equipo.<br>Un bloqueo en logs no demuestra que una intrusión completa haya sido detenida. Los hallazgos son verificaciones de configuración; no un catálogo exhaustivo de CVE.</div><footer class="muted">SENTINEL-YM v0.3 · actualización cada 30 s · datos locales · sin recursos externos</footer></main></div></body></html>'''


def dashboard(store, port=8765):
    port = int(port)
    if not 1024 <= port <= 65535:
        raise ValueError('Puerto fuera de rango')
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.headers.get('Host') not in (f'127.0.0.1:{port}',f'localhost:{port}'):
                self.send_error(403); return
            path = urlparse(self.path)
            params = parse_qs(path.query)
            try:
                mime = 'application/json'
                if path.path == '/health':
                    body = json.dumps(health(store))
                elif path.path == '/export':
                    body = json.dumps(json_export(store, params.get('kind',['incidents'])[0]), ensure_ascii=False, indent=2)
                elif path.path == '/':
                    mime = 'text/html'
                    body = render(store, params)
                else:
                    self.send_error(404); return
                data = body.encode()
                self.send_response(200)
                self.send_header('Content-Type', mime+'; charset=utf-8')
                self.send_header('Content-Length', str(len(data)))
                self.send_header('Cache-Control', 'no-store')
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.send_header('X-Frame-Options','DENY')
                self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
                if path.path == '/export':
                    self.send_header('Content-Disposition', 'attachment; filename="sentinel-export.json"')
                self.end_headers(); self.wfile.write(data)
            except ValueError:
                self.send_error(400)
            except (sqlite3.Error, OSError):
                self.send_error(500)
        def do_POST(self):
            self.send_error(405)
        def log_message(self, *args):
            pass
    with HTTPServer(('127.0.0.1', port), Handler) as server:
        server.timeout = 10
        print(f'Consola local: http://127.0.0.1:{port}', flush=True)
        server.serve_forever()
