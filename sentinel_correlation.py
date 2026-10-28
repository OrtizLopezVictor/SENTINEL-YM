"""Bounded, persistent SSH correlation. Observations are not proof of intrusion."""
import ipaddress
import re
import time


def correlate_auth(store, events, threshold=5, clock=None, window=300):
    now = time.time() if clock is None else clock
    state = store.get('auth_window_v3', {})
    history = [x for x in state.get('history', []) if now-window <= x['t'] <= now]
    notified = {k: v for k, v in state.get('notified', {}).items() if v > now-window}
    alerts = []
    for event in events:
        unit = event.get('unit', '')
        if unit not in ('ssh.service', 'sshd.service'):
            continue
        message = event.get('message', '')
        match = re.search(r'\bfrom\s+(\S+)', message)
        if not match:
            continue
        try:
            ip = str(ipaddress.ip_address(match.group(1)))
            stamp = float(event.get('timestamp', now))
        except (ValueError, TypeError):
            continue
        if not now-window <= stamp <= now+5:
            continue
        if re.search(r'Failed password|Invalid user|maximum authentication attempts', message, re.I):
            history.append({'ip': ip, 't': stamp})
            count = sum(x['ip'] == ip and stamp-window <= x['t'] <= stamp for x in history)
            key = 'burst:' + ip
            if count >= threshold and key not in notified:
                alerts.append(('high', 'autenticacion', 'Fallos SSH correlacionados entre escaneos',
                               f'{count} registros de fallo desde {ip} en hasta {window} s; no equivale a intentos únicos.',
                               'Verifica usuarios y origen; revisa los controles de acceso.', key))
                notified[key] = now
        elif re.search(r'Accepted\s+(?:password|publickey|keyboard-interactive)', message):
            count = sum(x['ip'] == ip and stamp-window <= x['t'] <= stamp for x in history)
            key = 'success_after_fail:' + ip
            if count >= threshold and key not in notified:
                alerts.append(('high', 'autenticacion', 'Acceso SSH después de múltiples fallos',
                               f'{ip}: acceso aceptado después de {count} registros de fallo. {message[:220]}',
                               'Confirma si el acceso fue autorizado; puede ser un usuario legítimo.', key))
                notified[key] = now
    store.put('auth_window_v3', {'history': history[-10000:], 'notified': dict(list(notified.items())[-2000:])})
    return alerts
