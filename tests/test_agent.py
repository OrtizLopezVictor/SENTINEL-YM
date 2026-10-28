import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('sentinel', Path(__file__).resolve().parents[1] / 'sentinel_ym.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class DetectionTests(unittest.TestCase):
    def test_ports(self):
        sample = 'tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n' \
                 'tcp LISTEN 0 4096 [::]:443 [::]:*\n' \
                 'udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\n'
        self.assertEqual(m.parse_ss_listeners(sample), {'tcp/22', 'tcp/443', 'udp/53'})

    def test_suspicious_exec(self):
        self.assertTrue(m.is_suspicious_exec('/dev/shm/x'))
        self.assertTrue(m.is_suspicious_exec('/usr/bin/ssh (deleted)'))
        self.assertFalse(m.is_suspicious_exec('/usr/bin/python3'))

    def test_bruteforce(self):
        events = [{'message': f'Failed password for invalid user test from 198.51.100.7 port {1200+i} ssh2'} for i in range(6)]
        alerts = m.parse_auth_events(events, 5)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0][1], 'autenticacion')

    def test_model(self):
        model = m.AdaptiveAnomalyModel(None)
        normal = {k: 1.0 for k in model.KEYS}
        for _ in range(12):
            self.assertFalse(model.observe(normal))
        changed = {**normal, 'process_count': 20.0}
        self.assertIn('process_count', model.observe(changed))
        self.assertEqual(model.state['n'], 12)

    def test_store_cooldown(self):
        with tempfile.TemporaryDirectory() as state:
            s = m.Store(state)
            try:
                args = ('high','x','test','details','recommendation','fingerprint',3600)
                first = s.alert(*args)
                self.assertIsInstance(first, int)
                self.assertIsNone(s.alert(*args))
                self.assertEqual(s.db.execute('SELECT occurrences FROM alerts').fetchone()[0], 2)
            finally:
                s.close()

    def test_shadow_perms(self):
        self.assertFalse(m.shadow_permissions_risky(0, 'shadow', 0o640))
        self.assertFalse(m.shadow_permissions_risky(0, 'root', 0o600))
        self.assertTrue(m.shadow_permissions_risky(0, 'shadow', 0o644))
        self.assertTrue(m.shadow_permissions_risky(0, 'staff', 0o640))
        self.assertTrue(m.shadow_permissions_risky(1000, 'shadow', 0o600))

    def test_patch_preview_only(self):
        # Action preview must be callable without root and without system modification.
        self.assertIsNone(m.patch_updates('enable-updates', False))

if __name__ == '__main__':
    unittest.main()
