import importlib.util
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sentinel_v2', ROOT / 'sentinel_ym.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
from sentinel_ext import (EnsembleOnlineDetector, classify_barriers,
                          record_finding, record_incident, review_finding, json_export)


class ExtendedTests(unittest.TestCase):
    def test_exact_block_evidence(self):
        events = [
            {'message':'[UFW BLOCK] IN=wlan0 SRC=198.51.100.7 DPT=22 PROTO=TCP'},
            {'message':'[UFW BLOCK] IN=wlan0 SRC=198.51.100.7 DPT=22 PROTO=TCP'},
            {'message':'apparmor="DENIED" operation="file_open" profile="snap.browser"'},
            {'message':'sshd: Failed password for demo from 198.51.100.7 port 12 ssh2'},
            {'message':'NOTICE firewall accepted connection'}]
        results = classify_barriers(events)
        self.assertEqual(len(results), 2)
        self.assertEqual({e['source'] for e in results}, {'UFW','AppArmor'})
        self.assertEqual([e['count'] for e in results if e['source']=='UFW'],[2])

    def test_fail2ban_ban_only(self):
        events = [
            {'unit':'fail2ban.service','message':'[sshd] Ban 198.51.100.77'},
            {'unit':'sshd.service','message':'Ban 198.51.100.78'},
        ]
        results = classify_barriers(events)
        self.assertEqual(len(results),1)
        self.assertEqual(results[0]['source'],'fail2ban')

    def test_approval_and_rejection_are_separate(self):
        with tempfile.TemporaryDirectory() as tmp:
            store=m.Store(tmp)
            record_finding(store,'unattended_missing','medium','Seguridad', 'No instalado','Revisar')
            called=[]
            self.assertTrue(review_finding(store,1,'rechazar', lambda *args: called.append(args), require_prompt=False))
            self.assertEqual(called,[])
            self.assertEqual(store.db.execute('SELECT status FROM findings').fetchone()[0], 'rechazado')
            self.assertTrue(review_finding(store,1,'aprobar', lambda *args: called.append(args), require_prompt=False))
            self.assertEqual(called, [('enable-updates',True)])
            self.assertEqual(store.db.execute('SELECT status FROM findings').fetchone()[0], 'aplicado_no_verificado')
            self.assertEqual(len(json_export(store,'audit')),4) # hallazgo, rechazo, autorización y ejecución
            store.close()

    def test_manual_never_automated(self):
        with tempfile.TemporaryDirectory() as tmp:
            store=m.Store(tmp)
            record_finding(store,'ssh_password_enabled','medium','SSH acepta contraseñas','sshd -T','Revisar')
            with self.assertRaises(ValueError):
                review_finding(store,1,'aprobar',lambda *_: self.fail('Called'), require_prompt=False)
            self.assertEqual(store.db.execute('SELECT status FROM findings').fetchone()[0],'revision_manual')
            store.close()

    def test_training_excludes_hostile_samples(self):
        m2=EnsembleOnlineDetector()
        clean={'load_per_core': .2, 'process_count':100,'listen_count':5,'ssh_failures':0,'suspect_processes':0}
        for i in range(45):
            self.assertFalse(m2.observe(clean,safe=True))
        hostile={**clean,'process_count':155,'ssh_failures':9}
        self.assertIn('process_count',m2.observe(hostile,safe=False))
        self.assertEqual(m2.state['accepted'],45)
        self.assertEqual(len(m2.state['history']),45)
        self.assertEqual(m2.state['rejected'],1)

    def test_persist_incidents(self):
        with tempfile.TemporaryDirectory() as tmp:
            store=m.Store(tmp)
            values=dict(outcome='bloqueado',severity='medium',category='firewall',source='UFW',
                        title='Bloqueo',evidence='Test',fingerprint='ufw:demo',count=2)
            record_incident(store,**values)
            record_incident(store,**values)
            store.close()
            store=m.Store(tmp)
            self.assertEqual(store.db.execute('SELECT occurrences FROM incidents').fetchone()[0],4)
            store.close()

    def test_misconfig_not_counted_as_attack(self):
        with tempfile.TemporaryDirectory() as tmp:
            store=m.Store(tmp)
            agent=m.Agent(store,m.config_read('/missing-config'))
            agent.emit('medium','actualizaciones','Actualizaciones necesarias','Paquetes','Revisar','unattended_missing')
            self.assertEqual(store.db.execute('SELECT COUNT(*) FROM incidents').fetchone()[0],0)
            self.assertEqual(store.db.execute('SELECT COUNT(*) FROM findings').fetchone()[0],1)
            store.close()

if __name__=='__main__':
    unittest.main()
