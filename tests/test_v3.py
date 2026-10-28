import tempfile
import unittest
from unittest.mock import patch
from sentinel_ym import Store
from sentinel_correlation import correlate_auth
from sentinel_console import render, health, select_rows
from sentinel_ext import record_incident, record_finding, review_finding

def event(text,t):
    return {'unit':'ssh.service','message':text+' from 198.51.100.8 port 4000 ssh2','timestamp':t}

class V3Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.store=Store(self.tmp.name)
    def tearDown(self):
        self.store.close(); self.tmp.cleanup()
    def test_cross_scan_restart(self):
        self.assertFalse(correlate_auth(self.store,[event('Failed password for demo',100)]*3,clock=100))
        self.store.close(); self.store=Store(self.tmp.name)
        self.assertEqual(len(correlate_auth(self.store,[event('Failed password for demo',110)]*2,clock=110)),1)
        self.assertFalse(correlate_auth(self.store,[event('Failed password for demo',111)],clock=111))
    def test_success_after_failures(self):
        correlate_auth(self.store,[event('Failed password for demo',100)]*5,clock=100)
        self.assertIn('Acceso SSH',correlate_auth(self.store,[event('Accepted publickey for demo',101)],clock=101)[0][2])
    def test_expired_and_wrong_unit(self):
        correlate_auth(self.store,[event('Failed password for demo',100)]*4,clock=100)
        fake=event('Failed password for demo',500);fake['unit']='example.service'
        self.assertFalse(correlate_auth(self.store,[fake,event('Failed password for demo',500)],clock=500))
    def test_old_logs(self):
        self.assertFalse(correlate_auth(self.store,[event('Failed password for demo',100)]*8,clock=1000))
    def test_console_escape_filters(self):
        record_incident(self.store,outcome='detectado',severity='high',category='ssh',source='test',title='<script>bad()</script>',evidence='198.51.100.8',fingerprint='a')
        page=render(self.store,{})
        self.assertNotIn('<script>',page); self.assertIn('&lt;script&gt;',page)
        self.assertEqual(len(select_rows(self.store,'incidents',{'q':['198.51.100.8']})),1)
        self.assertFalse(select_rows(self.store,'incidents',{'severity':['critical']}))
    def test_unknown_health(self):
        self.assertEqual(health(self.store)['status'],'sin_datos')
    def test_reentrant_review(self):
        record_finding(self.store,'unattended_missing','medium','updates','evidence','advice')
        def patcher(*args):
            with self.assertRaises(ValueError):
                review_finding(self.store,1,'aprobar',lambda *_: self.fail('double patch'),require_prompt=False)
        review_finding(self.store,1,'aprobar',patcher,require_prompt=False)
    def test_cancel(self):
        record_finding(self.store,'unattended_missing','medium','updates','evidence','advice')
        with patch('builtins.input',return_value='no'):
            self.assertFalse(review_finding(self.store,1,'aprobar',lambda *_: self.fail('unauthorized')))
