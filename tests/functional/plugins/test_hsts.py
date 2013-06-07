# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import requests
import sys
import time
import unittest
from multiprocessing import Process
from subprocess import Popen, PIPE

from flask import make_response

from base import TestPluginBaseClass, test_app, _kill_ports

@test_app.route('/has-hsps')
def has_hsps():
    res = make_response("<h1>HELLO HTTPS</h1>")
    res.headers['strict-transport-security'] = 'max-age=3153600'
    return res

@test_app.route('/no-hsps')
def no_hsps():
    res = make_response("")
    return res

class TestHSTSPlugin(TestPluginBaseClass):
    __test__ = True

    @classmethod
    def setUpClass(cls):
        def run_app(port):
            test_app.run(port=port)

        def run_stunnel():
            p = Popen(['stunnel4', 'stunnel-data/minion-test.ini'], stdout=PIPE,\
                stderr=PIPE)
            p.communicate()

        _kill_ports(cls.PORTS)
        cls.stunnel = Process(target=run_stunnel)
        cls.stunnel.daemon = True
        cls.stunnel.start()
        
        # server1 will be HTTP and one can access https through 1443
        cls.server1 = Process(target=run_app, args=(1235,))
        cls.server1.daemon = True
        cls.server1.start()
        cls.pname = 'HSTSPlugin'

    @classmethod
    def tearDownClass(cls):
        cls.server1.terminate()
        cls.stunnel.terminate() # only kills multiprocess instance
        # actually kills stunnel process
        _kill_ports(cls.PORTS)

    def validate_hsps(self, runner_resp, request_resp, expected=None, expectation=True):
        if expectation is True:
            self.assertEqual('Site sets Strict-Transport-Security header', \
                runner_resp[1]['data']['Summary'])
            self.assertEqual(True, 'max-age' in request_resp.headers['strict-transport-security'])
            self.assertEqual('Info', runner_resp[1]['data']['Severity'])
        elif expectation is False:
            self.assertEqual('High', runner_resp[1]['data']['Severity'])
            self.assertEqual('Site does not set Strict-Transport-Security header', \
                runner_resp[1]['data']['Summary'])
        elif expectation is 'BAD-CERT':
            self.assertEqual('Error', runner_resp[1]['data']['Severity'])

    def test_hsts_fail_on_cert_without_ca(self):
        api_name = '/has-hsts'
        self.validate_plugin(api_name, self.validate_hsps, expectation='BAD-CERT',\
            base='https://localhost:1443')
     
    def test_hsts_good_on_signed_cert(self):
        self.validate_plugin(None, self.validate_hsps, expectation=True, base=None,\
           target='https://www.mozillalabs.com')
    
    def test_hsps_no_hsps_header_over_https(self):
        self.validate_plugin(None, self.validate_hsps, expectation=False,\
            target='https://google.com')
   
