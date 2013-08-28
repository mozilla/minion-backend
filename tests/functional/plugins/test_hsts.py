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

from base import TestPluginBaseClass, test_app

from nose import SkipTest

@test_app.route('/has-hsts')
def has_hsts():
    res = make_response("<h1>HELLO HTTPS</h1>")
    res.headers['strict-transport-security'] = 'max-age=3153600'
    return res

@test_app.route('/no-hsts')
def no_hsts():
    res = make_response("")
    return res

@test_app.route("/negative-hsts")
def has_negative_hsts():
    res = make_response("")
    res.headers['strict-transport-security'] = 'max-age=-1'
    return res

@test_app.route("/invalid-hsts")
def invalid_hsts():
    res = make_response("")
    res.headers['strict-transport-security'] = 'max-agee=3153600'
    return res

@test_app.route('/hsts-include-subdomain')
def include_subdomain():
    res = make_response("")
    res.headers['strict-transport-security'] = 'max-age=3153600; includeSubdomain'
    return res

class TestHSTSPlugin(TestPluginBaseClass):
    __test__ = True

    @classmethod
    def setUpClass(cls):
        def run_app(port):
            test_app.run(port=port)

        def find_stunnel():
            for path in os.environ['PATH'].split(os.pathsep):
                stunnel_path = os.path.join(path, 'stunnel4')
                if os.path.exists(stunnel_path):
                    return stunnel_path

        cls.stunnel_process = None
        cls.stunnel_path = find_stunnel()
        if cls.stunnel_path:
            cls.stunnel_process = Popen([cls.stunnel_path, 'stunnel-data/minion-test.ini'], stdout=PIPE, stderr=PIPE)

        # server1 will be HTTP and one can access https through 1443
        cls.server1 = Process(target=run_app, args=(1235,))
        cls.server1.daemon = True
        cls.server1.start()
        cls.pname = 'HSTSPlugin'

    @classmethod
    def tearDownClass(cls):
        cls.server1.terminate()
        if cls.stunnel_process:
            cls.stunnel_process.terminate()

    def validate_hsts(self, runner_resp, request_resp, expected=None, expectation=True):
        if expectation is True:
            self.assertEqual('Strict-Transport-Security header is set properly', \
                runner_resp[1]['data']['Summary'])
            self.assertEqual("Site has the following Strict-Transport-Security header set: %s" \
                    % request_resp.headers['strict-transport-security'], runner_resp[1]['data']['Description'])
            self.assertEqual(True, 'max-age' in request_resp.headers['strict-transport-security'])
            self.assertEqual('Info', runner_resp[1]['data']['Severity'])
        elif expectation is False:
            self.assertEqual('High', runner_resp[1]['data']['Severity'])
            self.assertEqual('Strict-Transport-Security header is not set', \
                runner_resp[1]['data']['Summary'])
        elif expectation is 'BAD-CERT':
            self.assertEqual('Error', runner_resp[1]['data']['Severity'])
        elif expectation is "INVALID":
            self.assertEqual('High', runner_resp[1]['data']['Severity'])
            self.assertEqual("Site sets an invalid Strict-Transport-Security header", \
                    runner_resp[1]['data']['Summary'])
        elif expectation is "NEGATIVE":
            self.assertEqual('High', runner_resp[1]['data']['Severity'])
            self.assertEqual("Site sets a negative max-age in the Strict-Transport-Security header", \
                    runner_resp[1]['data']['Summary'])

    def test_hsts_fail_on_cert_without_ca(self):
        if not self.stunnel_path:
            raise SkipTest
        api_name = '/has-hsts'
        self.validate_plugin(api_name, self.validate_hsts, expectation='BAD-CERT',\
            base='https://localhost:1443')

    def test_hsts_good_on_signed_cert(self):
        self.validate_plugin(None, self.validate_hsts, expectation=True, base=None,\
           target='https://www.mozillalabs.com')

    def test_hsts_no_hsts_header_over_https(self):
        self.validate_plugin(None, self.validate_hsts, expectation=False,\
            target='https://google.com')
