# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import requests
import sys
import time
import unittest

from flask import make_response

from base import TestPluginBaseClass, test_app

@test_app.route('/xxsprotected')
def xxsprotected():
    res = make_response("")
    res.headers['X-XSS-Protection'] = '1; mode=block'
    return res

@test_app.route('/xxsprotect-zero')
def xxsprotect_zero():
    res = make_response("")
    res.headers['X-XSS-Protection'] = '0'
    return res

@test_app.route('/bad-xxsprotected-value')
def bad_xxsprotected_value():
    res = make_response("")
    res.headers['X-XSS-Protection'] = 'CHEESE'
    return res

@test_app.route('/not-xxsprotected')
def not_xxsprotected():
    res = make_response("")
    return res

class TestXXSSProtectionPlugin(TestPluginBaseClass):
    __test__ = True
    @classmethod
    def setUpClass(cls):
        super(TestXXSSProtectionPlugin, cls).setUpClass()
        cls.pname = 'XXSSProtectionPlugin'

    def validate_xxssprotection(self, runner_resp, request_resp, expected=None, expectation=True):
        if expectation is True:
            self.assertEqual('Info', runner_resp[1]['data']['Severity'])
            self.assertEqual('Site sets X-XSS-Protection header', runner_resp[1]['data']['Summary'])
            self.assertEqual(200, request_resp.status_code)
        elif expectation == 'INVALID':
            self.assertEqual('High', runner_resp[1]['data']['Severity'])
            self.assertEqual('Site sets an invalid X-XSS-Protection header: %s' % expected, \
                    runner_resp[1]['data']['Summary'])
            self.assertEqual(expected, request_resp.headers['x-xss-protection'])
        elif expectation == 'DISABLE':
            self.assertEqual('High', runner_resp[1]['data']['Severity'])
            self.assertEqual('Site sets X-XSS-Protection header to disable the XSS filter', \
                    runner_resp[1]['data']['Summary'])
            self.assertEqual(expected, request_resp.headers['x-xss-protection'])
        elif expectation is False:
            self.assertEqual('High', runner_resp[1]['data']['Severity'])
            self.assertEqual('Site does not set X-XSS-Protection header', \
                    runner_resp[1]['data']['Summary'])
            self.assertEqual(True, 'x-xss-protection' not in request_resp.headers)

    def test_xxsprotect_with_1_mode_block(self):
        api_name = '/xxsprotected'
        self.validate_plugin(api_name, self.validate_xxssprotection, expectation=True)
    def test_xxsprotect_with_0(self):
        api_name = '/xxsprotect-zero'
        self.validate_plugin(api_name, self.validate_xxssprotection, expected='0',\
                expectation='DISABLE')
    def test_xxsprotect_with_invalid_value(self):
        api_name = '/bad-xxsprotected-value'
        self.validate_plugin(api_name, self.validate_xxssprotection, \
            expected='CHEESE', expectation='INVALID')
    def test_without_xxssprotection(self):
        api_name = '/not-xxsprotected'
        self.validate_plugin(api_name, self.validate_xxssprotection, expectation=False)
