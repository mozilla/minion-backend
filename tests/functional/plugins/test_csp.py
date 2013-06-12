# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import requests
import sys
import time
import unittest

from flask import make_response

from base import TestPluginBaseClass, test_app

def _make_res(type, value):
    res = make_response("")
    if type.lower() == 'x':
        res.headers['X-Content-Security-Policy'] = value
    elif type.lower() == 'c':
        res.headers['Content-Security-Policy'] = value
    return res

RULES = {'DEFAULT-SRC': "default-src 'self'",
         "DEFAULT-SRC-DOMAIN": "default-src 'self' mydomain.com",
         "DEFAULT-SRC-DOMAIN-SUB-DOMAIN": "default-src 'self' *.mydomain.com",
         "DEFAULT-SRC-DOMAIN-SUB-DOMAIN-IMG-MEDIA-SCRIPT": 
            "default-src 'self'; img-src *; media-src media1.com media2.com; script-src userscripts.example.com",
         "EVAL": "script-src 'self' 'unsafe-eval' https://mydomain.com"
}

@test_app.route('/no-csp')
def no_csp():
    res = make_response()
    return res

@test_app.route('/default-src-self/<type>')
def default_src_self(type):
    return _make_res(type, RULES['DEFAULT-SRC'])

@test_app.route('/default-src-self-trusted-domain/<type>')
def default_src_self_trusted_domain(type):
    return _make_res(type, RULES['DEFAULT-SRC-DOMAIN'])

@test_app.route('/default-src-self-trusted-domain-subdomain/<type>')
def default_src_self_trusted_domain_subdomain(type):
    return _make_res(type, RULES['DEFAULT-SRC-DOMAIN-SUB-DOMAIN'])

@test_app.route('/default-src-self-trusted-subdomain-all-img-some-media-some-script/<type>')
def default_src_self_trusted_subdomain_all_img_some_media_some_script(type):
    return _make_res(type, RULES['DEFAULT-SRC-DOMAIN-SUB-DOMAIN-IMG-MEDIA-SCRIPT'])

@test_app.route('/malformed-csp')
def malformed_csp():
    mf = RULES['DEFAULT-SRC-DOMAIN-SUB-DOMAIN-IMG-MEDIA-SCRIPT'].replace(';', '')
    return _make_res('x', mf)

@test_app.route('/eval-csp')
def eval_csp():
    return _make_res('x', RULES['EVAL'])

class TestCSPPlugin(TestPluginBaseClass):
    __test__ = True
    @classmethod
    def setUpClass(cls):
        super(TestCSPPlugin, cls).setUpClass()
        cls.pname = 'CSPPlugin'

    def validate_csp(self, runner_resp, request_resp, expected=None, expectation=True):
        if expectation is True:
            self.assertEqual('FINISHED', runner_resp[1]['data']['state'])
        elif expectation == 'BOTH-SET':
            self.assertEqual('Both X-Content-Security-Policy and X-Content-Security-Policy-Report-Only headers set',
                    runner_resp[1]['data']['Summary'])
            self.assertEqual('High', runner_resp[1]['data']['Severity'])
        elif expectation == 'REPORT-ONLY':
            self.assertEqual('X-Content-Security-Policy-Report-Only header set',
                    runner_resp[1]['data']['Summary'])
            self.assertEqual('High', runner_resp[1]['data']['Severity'])
        elif expectation is False:
            self.assertEqual('No Content-Security-Policy header set',
                    runner_resp[1]['data']['Summary'])
            self.assertEqual('High', runner_resp[1]['data']['Severity'])
        elif expectation == 'INVALID':
            self.assertEqual('Malformed X-Content-Security-Policy header set',
                    runner_resp[1]['data']['Summary'])
        elif expectation == 'EVAL-ENABLED':
            self.assertEqual('CSP Rules allow eval-script',
                    runner_resp[1]['data']['Summary'])
            self.assertEqual('High', runner_resp[1]['data']['Severity'])
        elif expectation == 'INLINE-ENABLED':
            self.assertEqual('CSP Rules allow inline-script',
                    runner_resp[1]['data']['Summary'])
            self.assertEqual('High', runner_resp[1]['data']['Severity'])
        elif expectation is False:
            self.assertEqual('No X-Content-Security-Policy header set"',
                    runner_resp[1]['data']['Summary'])
            self.assertEqual('High', runner_resp[1]['data']['Severity'])

    def test_no_csp(self):
        api_name = '/no-csp'
        self.validate_plugin(api_name, self.validate_csp, expectation=False)

    def test_x_default_src_self(self):
        api_name= '/default-src-self/x'
        self.validate_plugin(api_name, self.validate_csp, expectation=True)
    def test_x_default_src_self_trusted_domain(self):
        api_name = '/default-src-self-trusted-domain/x'
        self.validate_plugin(api_name, self.validate_csp, expectation=True)
    def test_x_default_src_self_trusted_domain_subdomain(self):
        api_name = '/default-src-self-trusted-domain-subdomain/x'
        self.validate_plugin(api_name, self.validate_csp, expectation=True)
    def test_x_default_src_self_trusted_domain_subdomain_all_img_some_media_some_script(self):
        api_name = '/default-src-self-trusted-subdomain-all-img-some-media-some-script/x'
        self.validate_plugin(api_name, self.validate_csp, expectation=True)

    def test_default_src_self(self):
        api_name= '/default-src-self/c'
        self.validate_plugin(api_name, self.validate_csp, expectation=True)
    def test_default_src_self_trusted_domain(self):
        api_name = '/default-src-self-trusted-domain/c'
        self.validate_plugin(api_name, self.validate_csp, expectation=True)
    def test_default_src_self_trusted_domain_subdomain(self):
        api_name = '/default-src-self-trusted-domain-subdomain/c'
        self.validate_plugin(api_name, self.validate_csp, expectation=True)
    def test_default_src_self_trusted_domain_subdomain_all_img_some_media_some_script(self):
        api_name = '/default-src-self-trusted-subdomain-all-img-some-media-some-script/c'
        self.validate_plugin(api_name, self.validate_csp, expectation=True)

    def test_malformed_csp(self):
        api_name = '/malformed-csp'
        self.validate_plugin(api_name, self.validate_csp, expectation='INVALID')
    def test_eval_csp(self):
        api_name = '/eval-csp'
        self.validate_plugin(api_name, self.validate_csp, expectation='EVAL-ENABLED')
