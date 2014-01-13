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
         "EVAL": "script-src 'self' 'unsafe-eval' https://mydomain.com",
         "INLINE": "script-src 'self' 'unsafe-inline' https://mydomain.com",
         "BLOB": "default-src 'self' *.mega.co.nz http://*.mega.co.nz;" + 
                 "script-src 'self' mega.co.nz data: blob:;",
         "MALFORMED": "default-src 'selff'",
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
    return _make_res('c', RULES['MALFORMED'])

@test_app.route('/eval-csp')
def eval_csp():
    return _make_res('x', RULES['EVAL'])

@test_app.route('/inline-csp')
def inline_csp():
    return _make_res('x', RULES['INLINE'])

@test_app.route('/dual-policy')
def daul_policy():
    resp = make_response('')
    resp.headers['Content-Security-Policy'] = 'default-src *;'
    resp.headers['Content-Security-Policy-Report-Only'] = 'default *;'
    return resp

@test_app.route('/report-only')
def report_only():
    resp = make_response('')
    resp.headers['Content-Security-Policy-Report-Only'] = 'default *;'
    return resp

@test_app.route('/blob')
def blog():
    return _make_res('c', RULES['BLOB'])

class TestCSPPlugin(TestPluginBaseClass):
    __test__ = True
    @classmethod
    def setUpClass(cls):
        super(TestCSPPlugin, cls).setUpClass()
        cls.pname = 'CSPPlugin'

    def validate_csp(self, runner_resp, request_resp, expected=None, expectation=True):
        if expectation is True:
            self.assertEqual('Info', runner_resp[1]['data']['Severity'])
            self.assertEqual('Content-Security-Policy header set properly', runner_resp[1]['data']['Summary'])
            self.assertEqual("The Content-Security-Policy header is set properly. Neither 'unsafe-inline' or \
'unsafe-eval' is enabled.", runner_resp[1]['data']['Description'])
            self.assertEqual('FINISHED', runner_resp[2]['data']['state'])

        elif expectation == 'BOTH-SET':
            self.assertEqual('Content-Security-Policy-Report-Only and Content-Security-Policy are set',
                    runner_resp[1]['data']['Summary'])
            self.assertEqual('High', runner_resp[1]['data']['Severity'])

        elif expectation == 'REPORT-ONLY':
            self.assertEqial('Content-Security-Policy-Report-Only does not enforce any CSP policy. Use \
Content-Security-Policy to secure your site.', runner_resp[1]['data']['Description'])                    
            self.assertEqual('Content-Security-Policy-Report-Only header set',
                    runner_resp[1]['data']['Summary'])
            self.assertEqual('High', runner_resp[1]['data']['Severity'])

        elif expectation is False:
            self.assertEqual('No Content-Security-Policy header set',
                    runner_resp[1]['data']['Summary'])
            self.assertEqual('High', runner_resp[1]['data']['Severity'])

        elif expectation == 'INVALID':
            self.assertEqual('High', runner_resp[1]['data']['Severity'])
            self.assertEqual('Malformed Content-Security-Policy header is set', \
                runner_resp[1]['data']['Summary'])
            self.assertEqual('Malformed CSP header set: {value} does not seem like a valid source expression for {name}'.format(
                value=expected['value'], name=expected['name']), runner_resp[1]['data']['Description'])

        elif expectation == 'UNSAFE-INLINE':
            self.assertEqual('High', runner_resp[1]['data']['Severity'])
            self.assertEqual("'unsafe-inline' is set in Content-Security-Policy header", \
                runner_resp[1]['data']['Summary'])

        elif expectation == 'UNSAFE-EVAL':
            self.assertEqual('High', runner_resp[1]['data']['Severity'])
            self.assertEqual("'unsafe-eval' is set in Content-Security-Policy header", \
                runner_resp[1]['data']['Summary'])

        elif expectation is False:
            self.assertEqual('High', runner_resp[1]['data']['Severity'])
            self.assertEqual('No X-Content-Security-Policy header set"',
                    runner_resp[1]['data']['Summary'])
        """
        elif expectation == 'EVAL-ENABLED':
            self.assertEqual('CSP Rules allow unsafe-eval',
                    runner_resp[1]['data']['Summary'])
            self.assertEqual('High', runner_resp[1]['data']['Severity'])

        elif expectation == 'INLINE-ENABLED':
            self.assertEqual('CSP Rules allow unsafe-inline',
                    runner_resp[1]['data']['Summary'])
            self.assertEqual('High', runner_resp[1]['data']['Severity'])
        """  

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
        self.validate_plugin(api_name, self.validate_csp, expectation='INVALID',
                expected={'value': "'selff'", 'name': 'default-src', 'hname': 'content-security-policy'})
    def test_eval_csp(self):
        api_name = '/eval-csp'
        self.validate_plugin(api_name, self.validate_csp, expectation='UNSAFE-EVAL')
    def test_inline_csp(self):
        api_name = '/inline-csp'
        self.validate_plugin(api_name, self.validate_csp, expectation='UNSAFE-INLINE')

    def test_dual_policy(self):
        api_name = '/dual-policy'
        self.validate_plugin(api_name, self.validate_csp, expectation='BOTH-SET')

    def test_report_only(self):
        api_name = '/report_only'
        self.validate_plugin(api_name, self.validate_csp, expectation='REPORT_ONLY')

    def test_blob(self):
        api_name = '/blob'
        self.validate_plugin(api_name, self.validate_csp, expectation=True)
