# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from flask import make_response

from base import TestPluginBaseClass, test_app

@test_app.route('/xfo-with-deny')
def xfo_with_deny():
    res = make_response("")
    res.headers['X-Frame-Options'] = 'DENY'
    return res

@test_app.route('/xfo-with-sameorigin')
def xfo_with_sameorigin():
    res = make_response("")
    res.headers['X-Frame-Options'] = 'SAMEORIGIN'
    return res

@test_app.route('/xfo-with-allow-from')
def xfo_with_allow_from():
    res = make_response("")
    res.headers['X-Frame-Options'] = 'ALLOW-FROM http://localhost:1234/'
    return res

@test_app.route('/xfo-with-allow-from-with-colon')
def xfo_with_allow_from_with_colon():
    res = make_response("")
    res.headers['X-Frame-Options'] = 'ALLOW-FROM: http://localhost:1234/'
    return res

@test_app.route('/xfo-with-allow-from-without-http')
def xfo_with_allow_from_withou_http():
    res = make_response("")
    res.headers['X-Frame-Options'] = 'ALLOW-FROM localhost:1234/'
    return res

@test_app.route('/bad-xfo')
def bad_xfo():
    res = make_response("<h1>Hello World!</h1>")
    res.headers['X-Frame-Options'] = "CHEESE"
    return res

class TestXFrameOptionsPlugin(TestPluginBaseClass):
    __test__ = True
    @classmethod
    def setUpClass(cls):
        super(TestXFrameOptionsPlugin, cls).setUpClass()
        cls.pname = "XFrameOptionsPlugin"

    def validate_xframe_plugin(self, runner_resp, request_resp, expected=None, expectation=True):
        if expectation is True:
            self.assertEqual('X-Frame-Options header is set properly', runner_resp[1]['data']['Summary'])
            self.assertEqual('Info', runner_resp[1]['data']['Severity'])
        else:
            fragement = request_resp.headers['X-Frame-Options']
            self.assertEqual(True, fragement in runner_resp[1]['data']['Description'])
            self.assertEqual("High", runner_resp[1]['data']['Severity'])
            if expectation == 'INVALID':
                self.assertEqual("The following X-Frame-Options header value is detected and is invalid: %s" % fragement, \
                    runner_resp[1]['data']['Description'])
            else:
                self.assertEqual(True, "X-Frame-Options header is not found." in runner_resp[1]['data']['Description'])
        self.assertEqual(expected, request_resp.headers['X-Frame-Options'])

    def test_bad_xframe_option(self):
        api_name = "/bad-xfo"
        self.validate_plugin(api_name, self.validate_xframe_plugin, expected='CHEESE', expectation='INVALID')

    def test_xframe_option_with_same_origin(self):
        api_name = '/xfo-with-sameorigin'
        self.validate_plugin(api_name, self.validate_xframe_plugin, expected='SAMEORIGIN', expectation=True)

    def test_xframe_option_with_deny(self):
        api_name = '/xfo-with-deny'
        self.validate_plugin(api_name, self.validate_xframe_plugin, expected='DENY', expectation=True)

    def test_xframe_option_with_allow_from(self):
        api_name = '/xfo-with-allow-from'
        self.validate_plugin(api_name, self.validate_xframe_plugin, \
                expected='ALLOW-FROM http://localhost:1234/', expectation=True)

    def test_xframe_option_with_allow_from_colon_gets_rejected(self):
        api_name = '/xfo-with-allow-from-with-colon'
        self.validate_plugin(api_name, self.validate_xframe_plugin, \
                expected='ALLOW-FROM: http://localhost:1234/', expectation='INVALID')

    def test_xframe_option_without_http(self):
        api_name = '/xfo-with-allow-from-without-http'
        self.validate_plugin(api_name, self.validate_xframe_plugin, \
                expected='ALLOW-FROM localhost:1234/', expectation='INVALID')
