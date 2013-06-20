# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import requests
from flask import make_response

from base import TestPluginBaseClass, test_app

@test_app.route('/xcontent-nosniff')
def xcontent_nosniff():
    res = make_response("")
    res.headers['X-Content-Type-Options'] = 'nosniff'
    return res

@test_app.route('/xcontent-invalid-value')
def xcontent_invalid():
    res = make_response("")
    res.headers['X-Content-Type-Options'] = 'CHEESE'
    return res

@test_app.route('/without-xcontent')
def xcontent_without():
    res = make_response("")
    return res


class TestXContentTypeOptionsPlugin(TestPluginBaseClass):
    __test__ = True
    @classmethod
    def setUpClass(cls):
        super(TestXContentTypeOptionsPlugin, cls).setUpClass()
        cls.pname = "XContentTypeOptionsPlugin"

    def validate_xcontent(self, runner_resp, request_resp, expected=None, expectation=True):
        if expectation:
            self.assertEqual("X-Content-Type-Options is set properly", runner_resp[1]['data']['Summary'])
            self.assertEqual("Site has the following X-Content-Type-Options header set: %s" \
                    % request_resp.headers['x-content-type-options'], runner_resp[1]['data']['Description'])
            self.assertEqual("Info", runner_resp[1]['data']['Severity'])
        elif expectation == 'INVALID':
            self.assertEqual('Invalid X-Content-Type-Options header detected', runner_resp[1]['data']['Summary'])
            self.assertEqual("The following X-Content-Type-Options header value is detected and is \
invalid: %s" % request_resp.headers['x-content-type-options'], runner_resp[1]['data']['Description'])
            self.assertEqual("High", runner_resp[1]['data']['Severity'])
            self.assertEqual(expected, request_resp.headers['x-content-type-options'])
        elif expectation is False:
            self.assertEqual("X-Content-Type-Options header is not set", runner_resp[1]['data']['Summary'])
            self.assertEqual("High", runner_resp[1]['data']['Severity'])


    def test_xcontent_with_nosniff(self):
        api_name = '/xcontent-nosniff'
        self.validate_plugin(api_name, self.validate_xcontent, expectation=True)

    
    #def test_xcontent_with_invalid_value(self):
    #    api_name = '/xcontent-invalid-value'
    #    self.validate_plugin(api_name, self.validate_xcontent, expected='CHEESE', expectation='INVALID')

    def test_xcontent_without_option(self):
        api_name = '/without-xcontent'
        self.validate_plugin(api_name, self.validate_xcontent, expectation=False)
