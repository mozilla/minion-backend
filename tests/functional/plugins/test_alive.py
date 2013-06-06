# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import requests
import sys
import time
import unittest

from flask import make_response

from base import TestPluginBaseClass, test_app

@test_app.route('/alive')
def alive_alive():
    res = make_response("<h1>HELLO WORLD!</h1>")
    return res

@test_app.route('/timeout')
def alive_timeout():
    res = make_response('<h1> TIMEOUT </h1>')
    time.sleep(16)
    return res

class TestAlivePlugin(TestPluginBaseClass):
    __test__ = True
    @classmethod
    def setUpClass(cls):
        super(TestAlivePlugin, cls).setUpClass()
        cls.pname = 'AlivePlugin'

    def validate_alive(self, runner_resp, request_resp, expected=None, expectation=True):
        if expectation is True:
            self.assertEqual('FINISHED', runner_resp[1]['data']['state'])
            self.assertEqual(200, request_resp.status_code)
        elif expectation == '404':
            self.assertEqual('Fatal', runner_resp[1]['data']['Severity'])
            self.assertEqual(404, request_resp.status_code)
            self.assertEqual(True, 'non-200 response: 404' in runner_resp[1]['data']['URLs'][0]['Extra'])
        elif expectation in (False, 'TIMEOUT'):
            print runner_resp[1]['data']
            self.assertEqual('Fatal', runner_resp[1]['data']['Severity'])
            self.assertEqual('Site could not be reached', runner_resp[1]['data']['Summary'])
            self.assertEqual(expected, runner_resp[1]['data']['URLs'][0]['URL'])
            if expectation is False:
                # requests will throw exeception if not connectable
                self.assertEqual(requests.exceptions.ConnectionError, type(request_resp))

    def test_alive_200(self):
        api_name = '/alive'
        self.validate_plugin(api_name, self.validate_alive, expectation=True)
    def test_alive_404(self):
        api_name = '/not-alive'
        self.validate_plugin(api_name, self.validate_alive, expectation='404')
    def test_alive_timeout(self):
        api_name = '/timeout'
        self.validate_plugin(api_name, self.validate_alive, \
            expected='http://localhost:1234/timeout', expectation='TIMEOUT')

