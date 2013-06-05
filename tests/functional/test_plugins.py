# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import json
import unittest
import requests
from functools import wraps
from multiprocessing import Process
from subprocess import Popen, PIPE

from flask import Flask, make_response

#TODO: Investigate (1) why I can't make http request when launch
# nosetests on all tests_*.py and (2) any way to build the route table
# at a later time. Given these two issues, we shall build the table
# at the global level.
test_app = Flask(__name__)

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

@test_app.route('/bad-xfo')
def bad_xfo():
    res = make_response("<h1>Hello World!</h1>")
    res.headers['X-Frame-Options'] = "CHEESE"
    return res

class TestBuiltInPlugins(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        def run_app():
            test_app.run(host='localhost', port=1234)

        # use multiprocess to launch server and kill server
        cls.server = Process(target=run_app)
        cls.server.daemon = True
        cls.server.start()
        
        cls.pname = "XFrameOptionsPlugin"

    @classmethod
    def tearDownClass(cls):
        cls.server.terminate()

    def run_plugin(self, pname, api):
        pname = "minion.plugins.basic." + pname
        cmd = ["minion-plugin-runner",
                "-c", json.dumps({"target": api}),
                "-p", pname]
        p = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()
        msgs = stdout.split('\n')[:-1]
        msgs_lst = []
        for msg in msgs:
            msgs_lst.append(json.loads(msg))
        return msgs_lst

    def validate_xframe_plugin(self, api_name, expected=None, expectation=True):
        """ Validate the response returned subscribes to our expectation 
        and values agree with the expected values. """
        BASE = "http://localhost:1234"
        API = BASE + api_name
        # first, examine via plugin-runner and then quickly make request to api
        results = self.run_plugin(self.pname, API)
        resp = requests.get(API)

        if expectation:
            self.assertEqual(True, 'correct' in results[1]['data']['Summary'])
            self.assertEqual('Info', results[1]['data']['Severity'])
        else:
            fragement = "invalid value: %s" % resp.headers['X-Frame-Options']
            self.assertEqual(True, fragement in results[1]['data']['Summary'])
            self.assertEqual("High", results[1]['data']['Severity'])
        
    def test_bad_xframe_option(self):
        api_name = "/bad-xfo"
        self.validate_xframe_plugin(api_name, 'CHEESE', expectation=False)

    def test_xframe_option_with_same_origin(self):
        api_name = '/xfo-with-sameorigin'
        self.validate_xframe_plugin(api_name, expectation=True)

    def test_xframe_option_with_deny(self):
        api_name = '/xfo-with-deny'
        self.validate_xframe_plugin(api_name, expectation=True)

    def test_xframe_option_with_allow_from(self):
        api_name = '/xfo-with-allow-from'
        self.validate_xframe_plugin(api_name, expectation=True)
