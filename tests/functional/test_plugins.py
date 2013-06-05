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

@test_app.route('/bad-xfo')
def bad_xfo():
    res = make_response("<h1>Hello World!</h1>")
    res.headers['X-Frame-Options'] = "CHEESE"
    return res

class TestBuiltInPlugins(unittest.TestCase):
    def setUp(self):
        def run_app():
            test_app.run(host='localhost', port=1234)

        # use multiprocess to launch server and kill server
        self.server = Process(target=run_app)
        self.server.daemon = True
        self.server.start()

    def tearDown(self):
        self.server.terminate()

    def run_plugin(self, name, resource_name):
        name = "minion.plugins.basic." + name
        api = "http://localhost:1234" + resource_name
        cmd = ["minion-plugin-runner",
                "-c", json.dumps({"target": api}),
                "-p", name]
        p = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()
        msgs = stdout.split('\n')[:-1]
        msgs_lst = []
        for msg in msgs:
            msgs_lst.append(json.loads(msg))
        return msgs_lst

    def test_bad_xframe_option(self):
        resp = requests.get("http://localhost:1234/bad-xfo")
        self.assertEqual('CHEESE', resp.headers['X-Frame-Options'])
        results = self.run_plugin('XFrameOptionsPlugin', '/bad-xfo')
        self.assertEqual(True, "invalid value: CHEESE" in results[1]['data']['Summary'])
        self.assertEqual("High", results[1]['data']['Severity'])

