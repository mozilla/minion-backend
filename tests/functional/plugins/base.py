# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import json
import unittest
import requests
import time
from multiprocessing import Process
from subprocess import Popen, PIPE

from flask import Flask
test_app = Flask(__name__)

class TestPluginBaseClass(unittest.TestCase):
    __test__ = False 
    @classmethod
    def setUpClass(cls):
        """ Every test class inherits from this base class
        must define cls.pname as the name of the plugin. """
        def run_app():
            test_app.run(host='localhost', port=1234)

        # use multiprocess to launch server and kill server
        cls.server = Process(target=run_app)
        cls.server.daemon = True
        cls.server.start()

        @classmethod
        def tearDownClass(cls):
            cls.server.terminate()
            time.sleep(2)

    def run_plugin(self, pname, api):
        pname = "minion.plugins.basic." + pname
        cmd = ["minion-plugin-runner",
                "-c", json.dumps({"target": api}),
                "-p", pname]
        p = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()
        print stderr
        msgs = stdout.split('\n')[:-1]
        msgs_lst = []
        for msg in msgs:
            msgs_lst.append(json.loads(msg))
        return msgs_lst

    def validate_plugin(self, api_name, validator, expected=None, expectation=True,
            base='http://localhost:1234', target=None):
        """ Validate the response returned from the plugin runner subscribes to
        the validation specify by the function validator. When expectation is False,
        the validator function should check the response is negative. """

        if target:
            API = target
        else:
            API = base + api_name
        # first, examine via plugin-runner and then quickly make request to api
        runner_resp = self.run_plugin(self.pname, API)
        try:
            request_resp = requests.get(API, verify=False)
        except requests.exceptions.ConnectionError:
            request_resp = requests.exceptions.ConnectionError

        return validator(runner_resp, request_resp, expected=expected, expectation=expectation)

    

