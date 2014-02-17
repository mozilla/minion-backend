# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import json
import os
import requests
import time
import unittest

from collections import namedtuple
from multiprocessing import Process
from subprocess import Popen, PIPE

from flask import Flask
from OpenSSL import SSL

class TestPluginBaseClass(unittest.TestCase):
    __test__ = False
    PORTS = (1234, 1235, 1443)
    Issue = namedtuple('Issue', 'code summary severity')

    @classmethod
    def setUpClass(cls, app_file):
        file_path = os.path.join(os.path.dirname(__file__),
            "servers/" + app_file)
        cls.server = Popen(["python", file_path])
        time.sleep(1)

    @classmethod
    def tearDownClass(cls):
        cls.server.kill()
        cls.server.terminate()
        time.sleep(1)

    def run_plugin(self, pname, api):
        pname = "minion.plugins.basic." + pname
        cmd = ["minion-plugin-runner",
                "-c", json.dumps({"target": api}),
                "-p", pname]
        p = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()
        print stdout
        print stderr
        msgs = stdout.split('\n')[:-1]
        msgs_lst = []
        for msg in msgs:
            msgs_lst.append(json.loads(msg))
        return msgs_lst
 
    def _run(self, base="http://localhost:1234", api="/test", params=None):
        r = requests.Request('GET', base + api, params=params).prepare()
        return self.run_plugin(self.pname, r.url)

    def _get_summary(self, key, fill_with=None):
        _summary = self.plugin_class.REPORTS[key]['Summary']
        if fill_with:
            return _summary.format(**fill_with)
        else:
            return _summary

    def _get_issues(self, resps):
        issues = []
        for issue in resps:
            if issue.get('data') and issue['data'].get('Code'):
                _issue = self.Issue(issue['data']['Code'],
                                    issue['data']['Summary'],
                                    issue['data']['Severity'])
                issues.append(_issue)
        return issues

    def _test_expecting_codes(self, issues, expects, message):
        self.assertEqual(len(issues), len(expects), msg=message)
        for expect in expects:
            self._test_expecting_code(issues, expect, message)

    def _test_expecting_code(self, issues, expect, message):
        codes = [issue.code for issue in issues]
        self.assertEqual(True, expect in codes, msg=message)

    def _test_expecting_summary(self, issues, summary_name, message,
            fill_with=None):
        summaries = [issue.summary for issue in issues]
        expecting_summary = self._get_summary(summary_name, fill_with=fill_with)
        self.assertEqual(True, expecting_summary in summaries, msg=message)
