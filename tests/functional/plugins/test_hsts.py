# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import requests
import sys
import time
import unittest
from multiprocessing import Process
from subprocess import Popen, PIPE
from flask import make_response, request
from collections import namedtuple
from base import TestPluginBaseClass, test_app
from minion.plugins.basic import HSTSPlugin

@test_app.route('/test')
def endpoint():
    value = request.args.get("hsts-value")
    res = make_response("")
    if value:
        res.headers['strict-transport-security'] = value
    return res

class TestHSTSPlugin(TestPluginBaseClass):
    __test__ = True
    Issue = namedtuple('Issue', 'code summary severity')
    HSTS = HSTSPlugin()

    @classmethod
    def setUpClass(cls):
        super(TestHSTSPlugin, cls).setUpClass(tls=True)
        cls.pname = "HSTSPlugin"

    def _run_plugin(self, pname, url):
        runner_resp = self.run_plugin(pname, url)
        return runner_resp

    def _run(self, base="http://localhost:1234", endpoint="/test", hsts_value=None):
        API = base + endpoint
        r = requests.Request('GET', API,
            params={"hsts-value": hsts_value}).prepare()
        return self._run_plugin(self.pname, r.url)

    def _get_summary(self, key, fill_with=None):
        _summary = self.HSTS.REPORTS[key]['Summary']
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

    #NOTE: We will comment this out until we agree that curly.get should add
    # an option to enable and disable SSL verification.
    """
    def test_hsts_is_set(self):
        resp = self._run(base="https://localhost:1234", hsts_value="max-age=3153600")
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            "set",
            "HSTS is set properly should be in issues.")
        self._test_expecting_codes(
            issues,
            ["HSTS-0"],
            "Expecting HSTS is set properly")
    """

    def test_hsts_set_properly(self):
        resp = self._run_plugin(self.pname, "https://mozillalabs.com")
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            "set",
            "HSTS is set properly should be in issues.")
        self._test_expecting_codes(
            issues,
            ["HSTS-0"],
            "Expecting HSTS is set properly")

    def test_hsts_not_set(self):
        resp = self._run_plugin(self.pname, "https://google.com")
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            "not-set",
            "HSTS is not set should be in issues.")
        self._test_expecting_codes(
            issues,
            ["HSTS-2"],
            "Expecting HSTS is not set")
