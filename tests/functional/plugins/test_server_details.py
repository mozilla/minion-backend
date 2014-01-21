# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import requests
import sys
import time
import unittest

from flask import make_response, request
from collections import namedtuple
from base import TestPluginBaseClass, test_app
from minion.plugins.basic import ServerDetailsPlugin

@test_app.route('/test')
def endpoint():
    headers = request.args.getlist("headers")
    values = request.args.getlist("values")

    res = make_response("")
    if headers and values:
        _headers = dict(zip(headers, values))
        for name, value in _headers.items():
            res.headers[name] = value
    return res

# headers to be exposed
HEADERS = {
    'X-Powered-By': 'PHP/5.2.6',
    'X-AspNet-Version': '5.0.111212',
    'X-AspNetMvc-Version': '4.0',
    'X-Backend-Server': 'cheese-burger'
}

@test_app.route('/expose-single/<name>')
def respond_with_a_header(name):
    res = make_response('')
    res.headers[name] = HEADERS[name]
    return res

@test_app.route('/expose-all')
def respond_with_all_headers():
    res = make_response('')
    for name, value in HEADERS.iteritems():
        res.headers[name] = value
    return res

class TestServerDetailsPlugin(TestPluginBaseClass):
    __test__ = True
    Issue = namedtuple('Issue', 'code summary severity')
    ServerDetails = ServerDetailsPlugin()

    @classmethod
    def setUpClass(cls):
        super(TestServerDetailsPlugin, cls).setUpClass()
        cls.pname = "ServerDetailsPlugin"

    def _get_summary(self, key, fill_with=None):
        _summary = self.ServerDetails.REPORTS[key]['Summary']
        if fill_with:
            return _summary.format(**fill_with)
        else:
            return _summary

    def _run(self, headers=None, values=None):
        API = "http://localhost:1234/test"
        r = requests.Request('GET', API,
            params={"headers": headers, "values": values}).prepare()
        runner_resp = self.run_plugin(self.pname, r.url)
        return runner_resp

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

    def test_serverdetails_expose_powered_by(self):
        resp = self._run(headers=["X-Powered-By"], values=["PHP/5.2.6"])
        issues = self._get_issues(resp)

        self._test_expecting_codes(
            issues,
            ['SD-0', 'SD-0'],
            "X-Powered-By is set")

    def test_serverdetails_expose_all(self):
        resp = self._run(
            headers=["Server", "X-Powered-By", "X-AspNet-Version",
                     "X-AspNetMvc-Version", "X-Backend-Server"],
            values=["PyServer", "PHP/5.2.6", "5.0.111212", "4.0", "foobar-server"])

        issues = self._get_issues(resp)
        self._test_expecting_codes(
            issues,
            ['SD-0', 'SD-0', 'SD-0', 'SD-0', 'SD-0'],
            "Server, X-Powered-By, X-AspNet-Version, X-AspNetMvc-Version,\
X-Backend-Server are detected.")
