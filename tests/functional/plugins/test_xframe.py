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
from minion.plugins.basic import XFrameOptionsPlugin

@test_app.route('/test')
def endpoint():
    value = request.args.get("xframe-value")
    res = make_response("")
    if value:
        res.headers['X-Frame-Options'] = value
    return res

class TestXFrameOptionsPlugin(TestPluginBaseClass):
    __test__ = True
    Issue = namedtuple('Issue', 'code summary severity')
    XFrameOpts = XFrameOptionsPlugin()

    @classmethod
    def setUpClass(cls):
        super(TestXFrameOptionsPlugin, cls).setUpClass()
        cls.pname = "XFrameOptionsPlugin"

    def _get_summary(self, key, fill_with=None):
        _summary = self.XFrameOpts.REPORTS[key]['Summary']
        if fill_with:
            return _summary.format(**fill_with)
        else:
            return _summary

    def _run(self, xframe_value=None):
        API = "http://localhost:1234/test"
        r = requests.Request('GET', API,
            params={"xframe-value": xframe_value}).prepare()
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

    def test_xfo_not_set(self):
        resp = self._run()
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'not-set',
            "XFO is not set should be in issues")

        self._test_expecting_codes(issues,
            ['XFO-2'],
            "XFO is not set detected.")

    def test_set_xfo_with_same_origin(self):
        resp = self._run(xframe_value="SAMEORIGIN")
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'set',
            "XFO is set properly should be in issues")

        self._test_expecting_codes(issues,
            ['XFO-0'],
            "XFO is properly set detected.")

    def test_set_xfo_with_deny(self):
        resp = self._run(xframe_value="DENY")
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'set',
            "XFO is set properly should be in issues")

        self._test_expecting_codes(issues,
            ['XFO-0'],
            "XFO is properly set detected.")

    def test_set_xfo_with_allow_from(self):
        resp = self._run(xframe_value="ALLOW-FROM http://localhost:1234/")
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'set',
            "XFO is set properly should be in issues")

        self._test_expecting_codes(issues,
            ['XFO-0'],
            "XFO is properly set detected.")

    def test_xfo_mark_invalid_if_colon_append_to_allow_from(self):
        resp = self._run(xframe_value="ALLOW-FROM: http://localhost:1234/")
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'invalid',
            "Invalid XFO setting should be in issues")

        self._test_expecting_codes(issues,
            ['XFO-1'],
            "XFO is not properly set detected.")

    def test_xfo_mark_invalid_when_scheme_is_missing(self):
        resp = self._run(xframe_value="ALLOW-FROM localhost:1234/")
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'invalid',
            "Invalid XFO setting should be in issues")

        self._test_expecting_codes(issues,
            ['XFO-1'],
            "XFO is not properly set detected.")

    def test_xfo_mark_invalid_on_random_value_value(self):
        resp = self._run(xframe_value="foo")
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'invalid',
            "Invalid X-Frame-Options value is set should be in issues")

        self._test_expecting_codes(issues,
            ['XFO-1'],
            "Expecting invalid XFO value detected.")
