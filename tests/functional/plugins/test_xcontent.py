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
from minion.plugins.basic import XContentTypeOptionsPlugin

@test_app.route('/test')
def endpoint():
    value = request.args.get("xcontent-value")
    res = make_response("")
    if value:
        res.headers['X-Content-Type-Options'] = value
    return res

class TestXContentTypeOptionsPlugin(TestPluginBaseClass):
    __test__ = True
    Issue = namedtuple('Issue', 'code summary severity')
    XContent = XContentTypeOptionsPlugin()

    @classmethod
    def setUpClass(cls):
        super(TestXContentTypeOptionsPlugin, cls).setUpClass()
        cls.pname = "XContentTypeOptionsPlugin"

    def _get_summary(self, key, fill_with=None):
        _summary = self.XContent.REPORTS[key]['Summary']
        if fill_with:
            return _summary.format(**fill_with)
        else:
            return _summary

    def _run(self, xcontent_value=None):
        API = "http://localhost:1234/test"
        r = requests.Request('GET', API,
            params={"xcontent-value": xcontent_value}).prepare()
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

    def test_xcontent_set_nonsniff(self):
        resp = self._run(xcontent_value="nosniff")
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            "set",
            "Expecting XContentTypeOptions set properly with nosniff in issues")
        self._test_expecting_codes(
            issues,
            ['XCTO-0'],
            "Expecting XContentTypeOptions set properly")

    def test_xcontent_set_invalid_value(self):
        resp = self._run(xcontent_value="foobar")
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            "invalid",
            "Expecting XContentTypeOptions found invalid setting in issues")
        self._test_expecting_codes(
            issues,
            ['XCTO-1'],
            "Expecting XContentTypeOptions not set properly")

    def test_xcontent_not_se(self):
        resp = self._run()
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            "not-set",
            "Expecting XContentTypeOptions not set in issues")
        self._test_expecting_codes(
            issues,
            ['XCTO-2'],
            "Expecting XContentTypeOptions not set")
