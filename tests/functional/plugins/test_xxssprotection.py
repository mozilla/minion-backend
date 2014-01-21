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
from minion.plugins.basic import XXSSProtectionPlugin

@test_app.route('/test')
def endpoint():
    value = request.args.get("xxss-value")
    res = make_response("")
    if value:
        res.headers['X-XSS-Protection'] = value
    return res

class TestXXSSProtectionPlugin(TestPluginBaseClass):
    __test__ = True
    Issue = namedtuple('Issue', 'code summary severity')
    XXSS = XXSSProtectionPlugin()

    @classmethod
    def setUpClass(cls):
        super(TestXXSSProtectionPlugin, cls).setUpClass()
        cls.pname = 'XXSSProtectionPlugin'

    def _get_summary(self, key, fill_with=None):
        _summary = self.XXSS.REPORTS[key]['Summary']
        if fill_with:
            return _summary.format(**fill_with)
        else:
            return _summary

    def _run(self, xxss_value=None):
        API = "http://localhost:1234/test"
        r = requests.Request('GET', API,
            params={"xxss-value": xxss_value}).prepare()
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

    def test_xxssplugin_set_1_and_mode_block(self):
        resp = self._run(xxss_value="1; mode=block")
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'set',
            "X-XSS-Protection is set should be in issues")

        self._test_expecting_codes(
            issues,
            ['XXSSP-0'],
            "X-XSS-Protection is set")

    def test_xxssplugin_set_1_without_mode_block_is_invalid(self):
        resp = self._run(xxss_value="1")
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'invalid',
            "X-XSS-Protection set 1 without mode=block is invalid should be in issues")

        self._test_expecting_codes(
            issues,
            ['XXSSP-1'],
            "X-XSS-Protection invalid setting is detected")

    def test_xxssplugin_set_random_invalid_value(self):
        resp = self._run(xxss_value="foobar")
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'invalid',
            "X-XSS-Protection set invalid random value should be in issues")

        self._test_expecting_codes(
            issues,
            ['XXSSP-1'],
            "X-XSS-Protection invalid setting is detected")

    def test_xxssplugin_set_0_disable(self):
        resp = self._run(xxss_value="0")
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'disabled',
            "X-XSS-Protection set 0 disable protection should be in issues")

        self._test_expecting_codes(
            issues,
            ['XXSSP-3'],
            "X-XSS-Protection is disabled")

    def test_xxssplugin_not_set(self):
        resp = self._run()
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'not-set',
            "X-XSS-Protection is not set should be in issues")

        self._test_expecting_codes(
            issues,
            ['XXSSP-2'],
            "Expecting X-XSS-Protection header not present")

