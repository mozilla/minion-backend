# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import requests
import sys
import time
import unittest

from collections import namedtuple
from flask import make_response, request
from base import TestPluginBaseClass, test_app
from minion.plugins.basic import AlivePlugin

@test_app.route('/test')
def endpoint():
    timeout = request.args.get("timeout")
    res = make_response("")

    if timeout:
        time.sleep(5)
        return res
    else:
        return res

class TestAlivePlugin(TestPluginBaseClass):
    __test__ = True
    Alive = AlivePlugin()
    Issue = namedtuple('Issue', 'code summary severity')

    @classmethod
    def setUpClass(cls):
        super(TestAlivePlugin, cls).setUpClass()
        cls.pname = 'AlivePlugin'

    def _get_summary(self, key, fill_with=None):
        _summary = self.Alive.REPORTS[key]['Summary']
        if fill_with:
            return _summary.format(**fill_with)
        else:
            return _summary

    def _run(self, endpoint="/test", headers=None, timeout=None):
        API = "http://localhost:1234" + endpoint
        r = requests.Request('GET', API,
            params={"timeout": timeout}).prepare()
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


    def validate_alive(self, runner_resp, request_resp, expected=None, expectation=True):
        if expectation is True:
            self.assertEqual('FINISHED', runner_resp[2]['data']['state'])
            self.assertEqual('Site is reachable', runner_resp[1]['data']['Summary'])
            self.assertEqual(True, 'The server has responded with 200' in runner_resp[1]['data']['Description'])
            self.assertEqual(200, request_resp.status_code)
        elif expectation == '404':
            self.assertEqual('ABORTED', runner_resp[2]['data']['state'])
            self.assertEqual('Fatal', runner_resp[1]['data']['Severity'])
            self.assertEqual(404, request_resp.status_code)
            self.assertEqual('Site could not be reached', runner_resp[1]['data']['Summary'])
            self.assertEqual(True, 'The server has responded with 404' in runner_resp[1]['data']['Description'])
        elif expectation in (False, 'TIMEOUT'):
            self.assertEqual('ABORTED', runner_resp[2]['data']['state'])
            self.assertEqual('Fatal', runner_resp[1]['data']['Severity'])
            self.assertEqual('Site could not be reached', runner_resp[1]['data']['Summary'])
            self.assertEqual(expected, runner_resp[1]['data']['URLs'][0]['URL'])
            if expectation is False:
                # requests will throw exeception if not connectable
                self.assertEqual(requests.exceptions.ConnectionError, type(request_resp))

    def test_alive_200_return_reachable(self):
        resp = self._run()
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            "good",
            "Site is alive should be in issues")

        self._test_expecting_codes(
            issues,
            ["ALIVE-0"],
            "Expecting to see site is alive.")

    def test_alive_404_return_not_reachable(self):
        resp = self._run(endpoint="/404")
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            "bad",
            "Page is 404 so should not be reachable in issues")

        self._test_expecting_codes(
            issues,
            ["ALIVE-1"],
            "Expecting to see site/page not reachable due to 404.")

    """
    def test_alive_timeout_return_not_reachable(self):
        resp = self._run(timeout=True)
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            "bad",
            "Site timeout so should not be reachable in issues")

        self._test_expecting_codes(
            issues,
            ["ALIVE-1"],
            "Expecting to see site/page not reachable due to timeout.")
    """
