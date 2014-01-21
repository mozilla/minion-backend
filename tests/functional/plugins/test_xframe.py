# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from flask import make_response, request

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

    @classmethod
    def setUpClass(cls):
        super(TestXFrameOptionsPlugin, cls).setUpClass()
        cls.pname = "XFrameOptionsPlugin"
        cls.plugin_class = XFrameOptionsPlugin()

    def test_xfo_not_set(self):
        resp = self._run()
        issues = self._get_issues(resp)
        self._test_expecting_codes(issues,
            ['XFO-2'],
            "XFO is not set detected.")

    def test_set_xfo_with_same_origin(self):
        resp = self._run(params={"xframe-value": "SAMEORIGIN"})
        issues = self._get_issues(resp)
        self._test_expecting_codes(issues,
            ['XFO-0'],
            "XFO is properly set detected.")

    def test_set_xfo_with_deny(self):
        resp = self._run(params={"xframe-value": "DENY"})
        issues = self._get_issues(resp)
        self._test_expecting_codes(issues,
            ['XFO-0'],
            "XFO is properly set detected.")

    def test_set_xfo_with_allow_from(self):
        resp = self._run(params={"xframe-value": "ALLOW-FROM http://localhost:1234/"})
        issues = self._get_issues(resp)
        self._test_expecting_codes(issues,
            ['XFO-0'],
            "XFO is properly set detected.")

    def test_xfo_mark_invalid_if_colon_append_to_allow_from(self):
        resp = self._run(params={"xframe-value": "ALLOW-FROM: http://localhost:1234/"})
        issues = self._get_issues(resp)
        self._test_expecting_codes(issues,
            ['XFO-1'],
            "XFO is not properly set detected.")

    def test_xfo_mark_invalid_when_scheme_is_missing(self):
        resp = self._run(params={"xframe-value": "ALLOW-FROM localhost:1234/"})
        issues = self._get_issues(resp)
        self._test_expecting_codes(issues,
            ['XFO-1'],
            "XFO is not properly set detected.")

    def test_xfo_mark_invalid_on_random_value_value(self):
        resp = self._run(params={"xframe-value": "foo"})
        issues = self._get_issues(resp)
        self._test_expecting_codes(issues,
            ['XFO-1'],
            "Expecting invalid XFO value detected.")
