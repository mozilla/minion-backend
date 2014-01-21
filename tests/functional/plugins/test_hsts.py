# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from flask import make_response, request

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

    @classmethod
    def setUpClass(cls):
        super(TestHSTSPlugin, cls).setUpClass(tls=True)
        cls.pname = "HSTSPlugin"
        cls.plugin_class = HSTSPlugin()


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
        resp = self.run_plugin(self.pname, "https://mozillalabs.com")
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
        resp = self.run_plugin(self.pname, "https://google.com")
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            "not-set",
            "HSTS is not set should be in issues.")
        self._test_expecting_codes(
            issues,
            ["HSTS-2"],
            "Expecting HSTS is not set")
