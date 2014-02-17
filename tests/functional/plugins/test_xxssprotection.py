# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from base import TestPluginBaseClass
from minion.plugins.basic import XXSSProtectionPlugin

class TestXXSSProtectionPlugin(TestPluginBaseClass):
    __test__ = True

    @classmethod
    def setUpClass(cls):
        super(TestXXSSProtectionPlugin, cls).setUpClass("xxss_protection.py")
        cls.pname = 'XXSSProtectionPlugin'
        cls.plugin_class = XXSSProtectionPlugin()

    def test_xxssplugin_set_1_and_mode_block(self):
        resp = self._run(params={"xxss-value": "1; mode=block"})
        issues = self._get_issues(resp)
        self._test_expecting_codes(
            issues,
            ['XXSSP-0'],
            "X-XSS-Protection is set")

    def test_xxssplugin_set_1_without_mode_block_is_invalid(self):
        resp = self._run(params={"xxss-value": "1"})
        issues = self._get_issues(resp)
        self._test_expecting_codes(
            issues,
            ['XXSSP-1'],
            "X-XSS-Protection invalid setting is detected")

    def test_xxssplugin_set_random_invalid_value(self):
        resp = self._run(params={"xxss-value" : "foobar"})
        issues = self._get_issues(resp)
        self._test_expecting_codes(
            issues,
            ['XXSSP-1'],
            "X-XSS-Protection invalid setting is detected")

    def test_xxssplugin_set_0_disable(self):
        resp = self._run(params={"xxss-value": "0"})
        issues = self._get_issues(resp)
        self._test_expecting_codes(
            issues,
            ['XXSSP-3'],
            "X-XSS-Protection is disabled")

    def test_xxssplugin_not_set(self):
        resp = self._run()
        issues = self._get_issues(resp)
        self._test_expecting_codes(
            issues,
            ['XXSSP-2'],
            "Expecting X-XSS-Protection header not present")

