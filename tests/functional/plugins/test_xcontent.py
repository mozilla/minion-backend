# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from base import TestPluginBaseClass
from minion.plugins.basic import XContentTypeOptionsPlugin

class TestXContentTypeOptionsPlugin(TestPluginBaseClass):
    __test__ = True

    @classmethod
    def setUpClass(cls):
        super(TestXContentTypeOptionsPlugin, cls).setUpClass("xcontent.py")
        cls.pname = "XContentTypeOptionsPlugin"
        cls.plugin_class = XContentTypeOptionsPlugin()

    def test_xcontent_set_nonsniff(self):
        resp = self._run(params={"xcontent-value": "nosniff"})
        issues = self._get_issues(resp)
        self._test_expecting_codes(
            issues,
            ['XCTO-0'],
            "Expecting XContentTypeOptions set properly")

    def test_xcontent_set_invalid_value(self):
        resp = self._run(params={"xcontent-value": "foobar"})
        issues = self._get_issues(resp)
        self._test_expecting_codes(
            issues,
            ['XCTO-1'],
            "Expecting XContentTypeOptions not set properly")

    def test_xcontent_not_se(self):
        resp = self._run()
        issues = self._get_issues(resp)
        self._test_expecting_codes(
            issues,
            ['XCTO-2'],
            "Expecting XContentTypeOptions not set")
