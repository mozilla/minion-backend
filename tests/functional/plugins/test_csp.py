# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from base import TestPluginBaseClass
from minion.plugins.basic import CSPPlugin

class TestCSPPlugin(TestPluginBaseClass):
    __test__ = True

    @classmethod
    def setUpClass(cls):
        super(TestCSPPlugin, cls).setUpClass("csp.py")
        cls.pname = 'CSPPlugin'
        cls.plugin_class = CSPPlugin()

    def test_csp(self):
        resp = self._run(params={"headers": ['csp']})
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'csp-set',
            "CSP is set should be in issues")

        self._test_expecting_codes(issues,
            ['CSP-1', 'CSP-5'],
            "Expecting CSP is set, XCSP is not set and number of unspecified directives")

    def test_no_csp_and_no_xcsp(self):
        resp = self._run()
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'csp-not-set',
            "CSP is not set should be in issues")

        self._test_expecting_codes(
            issues,
            ['CSP-2', 'CSP-5'],
            "CSP is not set and XCSP is not set")

    def test_only_csp_ro_only(self):
        resp = self._run(params={"headers": ['csp-ro']})
        issues = self._get_issues(resp)

        self._test_expecting_summary(
            issues,
            'csp-ro-only-set',
            "CSP-Report-Only is set should be in issues")

        self._test_expecting_codes(
            issues,
            ['CSP-2', 'CSP-3', 'CSP-5'],
            "Expecting CSP is not set, CSP-RO is set and XCSP is not set")

    def test_only_xcsp_is_set(self):
        resp = self._run(params={"headers": ['xcsp']})
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'xcsp-set',
            "XCSP is set should be in issues")

        self._test_expecting_codes(
            issues,
            ['CSP-2', 'CSP-4'],
            "Expecting CSP is not set and XCSP is set.")

    def test_only_xcsp_ro_only(self):
        resp = self._run(params={"headers": ['xcsp-ro']})
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'xcsp-ro-only-set',
            "XCSP-Report-Only is set should be in issues")

        self._test_expecting_codes(
            issues,
            ['CSP-2', 'CSP-5', 'CSP-6'],
            "Expecting CSP and XCSP are not set but XCSP-RO is set")

    def test_csp_and_csp_ro_are_set(self):
        resp = self._run(params={"headers": ['csp', 'csp-ro']})
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'csp-csp-ro-set',
            "Both CSP and CSP-Report-Only are set should be in issues")

        self._test_expecting_codes(
            issues,
            ['CSP-1', 'CSP-5', 'CSP-7'],
            "Expecting CSP, CSP and CSP-RO are set but XCSP is not set")

    def test_xcsp_and_xcsp_ro_are_set(self):
        resp = self._run(params={"headers": ['xcsp', 'xcsp-ro']})
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'xcsp-xcsp-ro-set',
            "Both XCSP and XCSP-Report-Only are set should be in issues")

        self._test_expecting_codes(
            issues,
            ['CSP-2', 'CSP-4', 'CSP-8'],
            "Expecting XCSP, XCSP and XCSP-RO are set but CSP is not set")

    def test_unknown_directive_in_csp_only_header(self):
        resp = self._run(params={"headers": ['csp'],
            "policy": "default-src 'self'; unknown-directive 'self';"})
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'unknown-directive',
            "1 unknown directive should be in issues",
            fill_with={"count": 1})

        self._test_expecting_codes(
            issues,
            ['CSP-1', 'CSP-5', 'CSP-9'],
            "Expecting CSP is set, XCSP is not set and 1 unknown directive")

    def test_csp_deprecated_directive(self):
        resp = self._run(params={"headers": ['csp'],
            "policy": "allow 'self'; xhr-src foobar.com;"})
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'deprecated-directive',
            "2 unknown directive should be in issues",
            fill_with={"count": 2})

        self._test_expecting_codes(
            issues,
            ['CSP-1', 'CSP-5', 'CSP-10'],
            "Expecting CSP is set, XCSP is not set, 2 deprecated directives.")

    def test_none_used_with_other_source_expressions(self):
        resp = self._run(params={"headers": ['csp'],
            "policy": "default-src 'self'; style-src 'self' 'none';"})
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'bad-none',
            "'none' issue should be in issue")

        self._test_expecting_codes(
            issues,
            ['CSP-1', 'CSP-5', 'CSP-11'],
            "Expecting CSP is set, XCSP is not set, and improper use of 'none'")

    def test_inline(self):
        resp = self._run(params={"headers": ['csp'],
            "policy": "default-src 'self'; style-src 'unsafe-inline';"})
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'inline',
            "unsafe-inline is enabled should be in issue")

        self._test_expecting_codes(
            issues,
            ['CSP-1', 'CSP-5', 'CSP-12'],
            "Expecting CSP is set, XCSP is not set, and unsafe-inline is enabled")

    def test_eval(self):
        resp = self._run(params={"headers": ['csp'],
            "policy": "default-src 'self'; script-src 'unsafe-eval';"})
        issues = self._get_issues(resp)
        self._test_expecting_summary(
            issues,
            'eval',
            "unsafe-eval is enabled should be in issue")

        self._test_expecting_codes(
            issues,
            ['CSP-1', 'CSP-5', 'CSP-13'],
            "Expecting CSP is set, XCSP is not set, and unsafe-eval is enabled")
