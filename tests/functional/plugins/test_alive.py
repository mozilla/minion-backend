# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

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

    @classmethod
    def setUpClass(cls):
        super(TestAlivePlugin, cls).setUpClass()
        cls.pname = 'AlivePlugin'
        cls.plugin_class = AlivePlugin()

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
        resp = self._run(api="/404")
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
        resp = self._run(params={"timeout":True})
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
