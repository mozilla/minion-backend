# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from flask import make_response, request

from base import TestPluginBaseClass, test_app
from minion.plugins.basic import ServerDetailsPlugin

@test_app.route('/test')
def endpoint():
    headers = request.args.getlist("headers")
    values = request.args.getlist("values")

    res = make_response("")
    if headers and values:
        _headers = dict(zip(headers, values))
        for name, value in _headers.items():
            res.headers[name] = value
    return res

class TestServerDetailsPlugin(TestPluginBaseClass):
    __test__ = True

    @classmethod
    def setUpClass(cls):
        super(TestServerDetailsPlugin, cls).setUpClass()
        cls.pname = "ServerDetailsPlugin"
        cls.plugin_class = ServerDetailsPlugin()

    def test_serverdetails_expose_powered_by(self):
        resp = self._run(params={"headers":["X-Powered-By"], "values":["PHP/5.2.6"]})
        issues = self._get_issues(resp)

        self._test_expecting_codes(
            issues,
            ['SD-0', 'SD-0'],
            "X-Powered-By is set")

    def test_serverdetails_expose_all(self):
        resp = self._run(
            params={"headers": ["Server", "X-Powered-By", "X-AspNet-Version",
                     "X-AspNetMvc-Version", "X-Backend-Server"],
                    "values":  ["PyServer", "PHP/5.2.6", "5.0.111212", "4.0", "foobar-server"]})

        issues = self._get_issues(resp)
        self._test_expecting_codes(
            issues,
            ['SD-0', 'SD-0', 'SD-0', 'SD-0', 'SD-0'],
            "Server, X-Powered-By, X-AspNet-Version, X-AspNetMvc-Version, X-Backend-Server are detected.")
