# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import os
import time

from subprocess import Popen

from base import TestPluginBaseClass
from minion.plugins.basic import RobotsPlugin

class TestRobotsPlugin(TestPluginBaseClass):
    __test__ = True

    @classmethod
    def setUpClass(cls):
        """ We have to launch three ports in order to test this plugin. """

        def run_app(app_file):
            file_path = os.path.join(os.path.dirname(__file__),
                "servers/" + app_file)
            p = Popen(["python", file_path])
            time.sleep(1)
            return p

        cls.server1 = run_app("good_robots.py")
        cls.server2 = run_app("bad_robots.py")
        cls.server3 = run_app("no_robots.py")

        cls.pname = "RobotsPlugin"
        cls.plugin_class = RobotsPlugin()

    @classmethod
    def tearDownClass(cls):
        cls.server1.kill()
        cls.server1.terminate()
        cls.server2.kill()
        cls.server2.terminate()
        cls.server3.kill()
        cls.server3.terminate()
        time.sleep(1)

    def test_valid_robots_file(self):
        # first, assert that the plugin can assert the file from direct link
        resp = self._run(base="http://localhost:1234", api="/robots.txt")
        issues = self._get_issues(resp)
        self._test_expecting_codes(
            issues,
            ['ROBOTS-0'],
            "Expecting found robots.txt and validated")

        # next, assert plugin can ignore paths and make the direct link on its own
        resp = self._run(base="http://localhost:1234", api="/")
        issues = self._get_issues(resp)
        self._test_expecting_codes(
            issues,
            ['ROBOTS-0'],
            "Expecting found robots.txt and validated")

    def test_missing_robots_file(self):
        resp = self._run(base="http://localhost:1236", api="/robots.txt")
        issues = self._get_issues(resp)
        self._test_expecting_codes(
            issues,
            ['ROBOTS-1'],
            "Robots.txt is not found.")

        # like valid robots, plugin should make the direct link on its own
        resp = self._run(base="http://localhost:1236", api="/")
        issues = self._get_issues(resp)
        self._test_expecting_codes(
            issues,
            ['ROBOTS-1'],
            "Robots.txt is not found.")

    def test_invalid_robots_file(self):
        resp = self._run(base="http://localhost:1235", api="/robots.txt")
        issues = self._get_issues(resp)
        self._test_expecting_codes(
            issues,
            ['ROBOTS-2'],
            "Expecting invalid robots.txt detected")

        # like valid robots, plugin should make the direct link on its own
        resp = self._run(base="http://localhost:1235", api="/")
        issues = self._get_issues(resp)
        self._test_expecting_codes(
            issues,
            ['ROBOTS-2'],
            "Expecting invalid robots.txt detected")
