# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import unittest

from minion.plugins.basic import RobotsPlugin

class TestRobotsPluginValidator(unittest.TestCase):
    def _call(self, fname):
        with open('static/%s'%fname, 'r') as f:
            valid = RobotsPlugin().validator(f.read())
        return valid

    def test_good_robots(self):
        self.assertEqual(True, self._call('robots.txt'))

    def test_robots_with_violation(self):
        self.assertEqual(False, self._call('bad-robots.txt'))

    def test_robots_with_syntax_error(self):
        self.assertEqual(False, self._call('error-robots.txt'))
