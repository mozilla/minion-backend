# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import pprint

from minion.backend.views.base import BUILTIN_PLUGINS, TEST_PLUGINS

from base import BACKEND_KEY, BASE, _call, TestAPIBaseClass

class TestPluginAPIs(TestAPIBaseClass):

    def test_get_built_in_plugins(self):
        resp = self.get_plugins()

        self.assertEqual(200, resp.status_code)
        # check top-leve keys agreement
        expected_top_keys = ('success', 'plugins',)
        self._test_keys(resp.json().keys(), expected_top_keys)

        expected_plugin_names = ["Alive", "XFrameOptions", 
            "HSTS",  "XContentTypeOptions", "XXSSProtection",
            "ServerDetails",  "Robots", "CSP"]
        plugin_names = [plugin['name'] for plugin in resp.json()['plugins']]
        matches = 0
        for name in expected_plugin_names:
            if name in plugin_names:
                matches += 1
        self.assertEqual(8, matches)

        # check following keys are returned for each plugin
        expected_inner_keys = ('class', 'name', 'version', 'weight')
        for plugin in resp.json()['plugins']:
            self._test_keys(plugin.keys(), expected_inner_keys)

