# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from base import (TestAPIBaseClass, Plugins)

class TestPluginAPIs(TestAPIBaseClass):

    def test_get_built_in_plugins(self):
        resp = Plugins().get()

        self.assertEqual(resp.json()["success"], True)
        self.assertEqual(set(resp.json().keys()),
            set(["success", "plugins"]))

        expected_plugin_names = ["Alive", "XFrameOptions", 
            "HSTS",  "XContentTypeOptions", "XXSSProtection",
            "ServerDetails",  "Robots", "CSP"]

        names_from_test = [plugin['name'] for plugin in resp.json()['plugins']]
        for name in expected_plugin_names:
            self.assertEqual(True, name in names_from_test,
                msg={"Plugin {name} should exists".format(name=name)})

        # check following keys are returned for each plugin
        for plugin in resp.json()['plugins']:
            self.assertEqual(set(plugin.keys()),
                set(["class", "name", "version", "weight"]),
                msg={"Plugin {name} should have class,name,version,weight defined.".format(
                        name=plugin["name"])})        
