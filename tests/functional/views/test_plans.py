# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import pprint

from minion.backend.api import BUILTIN_PLUGINS, TEST_PLUGINS
from base import BACKEND_KEY, BASE, _call, TestAPIBaseClass

class TestPlanAPIs(TestAPIBaseClass):
    def setUp(self):
        super(TestPlanAPIs, self).setUp()
        self.import_plan()

    def test_get_plans(self):
        resp = self.get_plans()
        self.assertEqual(200, resp.status_code)
        expected_top_keys = ('success', 'plans')
        self._test_keys(resp.json().keys(), expected_top_keys)
        expected_inner_keys = ('name', 'description')
        self._test_keys(resp.json()['plans'][0].keys(), expected_inner_keys)
        self.assertEqual(resp.json()['plans'][0]['name'], "basic")
        self.assertEqual(resp.json()['plans'][0]['description'], "Run basic tests")

    def test_get_plan(self):
        resp = self.get_plan('basic')
        self.assertEqual(200, resp.status_code)

    def test_create_plan(self):
        # Create a plan
        c = { "name": "test",
              "description": "Test",
              "workflow": [ { "plugin_name": "minion.plugins.basic.AlivePlugin",
                              "description": "Test if the site is alive",
                              "configuration": { "foo": "bar" }
                              } ] }
        r = self.create_plan(c)
        self.assertSuccessfulResponse(r)
        # Check if we got a valid plan back
        j  = r.json()
        plan = j["plan"]
        self.assertEqual("test", plan["name"])
        self.assertEqual("Test", plan["description"])
        self.assertEqual(1, len(plan["workflow"]))
        self.assertEqual("Test if the site is alive", plan["workflow"][0]["description"])
        self.assertEqual({"foo": "bar"}, plan["workflow"][0]["configuration"])
        self.assertEqual("minion.plugins.basic.AlivePlugin", plan["workflow"][0]["plugin_name"])
        # Check if we can retrieve the plan we just created
        r = self.get_plan("test")
        self.assertSuccessfulResponse(r)
        j  = r.json()
        plan = j["plan"]
        self.assertEqual("test", plan["name"])
        self.assertEqual("Test", plan["description"])
        self.assertEqual(1, len(plan["workflow"]))
        self.assertEqual("Test if the site is alive", plan["workflow"][0]["description"])
        self.assertEqual({"foo": "bar"}, plan["workflow"][0]["configuration"])
        self.assertEqual("minion.plugins.basic.AlivePlugin", plan["workflow"][0]["plugin_name"])



    def test_create_invalid_plugin_plan(self):
        """ Check /plans return invalid-plan-exists when plugin is not importable. """
        # Create a plan
        c = { "name": "test",
              "description": "Test",
              "workflow": [ { "plugin_name": "minion.plugins.basic.Cheeseburger",
                              "description": "Test if the site is cheeseburger",
                              "configuration": { "foo": "bar" }
                              } ] }
        resp = self.create_plan(c)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['reason'], 'invalid-plan-exists')

    def test_create_plan_without_required_field(self):
        """ Check /plans return invalid-plan-exists when plan submitted does
        not contain plugin_name. """
        # Create a plan
        c = { "name": "test",
              "description": "Test",
              "workflow": [ {"description": "Test if the site is cheeseburger",
                              "configuration": { "foo": "bar" }
                              } ] }
        resp = self.create_plan(c)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['reason'], 'invalid-plan-exists')

    def test_create_plan_without_proper_structure(self):
        """ Check /plans return invalid-plan-exists when plan submitted does
        not contain proper structure. """
        # Create a plan
        c = { "name": "test",
              "description": "Test",
              "workflow": []}
        resp = self.create_plan(c)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['reason'], 'invalid-plan-exists')

    def test_delete_plan(self):
        # Create a plan
        c = { "name": "test",
              "description": "Test",
              "workflow": [ { "plugin_name": "minion.plugins.basic.AlivePlugin",
                              "description": "Test if the site is alive",
                              "configuration": { "foo": "bar" }
                              } ] }
        r = self.create_plan(c)
        self.assertSuccessfulResponse(r)
        # Delete the plan
        r = self.delete_plan('test')
        self.assertSuccessfulResponse(r)
        # Make sure the plan is gone
        r = self.get_plan("test")
        self.assertSuccessfulResponse(r, success=False, reason='no-such-plan')

    def test_delete_unknown_plan(self):
        r = self.delete_plan('testfoodoesnotexist')
        self.assertSuccessfulResponse(r, success=False, reason='no-such-plan')

    def test_update_plan(self):
        # Create a plan
        c = { "name": "test",
              "description": "Test",
              "workflow": [ { "plugin_name": "minion.plugins.basic.AlivePlugin",
                              "description": "Test if the site is alive",
                              "configuration": { "foo": "bar" }
                              } ] }
        r = self.create_plan(c)
        self.assertSuccessfulResponse(r)
        # Update the plan
        u = { "description": "Changed Test",
              "workflow": [ { "plugin_name": "minion.plugins.basic.XFrameOptionsPlugin",
                              "description": "Test if the site has an X-Frame-Options header",
                              "configuration": { "require": "DENY" } } ] }
        r = self.update_plan("test", u)
        self.assertSuccessfulResponse(r)
        # Make sure the plan has changed
        r = self.get_plan("test")
        self.assertSuccessfulResponse(r)
        j  = r.json()
        plan = j["plan"]
        self.assertEqual("test", plan["name"])
        self.assertEqual("Changed Test", plan["description"])
        self.assertEqual(1, len(plan["workflow"]))
        self.assertEqual("Test if the site has an X-Frame-Options header", plan["workflow"][0]["description"])
        self.assertEqual({"require": "DENY"}, plan["workflow"][0]["configuration"])
        self.assertEqual("minion.plugins.basic.XFrameOptionsPlugin", plan["workflow"][0]["plugin_name"])

    def test_delete_unknown_plan(self):
        r = self.delete_plan('testfoodoesnotexist')
        self.assertSuccessfulResponse(r, success=False, reason='no-such-plan')

class TestPluginAPIs(TestAPIBaseClass):

    def test_get_built_in_plugins(self):
        resp = self.get_plugins()

        self.assertEqual(200, resp.status_code)
        # check top-leve keys agreement
        expected_top_keys = ('success', 'plugins',)
        self._test_keys(resp.json().keys(), expected_top_keys)

        # num of total built-in plugins should match
        plugins_count = len(BUILTIN_PLUGINS)
        self.assertEqual(plugins_count, len(resp.json()['plugins']))
        # check following keys are returned for each plugin
        expected_inner_keys = ('class', 'name', 'version', 'weight')
        for plugin in resp.json()['plugins']:
            self._test_keys(plugin.keys(), expected_inner_keys)
