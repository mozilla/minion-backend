# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import pprint

from base import BACKEND_KEY, BASE, _call, TestAPIBaseClass

class TestPlanAPIs(TestAPIBaseClass):

    PLAN = { "name": "test",
                      "description": "Test",
                      "workflow": [ { "plugin_name": "minion.plugins.basic.AlivePlugin",
                                      "description": "Test if the site is alive",
                                      "configuration": { "foo": "bar" }
                                      } ] }
    def _create_plan(self, plan):
        res1 = self.create_user(email=self.email)
        res2 = self.create_group(users=[self.email,], group_name='test_group')
        res3 = self.create_plan(plan)
        res4 = self.create_site(plans=['test'], groups=['test_group'])
        return res3

    def assertTestPlanIsReturned(self, plan):
        self.assertEqual("test", plan["name"])
        self.assertEqual("Test", plan["description"])
        self.assertEqual(1, len(plan["workflow"]))
        self.assertEqual("Test if the site is alive", plan["workflow"][0]["description"])
        self.assertEqual({"foo": "bar"}, plan["workflow"][0]["configuration"])
        self.assertEqual("minion.plugins.basic.AlivePlugin", plan["workflow"][0]["plugin_name"])

    def test_create_plan_and_get_plan(self):
        # bootstrap all steps needed to create a plan
        r = self._create_plan(self.PLAN)

        self.assertSuccessfulResponse(r)
        # Check if we got a valid plan back
        j  = r.json()
        plan = j["plan"]
        self.assertTestPlanIsReturned(plan)

        # Check if we can retrieve the plan we just created
        r = self.get_plan("test", email=self.email)
        self.assertSuccessfulResponse(r)
        j  = r.json()
        plan = j["plan"]
        self.assertTestPlanIsReturned(plan)

    def test_get_plan_without_email(self):
        res1 = self._create_plan(self.PLAN)
        res2 = self.get_plan('test')
        self.assertSuccessfulResponse(res2)
        self.assertEqual("test", res2.json()['plan']['name'])

    def test_all_plans_with_email(self):
        # import a plan named 'basic' into the database directly
        self.import_plan()
        # create a plan associate to self.email user
        res1 = self._create_plan(self.PLAN)
        res2 = self.get_plans(email=self.email)
        self.assertSuccessfulResponse(res2)
        plans = res2.json()['plans']
        self.assertTestPlanIsReturned(plans[1])

    def test_all_plans_without_email(self):
        # import a plan named 'basic' into the database directly
        self.import_plan()
        # create a plan associate to self.email user
        res1 = self._create_plan(self.PLAN)
        res2 = self.get_plans()
        self.assertSuccessfulResponse(res2)
        self.assertEqual(True, "plans" in res2.json().keys())
        self.assertEqual(2, len(res2.json()['plans']))
        self.assertEqual('basic', res2.json()['plans'][0]['name'])
        self.assertTestPlanIsReturned(res2.json()['plans'][1])

    def test_create_invalid_plugin_plan(self):
        # Check /plans return invalid-plan-exists when plugin is not
        # importable.  Create a plan
        c = { "name": "test",
              "description": "Test",
              "workflow": [ { "plugin_name": "minion.plugins.basic.Cheeseburger",
                              "description": "Test if the site is cheeseburger",
                              "configuration": { "foo": "bar" }
                              } ] }
        resp = self._create_plan(c)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['reason'], 'invalid-plan-exists')

    def test_create_plan_without_required_field(self):
        # Check /plans return invalid-plan-exists when plan submitted
        #does not contain plugin_name.  Create a plan
        c = { "name": "test",
              "description": "Test",
              "workflow": [ {"description": "Test if the site is cheeseburger",
                              "configuration": { "foo": "bar" }
                              } ] }
        resp = self._create_plan(c)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['reason'], 'invalid-plan-exists')

    def test_create_plan_without_proper_structure(self):
        # Check /plans return invalid-plan-exists when plan submitted
        # does not contain proper structure.  Create a plan
        c = { "name": "test",
              "description": "Test",
              "workflow": []}
        resp = self._create_plan(c)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['reason'], 'invalid-plan-exists')

    def test_delete_plan(self):
        r = self._create_plan(self.PLAN)
        self.assertSuccessfulResponse(r)
        # Delete the plan
        r = self.delete_plan('test')
        self.assertSuccessfulResponse(r)
        # Make sure the plan is gone
        r = self.get_plan("test", email=self.email)
        self.assertSuccessfulResponse(r, success=False, reason='Plan does not exist.')

    def test_delete_unknown_plan(self):
        r = self.delete_plan('testfoodoesnotexist')
        self.assertSuccessfulResponse(r, success=False, reason='no-such-plan')

    def test_update_plan(self):
        r = self._create_plan(self.PLAN)
        self.assertSuccessfulResponse(r)
        # Update the plan
        u = { "description": "Changed Test",
              "workflow": [ { "plugin_name": "minion.plugins.basic.XFrameOptionsPlugin",
                              "description": "Test if the site has an X-Frame-Options header",
                              "configuration": { "require": "DENY" } } ] }
        r = self.update_plan("test", u)
        self.assertSuccessfulResponse(r)
        # Make sure the plan has changed
        r = self.get_plan("test", self.email)
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
        self.assertEqual('Plan does not exist.', r.json()['reason'])
