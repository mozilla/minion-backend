# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from base import (TestAPIBaseClass, User, Site, Group, Plan, Plans)

class TestPlanAPIs(TestAPIBaseClass):

    TEST_PLAN = { "name": "test",
                      "description": "Test",
                      "workflow": [ { "plugin_name": "minion.plugins.basic.AlivePlugin",
                                      "description": "Test if the site is alive",
                                      "configuration": { "foo": "bar" }
                                      } ] }
    def _create_plan(self, plan=None):
        """ Create a plan in Minion and assign
        a site to a group and a user.

        Use Plan(self.TEST_PLAN) to test plan only.
        """

        _plan = plan or self.TEST_PLAN
        self.plan = Plan(_plan)
        resp = self.plan.create()

        self.user = User(self.email)
        self.user.create()
        self.site = Site(self.target_url, plans=[self.plan.plan["name"]])
        self.site.create()
        self.group = Group("testgroup", sites=[self.site.url], users=[self.user.email])
        self.group.create()
        self.plan = Plan(_plan)
        return resp

    def _assert_test_plan(self, plan):
        self.assertEqual("test", plan["name"])
        self.assertEqual("Test", plan["description"])
        self.assertEqual(1, len(plan["workflow"]))
        self.assertEqual("Test if the site is alive", plan["workflow"][0]["description"])
        self.assertEqual({"foo": "bar"}, plan["workflow"][0]["configuration"])
        self.assertEqual("minion.plugins.basic.AlivePlugin", plan["workflow"][0]["plugin_name"])

    def test_create_plan_and_get_plan(self):
        plan = Plan(self.TEST_PLAN)
        res = plan.create()
        self.assertEqual(res.json()["success"], True)
        self._assert_test_plan(res.json()["plan"])

        # Check if we can retrieve the plan we just created
        # retrieve the newly created plan
        res2 = plan.get(plan.plan["name"])
        self.assertEqual(res2.json()["success"], True)
        self._assert_test_plan(res2.json()["plan"])

    def test_get_plan_without_email(self):
        self._create_plan()
        resp = Plans().get(name=self.TEST_PLAN["name"])
        self.assertEqual(len(resp.json()["plans"]), 1)
        self._assert_test_plan(resp.json()["plans"][0])

    def test_find_all_plans_registered_under_an_email(self):
        self._create_plan()
        resp = Plans().get(email=self.user.email)
        self.assertEqual(len(resp.json()["plans"]), 1)
        self._assert_test_plan(resp.json()["plans"][0])

    def test_create_invalid_plugin_plan(self):
        # Check /plans return invalid-plan-exists when plugin is not
        # importable.
        bad_plan = { "name": "test",
                     "description": "Test",
                     "workflow": [ { "plugin_name": "minion.plugins.basic.Cheeseburger",
                                     "description": "Test if the site is cheeseburger",
                                     "configuration": { "foo": "bar" }
                      } ] }
        plan = Plan(bad_plan)
        resp = plan.create()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['reason'], 'invalid-plan-exists')

    def test_create_plan_fail_because_plugin_name_is_missing(self):
        # this plan does not contain plugin_name which is invalid
        bad_plan = { "name": "test",
                     "description": "Test",
                     "workflow": [ {"description": "Test if the site is cheeseburger",
                                    "configuration": { "foo": "bar" }
                    } ] }
        plan = Plan(bad_plan)
        resp = plan.create()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['reason'], 'invalid-plan-exists')

    def test_create_plan_fail_because_workflow_is_empty(self):
        # workflow is entirely missing
        bad_plan = { "name": "test",
                     "description": "Test",
                     "workflow": []}
        plan = Plan(bad_plan)
        resp = plan.create()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['reason'], 'invalid-plan-exists')

    def test_delete_plan(self):
        plan = Plan(self.TEST_PLAN)
        res1 = plan.create()
        self.assertEqual(res1.json()["success"], True)

        # Delete the plan
        res2 = plan.delete(self.TEST_PLAN["name"])
        self.assertEqual(res2.json()["success"], True)

        # Make sure the plan is gone
        res3 = plan.get(self.TEST_PLAN["name"])
        self.assertEqual(res3.json()["success"], False)
        self.assertEqual(res3.json()["reason"], "Plan does not exist")

    def test_delete_nonexistent_plan(self):
        plan = Plan(None)
        resp = plan.delete("nonexistentplan")
        self.assertEqual(resp.json()["success"], False)
        self.assertEqual(resp.json()["reason"], "Plan does not exist.")

    def test_update_plan(self):
        plan = Plan(self.TEST_PLAN)
        resp = plan.create()

        # Update the plan
        new_plan = { "description": "Changed Test",
                     "workflow": [ { "plugin_name": "minion.plugins.basic.XFrameOptionsPlugin",
                                     "description": "Test if the site has an X-Frame-Options header",
                                     "configuration": { "require": "DENY" } } ] }

        res = plan.update(plan.plan["name"], new_plan)
        self.assertEqual(res.json()["success"], True)

        # make a copy of the new plan because we need to fill in the plan name
        _new_plan = dict(new_plan)
        _new_plan["name"] = self.TEST_PLAN["name"]
        # the response contains some unncessary fields, only extract the good one
        _res_plan = {key:value for key,value in res.json()["plan"].items() 
                if key in ("name", "description", "workflow")}
        # the new plan we feed into minion and the one we return from response shoudl match
        self.assertEqual(_res_plan, _new_plan)

        # make sure get gives the same result as well
        res2 = plan.get(self.TEST_PLAN["name"])
        _res2_plan = {key:value for key,value in res2.json()["plan"].items() 
                if key in ("name", "description", "workflow")}
        self.assertEqual(_res2_plan, _new_plan)
