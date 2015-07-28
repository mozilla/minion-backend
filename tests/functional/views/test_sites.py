# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from base import (TestAPIBaseClass, User, Users, Site, Sites, Group, Plan)

class TestSitesAPIs(TestAPIBaseClass):
    TEST_PLAN = { "name": "test",
                      "description": "Test",
                      "workflow": [ { "plugin_name": "minion.plugins.basic.AlivePlugin",
                                      "description": "Test if the site is alive",
                                      "configuration": { "foo": "bar" }
                                      } ] }

    expected_inner_keys = ('id', 'url', 'plans', 'created', 'verification', "groups")

    def create_plan(self):
        self.plan = Plan(self.TEST_PLAN)
        res = self.plan.create()
        self.assertEqual(res.json()["success"], True)
        self.user = User(self.email)
        self.user.create()
        self.site = Site(self.target_url, plans=[self.plan.plan["name"]])

    def setUp(self):
        super(TestSitesAPIs, self).setUp()
        self.create_plan()

    def test_create_site_without_verifying(self):
        group = Group(self.group_name)
        group.create()
        
        site = Site(self.target_url, groups=[group.group_name])
        res = site.create(verify=False)
        self.assertEqual(set(res.json()['site'].keys()),
            set(self.expected_inner_keys))
        self.assertEqual(res.json()['site']['url'], site.url)
        self.assertEqual(res.json()['site']['plans'], [])
        self.assertEqual(res.json()['site']['verification']['enabled'], False)
        self.assertEqual(res.json()['site']['verification']['value'], None)

    def test_create_site_with_verifying(self):
        group = Group(self.group_name)
        group.create()
        site = Site(self.target_url, groups=[group.group_name])

        res = site.create(verify=True)
        self.assertEqual(res.json()['site']['verification']['enabled'], True)
        self.assertTrue(res.json()['site']['verification']['value'])

    def test_create_duplicate_site(self):
        group = Group(self.group_name)
        group.create()
        site = Site(self.target_url, groups=[group.group_name])
        res1 = site.create()
        res2 = site.create()
        self.assertEqual(res2.json()['success'], False)
        self.assertEqual(res2.json()['reason'], 'site-already-exists')

    def test_create_site_with_ip(self):
        group = Group(self.group_name)
        group.create()

        site = Site(self.target_ip, groups=[group.group_name])
        res = site.create()
        self.assertEqual(set(res.json()['site'].keys()),
            set(self.expected_inner_keys))
        self.assertEqual(res.json()['site']['url'], site.url)
        self.assertEqual(res.json()['site']['plans'], [])

    def test_create_site_with_cidr_network(self):
        group = Group(self.group_name)
        group.create()

        site = Site(self.target_cidr, groups=[group.group_name])
        res = site.create()
        self.assertEqual(set(res.json()['site'].keys()),
            set(self.expected_inner_keys))
        self.assertEqual(res.json()['site']['url'], site.url)
        self.assertEqual(res.json()['site']['plans'], [])

    def test_create_site_with_bad_format(self):
        group = Group(self.group_name)
        group.create()

        site = Site(self.target_badurl, groups=[group.group_name])
        res = site.create()
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['reason'], 'invalid-url')

    def test_get_all_sites(self):
        group = Group(self.group_name)
        group.create()
        site = Site(self.target_url, groups=[group.group_name])
        site.create()

        res = Sites().get()
        self.assertEqual(res.json()["success"], True)
        self.assertEqual(set(res.json()['sites'][0].keys()),
            set(self.expected_inner_keys))
        self.assertEqual(res.json()['sites'][0]['url'], site.url)
        self.assertEqual(res.json()['sites'][0]['groups'], site.groups)
        self.assertEqual(res.json()['sites'][0]['plans'], site.plans)

    def test_get_site(self):
        group = Group(self.group_name)
        group.create()

        site = Site(self.target_url, groups=[group.group_name])
        res1 = site.create()
        site_id = res1.json()["site"]["id"]

        res2 = site.get(site_id)
        self.assertEqual(res2.json()["success"], True)
        self.assertEqual(res2.json()['site'], res1.json()['site'])

    def test_get_specific_site_by_url(self):
        group = Group(self.group_name)
        group.create()

        site = Site(self.target_url, groups=[group.group_name])
        res1 = site.create()
        res2 = Sites().get(url=site.url)
        self.assertEqual(len(res2.json()["sites"]), 1)
        self.assertEqual(res2.json()["sites"][0], res1.json()["site"])

    def test_update_site(self):
        group1 = Group("group1")
        group2 = Group("group2")
        group3 = Group("group3")
        group1.create()
        group2.create()
        group3.create()

        site = Site(self.target_url)
        res1 = site.create()
        site_id = res1.json()["site"]["id"]
        # Verify that the new site has no plans and no groups
        self.assertEqual(res1.json()["site"]['plans'], site.plans)
        self.assertEqual(res1.json()["site"]['groups'], site.groups)

        # Update the site, add a plan and group
        res2 = site.update(site_id, groups=[group1.group_name],
            plans=[self.TEST_PLAN["name"]])
        # Verify that the site has these new settings
        res3 = site.get(site_id)
        self.assertEqual(res3.json()["site"]['plans'], [self.TEST_PLAN["name"]])
        self.assertEqual(res3.json()["site"]["groups"], [group1.group_name])
        self.assertEqual(res3.json()["site"]['url'], site.url)

        # Update the site, replace plans and groups
        res4 = site.update(site_id, groups=[group2.group_name, group3.group_name]) # bug #144
        res5 = site.get(site_id)
        self.assertEqual(res5.json()["site"]['plans'], [self.TEST_PLAN["name"]])
        self.assertEqual(set(res5.json()["site"]['groups']), set([group2.group_name, group3.group_name]))
        self.assertEqual(res5.json()["site"]['url'], site.url)

    def test_update_unknown_site(self):
        site = Site(self.target_url)
        res = site.update("e22dbe0c-b958-4050-a339-b9a88fa7cd01",
            plans=["nmap", "zap"], groups=["foo", "bar"])
        self.assertEqual(res.json(), {'success': False, 'reason': 'no-such-site'})

    def test_update_site_with_unknown_group(self):
        site = Site(self.target_url)
        res1 = site.create()
        site_id = res1.json()["site"]["id"]
        res2 = site.update(site_id, groups=["non-existing-group"])
        self.assertEqual(res2.json(), {'success': False, 'reason': 'unknown-group'})

    def test_update_site_with_unknown_plan(self):
        site = Site(self.target_url)
        res1 = site.create()
        site_id = res1.json()["site"]["id"]
        res2 = site.update(site_id, plans=["non-existing-plan"])
        self.assertEqual(res2.json(), {'success': False, 'reason': 'unknown-plan'})

    def test_update_only_change_plans(self):
        group = Group(self.group_name)
        group.create()
        site = Site(self.target_url, groups=[group.group_name],
            plans=[self.TEST_PLAN["name"]])
        res1 = site.create()
        site_id = res1.json()["site"]["id"]
        self.assertEqual(res1.json()["success"], True)
        self.assertEqual(res1.json()["site"]["plans"], [self.TEST_PLAN["name"]])
        self.assertEqual(res1.json()["site"]["groups"], [group.group_name])

        res2 = site.update(site_id, plans=[self.TEST_PLAN["name"]])
        self.assertEqual(res2.json()["success"], True)
        self.assertEqual(set(res2.json()["site"]["plans"]),
            set([self.TEST_PLAN["name"], self.TEST_PLAN["name"]]))
        self.assertEqual(res2.json()["site"]["groups"], [group.group_name])

    def test_update_only_change_groups(self):
        group1 = Group("group1")
        group1.create()
        group2 = Group("group2")
        group2.create()

        site = Site(self.target_url, groups=[group1.group_name],
            plans=[self.TEST_PLAN["name"]])
        res1 = site.create()
        site_id = res1.json()["site"]["id"]
        self.assertEqual(res1.json()["success"], True)
        self.assertEqual(res1.json()["site"]["plans"], [self.TEST_PLAN["name"]])
        self.assertEqual(res1.json()["site"]["groups"], [group1.group_name])

        """
        res2 = site.update(site_id, groups=[group2.group_name])
        self.assertEqual(res2.json()["success"], True)
        self.assertEqual(set(res2.json()["site"]["groups"]),
            set([group1.group_name, group2.group_name]))
        self.assertEqual(res2.json()["site"]["plans"], [group.group_name])
        """
