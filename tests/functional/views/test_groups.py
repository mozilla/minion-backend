# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from base import (TestAPIBaseClass, User, Users, Group, Groups, Plan, Site, Reports)

class TestGroupAPIs(TestAPIBaseClass):
    TEST_PLAN = { "name": "test",
                 "description": "Test",
                 "workflow": [ { "plugin_name": "minion.plugins.basic.AlivePlugin",
                                 "description": "Test if the site is alive",
                                 "configuration": { "foo": "bar" }
                                 } ] }

    expected_inner_keys = ('id', 'created', 'name', 'description', "users", "sites")

    def test_create_group(self):
        group = Group(self.group_name, description=self.group_description)
        res = group.create()
        self.assertEqual(res.json()["success"], True)
        self.assertEqual(set(res.json()["group"].keys()),
            set(self.expected_inner_keys))
        self.assertEqual(res.json()['group']['name'], self.group_name)
        self.assertEqual(res.json()['group']['description'], self.group_description)

    def test_create_duplicate_group(self):
        group = Group(self.group_name)
        group.create()

        # now try to re-create the same leads to duplication error
        res = group.create()

        self.assertEqual(res.json()['success'], False)
        self.assertEqual(res.json()['reason'], 'group-already-exists')

    # issue#132
    def test_create_group_without_group_name(self):
        group = Group(None)
        res = group.create() 
        self.assertEqual(res.json()['success'], False)
        self.assertEqual(res.json()['reason'], 'name-field-is-required')

    #issue#132
    def test_create_group_with_non_existing_user(self):
        group = Group(self.group_name, users=["user1", "user2"])
        res = group.create()
        self.assertEqual(res.json()['success'], False)
        self.assertEqual(res.json()['reason'], 'user user1 does not exist')

    #issue#132
    def test_create_group_with_non_existing_site(self):
        group = Group(self.group_name, sites=["https://example1.com"])
        res = group.create()
        self.assertEqual(res.json()['success'], False)
        self.assertEqual(res.json()['reason'], 'site https://example1.com does not exist')

    #issue#132
    def test_create_group_with_existing_user(self):
        bob = User(self.email)
        bob.create()
        alice = User("alice@example.org")
        alice.create()

        group = Group(self.group_name, users=[bob.email, alice.email])
        res = group.create()

        self.assertEqual(res.json()['success'], True)
        self.assertEqual(set(res.json()['group']['users']),
            set([alice.email, bob.email]))

    def test_get_all_groups(self):
        group = Group(self.group_name)
        res1 = group.create()
        res2 = Groups().get()
        self.assertEqual(res2.json()["success"], True)
        self.assertEqual(res2.json()['groups'][0], res1.json()['group'])

    def test_get_group(self):
        user = User(self.email)
        user.create()

        group = Group(self.group_name, description=self.group_description,
            users=[user.email])
        res1 = group.create()

        res2 = group.get()
        self.assertEqual(res2.json()["success"], True)
        self.assertEqual(res2.json()['group']['name'], group.group_name)
        self.assertEqual(res2.json()['group']['description'], group.description)
        self.assertEqual(res2.json()['group']['users'], [user.email])

    # issue #215
    def test_retrieve_issue_status_and_issues_by_group(self):
        # Don't be shock. This test fits here; by querying
        # user and group, we should only be given the latest
        # issue status.

        bob = User(self.email)
        bob.create()

        group1 = Group("group1", users=[bob.email])
        group2 = Group("group2", users=[bob.email])
        res1 = group1.create()
        res2 = group2.create()

        plan = Plan(self.TEST_PLAN)
        plan.create()

        site1 = Site(self.target_url, groups=[group1.group_name],
            plans=[self.TEST_PLAN["name"]])
        site1.create()
        site2 = Site(self.target_url, groups=[group2.group_name],
            plans=[self.TEST_PLAN["name"]])
        site2.create()

        # if we query just test1, should get back only foo.com
        report = Reports()
        res5 = report.get_status(user=bob.email, group_name=group1.group_name)
        r = res5.json()['report']
        self.assertEqual(len(r), 1) # there should just be one dict returned in the list
        self.assertEqual(r[0]['target'], site1.url)

        # if we try it on get_report_issues we should see similar result
        res6 = report.get_issues(user=bob.email, group_name=group1.group_name)
        r = res6.json()['report']
        self.assertEqual(len(r), 1) # there should just be one dict returned in the list
        self.assertEqual(r[0]['target'], site1.url)

    def test_delete_group(self):
        group = Group(self.group_name)
        group.create()
        res = group.delete()
        self.assertEqual(res.json()['success'], True)
        self.assertEqual(set(res.json().keys()), set(["success"]))

    def test_patch_group_add_site(self):
        group = Group(self.group_name)
        res1 = group.create()
        self.assertEqual(res1.json()["success"], True)
        self.assertEqual(res1.json()["group"]["sites"], [])

        res2 = group.update(add_sites=[self.target_url])
        self.assertEqual(set(res2.json().keys()), set(res1.json().keys()))
        self.assertEqual(set(res2.json()['group'].keys()),
            set(res1.json()['group'].keys()))
        self.assertEqual(res2.json()['group']['sites'][0], self.target_url)

    def test_patch_group_remove_site(self):
        group = Group(self.group_name)
        res1 = group.create()
        self.assertEqual(res1.json()["success"], True)
        self.assertEqual(res1.json()["group"]["sites"], [])

        res2 = group.update(add_sites=[self.target_url])
        self.assertEqual(res2.json()['group']['sites'][0], self.target_url)

        res3 = group.update(remove_sites=[self.target_url])
        self.assertEqual(set(res3.json().keys()), set(res2.json().keys()))
        self.assertEqual(set(res3.json()['group'].keys()),
            set(res2.json()['group'].keys()))
        self.assertEqual(res3.json()['group']['sites'], [])

    def test_patch_group_add_user(self):
        bob = User(self.email)
        bob.create()
        group = Group(self.group_name)
        group.create()
        res = group.update(add_users=[bob.email])
        self.assertEqual(res.json()['group']['users'], group.users)

    def test_patch_group_remove_user(self):
        bob = User(self.email)
        bob.create()
        group = Group(self.group_name, users=[bob.email])
        res1 = group.create()
        self.assertEqual(res1.json()["success"], True)
        self.assertEqual(res1.json()["group"]["users"], group.users)

        res2 = group.update(remove_users=[bob.email])
        self.assertEqual(res2.json()['group']['users'], [])
