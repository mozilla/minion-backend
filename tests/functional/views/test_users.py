# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from base import (TestAPIBaseClass, Users, User, Group, Groups)

class TestUserAPIs(TestAPIBaseClass):
    expected_inner_keys = ('id', 'created', 'role', 'email', 'status',
        'last_login', "api_key", "name", "groups")

    def assertSMTPReceived(self, actual_msg, user_email, invite_url):
        msgs = actual_msg.split('\n')
        # the first and last elements must be '------- MESSAGE BEGING/END -------'
        # [2] --> From ,  [3] --> To,   [4] --> Subject ,  [5] --> X-Peer,
        # [6] --> len(actual_msg)-2  ---> rest of body
        self.assertEqual(True, user_email in msgs[1])
        self.assertEqual(True, invite_url in '\n'.join(msgs[6:-1]))

    def test_create_user(self):
        res = User(self.email).create()
        self.assertEqual(res.json()["success"], True)
        self.assertEqual(set(res.json()['user'].keys()), set(self.expected_inner_keys))
        self.assertEqual(res.json()['user']['status'], 'active')    # ticket #109

    # issue #128
    def test_login_user(self):
        bob = User(self.email)
        res1 = bob.create()
        res2 = bob.login()
        self.assertEqual(res2.json()['success'], True)
        self.assertEqual(True, res2.json()['user']['last_login'] is not None)

    # issue #128
    def test_login_non_existing_user(self):
        bob = User(self.email)
        res1 = bob.login()
        self.assertEqual(res1.json()['success'], False)
        self.assertEqual(res1.json()['reason'], "user-does-not-exist")
    
    # issue #128
    def test_login_non_active_user(self):
        bob = User(self.email)
        res1 = bob.create()
        # change user to banned
        res2 = bob.update(status="banned")
        res3 = bob.login()
        self.assertEqual(res3.json()['success'], False)
        self.assertEqual(res3.json()['reason'], 'banned')
        
    # ticket #109, #110
    def test_invite_user(self):
        #self.start_smtp()
        bob = User(self.email)
        res = bob.invite()
        self.assertEqual(set(res.json()['user'].keys()), set(self.expected_inner_keys))
        self.assertEqual(res.json()['user']['status'], 'invited')

    # ticket #109, #110
    def test_update_invited_user(self):
        #self.start_smtp()
        bob = User(self.email)
        res1 = bob.invite()
        res2 = bob.update(status="active")
        self.assertEqual(res2.json()['user']['status'], 'active')
        self.assertEqual(res1.json()['user']['status'], 'invited')
        #self.stop_smtp()

    def test_get_user(self):
        group = Group("foo")
        res = group.create()
        self.assertEqual(True, res.json()['success'])
        # Add a user
        bob = User(self.email, name="Bob", groups=["foo"])
        r = bob.create()
        j = r.json()
        self.assertEqual(True, r.json()['success'])

        # Make sure the user stored in the db is correct
        r = User(self.email).get()
        j = r.json()
        self.assertEqual(True, j['success'])
        self.assertEqual(self.email, j['user']['email'])
        self.assertEqual("Bob", j['user']['name'])
        self.assertEqual(['foo'], j['user']['groups'])
        self.assertEqual('user', j['user']['role'])

    def test_get_all_users(self):
        bob = User(self.email)
        bob.create()

        res = Users().get()
        _expected = list(self.expected_inner_keys) + ["sites"]
        self.assertEqual(set(res.json()['users'][0].keys()),
            set(_expected))
        self.assertEqual(1, len(res.json()['users']))

    def test_delete_user(self):
        # Create a user
        bob = User(self.email)
        r = bob.create()
        j = r.json()
        self.assertEqual(True, j['success'])
        # Delete the user
        r = bob.delete()
        self.assertEqual({'success': True}, r.json())
        # Make sure the user is gone
        r = bob.delete()
        self.assertEqual({'success': False, 'reason': 'no-such-user'}, r.json())

    def test_delete_user_also_removes_group_membership(self):
        # Create a user and add it to a group
        bob = User(self.email)
        res = bob.create()
        self.assertEqual(res.json()['success'], True)

        group = Group(self.group_name, users=[bob.email])
        res2 = group.create()
        self.assertEqual(res2.json()['success'], True)

        # Make sure the user is in the group
        res3 = group.get()
        self.assertEqual(res3.json()['group']['users'], [bob.email])

        # Delete the user
        res4 = bob.delete()
        self.assertEqual(res4.json()["success"], True)

        # Make sure the user is not in the group anymore
        res5 = group.get()
        self.assertEqual(res5.json()['group']['users'], [])

    def test_delete_unknown_user(self):
        random_user = User("doesnotexist@doesnotexist.com")
        r = random_user.delete()
        self.assertEqual({'success': False, 'reason': 'no-such-user'}, r.json())

    def test_update_user(self):
        group1 = Group("group1")
        group2 = Group("group2")
        group1.create()
        group2.create()

        # Create a user
        bob = User(self.email, name="Bob", role="user", groups=[group1.group_name])
        res2 = bob.create()
        self.assertEqual(res2.json()['user']['email'], bob.email)
        self.assertEqual(res2.json()['user']['groups'], [group1.group_name])
        self.assertEqual(res2.json()["user"]["role"], "user")

        # Update the user
        res3 = bob.update(name="Bobby", role="administrator", groups=[group2.group_name])
        self.assertEqual(res3.json()["success"], True)
        self.assertEqual(res3.json()['user']['email'], bob.email)
        self.assertEqual(res3.json()['user']['name'], bob.name)
        self.assertEqual(res3.json()['user']['groups'], [group2.group_name])
        self.assertEqual(res3.json()["user"]["role"], "administrator")

        # Make sure the user stored in the db is correct
        res4 = bob.get()
        self.assertEqual(res4.json()['success'], True)
        self.assertEqual(res4.json()['user']['email'], bob.email)
        self.assertEqual(res4.json()['user']['name'], bob.name)
        self.assertEqual(res4.json()['user']['groups'], [group2.group_name])
        self.assertEqual(res4.json()['user']['role'], "administrator")

class TestGroupAPIs(TestAPIBaseClass):
    def test_create_group(self):
        bob = User(self.email)
        bob.create()
        group = Group(self.group_name, description=self.group_description)
        res = group.create()
        self.assertEqual(set(res.json().keys()), set(["success", "group"]))
        self.assertEqual(set(res.json()["group"].keys()),
            set(["id", "created", "name", "description", "users", "sites"]))
        self.assertEqual(res.json()['group']['name'], self.group_name)
        self.assertEqual(res.json()['group']['description'], self.group_description)

    def test_create_duplicate_group(self):
        bob = User(self.email)
        bob.create()
        group = Group(self.group_name)
        group.create()
        res = group.create()
        self.assertEqual(res.json()['success'], False)
        self.assertEqual(res.json()['reason'], 'group-already-exists')

    def test_get_all_groups(self):
        bob = User(self.email)
        bob.create()
        group = Group(self.group_name)
        res1 = group.create()
        res2 = Groups().get()
        self.assertEqual(res2.json()['groups'][0], res1.json()['group'])

    def test_get_group(self):
        bob = User(self.email)
        bob.create()
        group = Group(self.group_name)
        group.create()
        res = group.get()
        self.assertEqual(res.json()['group']['name'], group.group_name)
        self.assertEqual(res.json()['group']['description'], group.description)

    def test_delete_group(self):
        bob = User(self.email)
        bob.create()
        group = Group(self.group_name)
        group.create()
        res = group.delete()
        self.assertEqual(res.json()['success'], True)

    def test_patch_group_add_site(self):
        bob = User(self.email)
        bob.create()
        group = Group(self.group_name)
        res1 = group.create()
        res2 = group.update(add_sites=[self.target_url])
        self.assertEqual(res2.json()['group']['sites'][0], self.target_url)

    def test_patch_group_remove_site(self):
        bob = User(self.email)
        bob.create()
        group = Group(self.group_name)
        res1 = group.create()
        res2 = group.update(add_sites=[self.target_url])
        self.assertEqual(res2.json()['group']['sites'], group.sites)

        res3 = group.update(remove_sites=[self.target_url])
        self.assertEqual(res3.json()['group']['sites'], [])

    def test_patch_group_add_user(self):
        bob = User(self.email)
        bob.create()
        group = Group(self.group_name)
        res1 = group.create()
        res2 = group.update(add_users=[bob.email])
        self.assertEqual(res2.json()['group']['users'], group.users)

    def test_patch_group_remove_user(self):
        bob = User(self.email)
        bob.create()
        group = Group(self.group_name, users=[bob.email])
        res1 = group.create()
        res2 = group.update(remove_users=[bob.email])
        self.assertEqual(res2.json()['group']['users'], [])
