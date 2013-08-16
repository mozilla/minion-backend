# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import datetime
import pprint

from base import BACKEND_KEY, BASE, _call, TestAPIBaseClass

class TestUserAPIs(TestAPIBaseClass):
    def assertSMTPReceived(self, actual_msg, user_email, invite_url):
        msgs = actual_msg.split('\n')
        # the first and last elements must be '------- MESSAGE BEGING/END -------'
        # [2] --> From ,  [3] --> To,   [4] --> Subject ,  [5] --> X-Peer,
        # [6] --> len(actual_msg)-2  ---> rest of body
        self.assertEqual(True, user_email in msgs[1])
        self.assertEqual(True, invite_url in '\n'.join(msgs[6:-1]))

    def test_create_user(self):
        res = self.create_user()
        expected_top_keys = ('user', 'success')
        self._test_keys(res.json().keys(), expected_top_keys)
        expected_inner_keys = ('id', 'created', 'role', 'email', 'status', 'last_login')
        self._test_keys(res.json()['user'].keys(), expected_inner_keys)
        self.assertEqual(res.json()['user']['status'], 'active')    # ticket #109

    # issue #128
    def test_login_user(self):
        res1 = self.create_user(email="bob@example.org")
        res2 = self.login_user(email="bob@example.org")
        self.assertEqual(res2.json()['success'], True)
        self.assertEqual(True, res2.json()['user']['last_login'] is not None)

    # issue #128
    def test_login_non_existing_user(self):
        res1 = self.login_user(email="bob@example.org")
        self.assertEqual(res1.json()['success'], False)
        self.assertEqual(res1.json()['reason'], "user-does-not-exist")
    
    # issue #128
    def test_login_non_active_user(self):
        res1 = self.create_user(email="bob@example.org")
        # change user to banned
        res2 = self.update_user("bob@example.org", {'status': 'banned'})
        res3 = self.login_user(email="bob@example.org")
        self.assertEqual(res3.json()['success'], False)
        self.assertEqual(res3.json()['reason'], 'banned')
        
    # ticket #109, #110
    def test_invite_user(self):
        #self.start_smtp()
        res = self.create_user(email=self.email, invitation=True)
        expected_top_keys = ('user', 'success')
        self._test_keys(res.json().keys(), expected_top_keys)
        expected_inner_keys = ('id', 'created', 'role', 'email', 'status')
        self._test_keys(res.json()['user'].keys(), expected_inner_keys)
        self.assertEqual(res.json()['user']['status'], 'invited')
        #with open('/tmp/minion_smtp_debug.txt', 'r') as f:
        #    data = f.read()
        #self.assertSMTPReceived(data, self.email, '0.0.0.0:8080')
        #self.stop_smtp()

    # ticket #109, #110
    def test_update_invited_user(self):
        #self.start_smtp()
        res1 = self.create_user(email=self.email, invitation=True)
        res2 = self.update_user(self.email, user={'status': 'active'})
        self.assertEqual(res2.json()['user']['status'], 'active')
        self.assertEqual(res1.json()['user']['status'], 'invited')
        #self.stop_smtp()

    def test_get_user(self):
        r = self.create_group('foo')
        j = r.json()
        self.assertEqual(True, r.json()['success'])
        # Add a user
        r = self.create_user(email="foo@example.com", name="Foo", role="user", groups=['foo'])
        r.raise_for_status()
        j = r.json()
        self.assertEqual(True, r.json()['success'])
        # Make sure the user stored in the db is correct
        r = self.get_user('foo@example.com')
        r.raise_for_status()
        j = r.json()
        self.assertEqual(True, j['success'])
        self.assertEqual("foo@example.com", j['user']['email'])
        self.assertEqual("Foo", j['user']['name'])
        self.assertEqual(['foo'], j['user']['groups'])
        self.assertEqual('user', j['user']['role'])

    def test_get_all_users(self):
        # we must recreate user
        self.create_user()
        res = self.get_users()
        expected_inner_keys = ('id', 'email', 'role', 'sites', 'groups')
        self._test_keys(res.json()['users'][0].keys(), expected_inner_keys)
        self.assertEqual(1, len(res.json()['users']))

    def test_delete_user(self):
        # Create a user
        r = self.create_user()
        r.raise_for_status()
        j = r.json()
        self.assertEqual(True, j['success'])
        # Delete the user
        r = self.delete_user(self.email)
        r.raise_for_status()
        self.assertEqual({'success': True}, r.json())
        # Make sure the user is gone
        r = self.delete_user(self.email)
        r.raise_for_status()
        self.assertEqual({'success': False, 'reason': 'no-such-user'}, r.json())

    def test_delete_user_also_removes_group_membership(self):
        # Create a user and add it to a group
        r = self.create_user()
        r.raise_for_status()
        self.assertEqual(True, r.json()['success'])
        r = self.create_group(users=[self.email])
        r.raise_for_status()
        self.assertEqual(True, r.json()['success'])
        # Make sure the user is in the group
        r = self.get_group(self.group_name)
        r.raise_for_status()
        self.assertEqual([self.email], r.json()['group']['users'])
        # Delete the user
        r = self.delete_user(self.email)
        r.raise_for_status()
        self.assertEqual({'success': True}, r.json())
        # Make sure the user is not in the group anymore
        r = self.get_group(self.group_name)
        r.raise_for_status()
        self.assertEqual([], r.json()['group']['users'])

    def test_delete_unknown_user(self):
        r = self.delete_user('doesnotexist@doesnotexist.com')
        r.raise_for_status()
        self.assertEqual({'success': False, 'reason': 'no-such-user'}, r.json())

    def test_update_user(self):
        r = self.create_group('foo')
        r = self.create_group('bar')
        # Create a user
        r = self.create_user(email="foo@example.com", name="Foo", role="user", groups=['foo'])
        r.raise_for_status()
        j = r.json()
        self.assertEqual("foo@example.com", j['user']['email'])
        self.assertEqual("Foo", j['user']['name'])
        self.assertEqual(['foo'], j['user']['groups'])
        self.assertEqual('user', j['user']['role'])
        # Update the user
        r = self.update_user('foo@example.com', {'name': 'New Foo', 'role': 'administrator',
                                               'groups': ['bar']})
        r.raise_for_status()
        j = r.json()
        self.assertEqual(True, j['success'])
        # Make sure the user returned is correct
        self.assertEqual("foo@example.com", j['user']['email'])
        self.assertEqual("New Foo", j['user']['name'])
        self.assertEqual(['bar'], j['user']['groups'])
        self.assertEqual('administrator', j['user']['role'])
        # Make sure the user stored in the db is correct
        r = self.get_user('foo@example.com')
        r.raise_for_status()
        j = r.json()
        self.assertEqual(True, j['success'])
        self.assertEqual("foo@example.com", j['user']['email'])
        self.assertEqual("New Foo", j['user']['name'])
        self.assertEqual(['bar'], j['user']['groups'])
        self.assertEqual('administrator', j['user']['role'])

class TestGroupAPIs(TestAPIBaseClass):
    def test_create_group(self):
        res = self.create_user()
        res = self.create_group()
        expected_top_keys = ('success', 'group')
        self._test_keys(res.json().keys(), expected_top_keys)
        expected_inner_keys = ('id', 'created', 'name', 'description')
        self._test_keys(res.json()['group'], expected_inner_keys)
        self.assertEqual(res.json()['group']['name'], self.group_name)
        self.assertEqual(res.json()['group']['description'], self.group_description)

    def test_create_duplicate_group(self):
        res = self.create_user()
        res = self.create_group()
        res = self.create_group()
        expected_top_keys = ('success', 'reason')
        self._test_keys(res.json().keys(), expected_top_keys)
        self.assertEqual(res.json()['success'], False)
        self.assertEqual(res.json()['reason'], 'group-already-exists')

    def test_get_all_groups(self):
        res = self.create_user()
        res1 = self.create_group()
        res2 = self.get_groups()
        expected_top_keys = ('success', 'groups')
        self._test_keys(res2.json().keys(), expected_top_keys)
        self.assertEqual(res2.json()['groups'][0], res1.json()['group'])

    def test_get_group(self):
        res = self.create_user()
        res1 = self.create_group()
        res2 = self.get_group(self.group_name)
        expected_top_keys = ('success', 'group')
        self._test_keys(res2.json().keys(), expected_top_keys)
        self.assertEqual(res2.json()['group']['name'], self.group_name)
        self.assertEqual(res2.json()['group']['description'], self.group_description)

    def test_delete_group(self):
        res = self.create_user()
        res1 = self.create_group()
        res2 = self.delete_group(self.group_name)
        expected_top_keys = ('success', )
        self._test_keys(res2.json().keys(), expected_top_keys)
        self.assertEqual(res2.json()['success'], True)

    def test_patch_group_add_site(self):
        res = self.create_user()
        res1 = self.create_group()
        res2 = self.modify_group(self.group_name,
                data={'addSites': [self.target_url]})
        self._test_keys(res2.json().keys(), set(res1.json().keys()))
        self._test_keys(res2.json()['group'].keys(), set(res1.json()['group'].keys()))
        self.assertEqual(res2.json()['group']['sites'][0], self.target_url)

    def test_patch_group_remove_site(self):
        res = self.create_user()
        res1 = self.create_group()
        res2 = self.modify_group(self.group_name,
                data={'addSites': [self.target_url]})
        self.assertEqual(res2.json()['group']['sites'][0], self.target_url)

        res2 = self.modify_group(self.group_name,
                data={'removeSites': [self.target_url]})
        self._test_keys(res2.json().keys(), set(res1.json().keys()))
        self._test_keys(res2.json()['group'].keys(), set(res1.json()['group'].keys()))
        self.assertEqual(res2.json()['group']['sites'], [])

    def test_patch_group_add_user(self):
        res = self.create_user()
        res1 = self.create_group()
        res2 = self.modify_group(self.group_name,
                data={'addUsers': [self.email2]})
        self._test_keys(res2.json().keys(), set(res1.json().keys()))
        self._test_keys(res2.json()['group'].keys(), set(res1.json()['group'].keys()))
        self.assertEqual(res2.json()['group']['users'][0], self.email2)

    def test_patch_group_remove_user(self):
        res = self.create_user()
        res1 = self.create_group()
        res2 = self.modify_group(self.group_name,
                data={'addUsers': [self.email2]})
        self.assertEqual(res2.json()['group']['users'][0], self.email2)

        res2 = self.modify_group(self.group_name,
                data={'removeUsers': [self.email2]})
        self._test_keys(res2.json().keys(), set(res1.json().keys()))
        self._test_keys(res2.json()['group'].keys(), set(res1.json()['group'].keys()))
        self.assertEqual(res2.json()['group']['users'], [])
