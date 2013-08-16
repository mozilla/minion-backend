# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import pprint
import requests

from base import BACKEND_KEY, BASE, _call, TestAPIBaseClass

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

    # issue#132
    def test_create_empty_group(self):
        res = self.create_group(group_name='')
        self.assertEqual(res.json()['success'], False)
        self.assertEqual(res.json()['reason'], 'name-field-is-required')

    #issue#132
    def test_create_group_with_non_existing_user(self):
        res = self.create_group(users=['user1', 'user2'])
        self.assertEqual(res.json()['success'], False)
        self.assertEqual(res.json()['reason'], 'user user1 does not exist')
    
    #issue#132
    def test_create_group_with_non_existing_user(self):
        res = self.create_group(sites=['https://example1.com',])
        self.assertEqual(res.json()['success'], False)
        self.assertEqual(res.json()['reason'], 'site https://example1.com does not exist')
    
    #issue#132
    def test_create_group_with_existing_user(self):
        res1 = self.create_user(email='user1@example.org')
        res2 = self.create_user(email='user2@example.org')

        res3 = self.create_group(
            users=['user1@example.org', 'user2@example.org'])
        self.assertEqual(res3.json()['success'], True)
        self.assertEqual(res3.json()['group']['users'], ['user1@example.org', \
            'user2@example.org'])

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

    # issue #215
    def test_retrieve_issue_status_and_issues_by_group(self):
        """ Don't be shock. This test fits here; by querying
        user and group, we should only be given the lastest
        issue status. """

        res = self.create_user()
        res1 = self.create_group(group_name="test1", users=[self.email])
        res2 = self.create_group(group_name="test2", users=[self.email])
        res3 = self.create_site(groups=["test1"], site="http://foo.com")
        res4 = self.create_site(groups=["test2"], site="http://bar.com")
        raw_input("----")
        # if we query just test1, should get back only foo.com
        res5 = self.get_reports_status(user=self.email, group="test1")
        r = res5.json()['report']
        self.assertEqual(len(r), 1) # there should just be one dict returned in the list
        self.assertEqual(r[0]['target'], "http://foo.com")
    
        # if we try it on get_report_issues we should see similar result
        res6 = self.get_report_issues(user=self.email, group="test1")
        r = res6.json()['report']
        self.assertEqual(len(r), 1) # there should just be one dict returned in the list
        self.assertEqual(r[0]['target'], "http://foo.com")

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

