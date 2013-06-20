# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import json
import pprint
import requests
import time
import unittest
from flask import Flask, make_response
from multiprocessing import Process
from subprocess import Popen, PIPE

from pymongo import MongoClient

import minion.backend.utils as backend_utils
from minion.backend.api import BUILTIN_PLUGINS, TEST_PLUGINS

BACKEND_KEY = backend_utils.backend_config()['api'].get('key')
BASE = 'http://localhost:8383'
APIS = {'users':
            {'POST': '/users',
             'GET': '/users'},
        'user':
            {'DELETE': '/users/{user_email}',
             'GET': '/users/{user_email}',
             'POST': '/users/{user_email}'},
        'groups':
            {'POST': '/groups',
              'GET': '/groups'},
        'group':
            {'GET': '/groups/{group_name}',
             'DELETE': '/groups/{group_name}',
             'PATCH': '/groups/{group_name}'},
        'sites':
            {'GET': '/sites',
             'POST': '/sites'},
        'site':
            {'GET': '/sites/{site_id}',
             'POST': '/sites/{site_id}'},
        'get_plans':
            {'GET': '/plans'},
        'get_plan':
            {'GET': '/plans/{plan_name}'},
        'get_plugins':
            {'GET': '/plugins'},
        'scans':
            {'POST': '/scans',},
        'scan':
            {'GET': '/scans/{scan_id}',
             'PUT': '/scans/{scan_id}/control'},
        'scan_summary':
            {'GET': '/scans/{scan_id}/summary'},
        'history':
            {'GET': '/reports/history'},
        'issues':
            {'GET': '/reports/issues'},
        'status':
            {'GET': '/reports/status'},
}

def get_api(api_name, method, args=None):
    """ Return a full url and map each key
    in args to the url found in APIS. """
    api = ''.join([BASE, APIS[api_name][method]])
    if args:
        return api.format(**args)
    else:
        return api

def _call(task, method, auth=None, data=None, url_args=None, jsonify=True, \
        headers=None):
    """
    Make HTTP request.

    Parameters
    ----------
    task : str
        The name of the api to call which corresponds
        to a key name in ``APIS``.
    method : str
        Accept 'GET', 'POST', 'PUT', or
        'DELETE'.
    auth : optional, tuple
        Basic auth tuple ``(username, password)`` pair.
    data : optional, dict
        A dictionary of data to pass to the API.
    url_args : optional, dict
        A dictionary of url arguments to replace in the
        URL. For example, to match user's GET URL which
        requires ``id``, you'd pass ``{'id': '3a7a67'}``.
    jsonify : bool
        If set to True, data will be sent as plaintext like GET.
    headers : dict
        Default to None. GET will send as plain/text while
        POST, PUT, and PATCH will send as application/json.

    Returns
    -------
    res : requests.Response
        The response object.

    """

    req_objs = {'GET': requests.get,
        'POST': requests.post,
        'PUT': requests.put,
        'DELETE': requests.delete,
        'PATCH': requests.patch}

    method = method.upper()
    api = APIS[task][method]
    if url_args:
        api = api.format(**url_args)
    # concatenate base and api
    api = os.path.join(BASE.strip('/'), api.strip('/'))

    req_objs = req_objs[method]
    if jsonify and data and method != 'GET':
        data = json.dumps(data)

    if headers is None:
        if jsonify:
            headers = {'Content-Type': 'application/json',
                    'X-Minion-Backend-Key': BACKEND_KEY}
        else:
            headers = {'Content-Type': 'text/plain',
                    'X-Minion-Backend-Key': BACKEND_KEY}

    if method == 'GET' or method == 'DELETE':
        res = req_objs(api, params=data, auth=auth, headers=headers)
    else:
        res = req_objs(api, data=data, auth=auth, headers=headers)
    return res

class TestAPIBaseClass(unittest.TestCase):
    def setUp(self):
        self.mongodb = MongoClient()
        self.mongodb.drop_database("minion")
        self.db = self.mongodb.minion

        self.email = "bob@example.org"
        self.email2 = "alice@example.org"
        self.role = "user"
        self.group_name = "minion-test-group"
        self.group_description = "minion test group is awesome."
        self.group_name2 = "minion-test-group2"
        self.group_description2 = "minion test group 2 is super."

        self.target_url = "http://foo.com"
        self.site2 = "http://bar.com"

        self.target_url = 'http://localhost:1234'

    def tearDown(self):
        self.mongodb.drop_database("minion")

    def _kill_ports(self, ports):
        for port in ports:
            p = Popen(['kill `fuser -n tcp %s`' % str(port)],\
                    stdout=PIPE, stderr=PIPE, shell=True)
            p.communicate()
    def start_server(self):
        """ Similar to plugin functional tests, we need
        to start server and kill ports. """
        def run_app():
            test_app.run(host='localhost', port=1234)
        self._kill_ports([1234,])
        self.server = Process(target=run_app)
        self.server.daemon = True
        self.server.start()

    def stop_server(self):
        self.server.terminate()
        self._kill_ports([1234,])


    def import_plan(self, plan_name='basic'):
        ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        PLANS_ROOT = os.path.join(ROOT, 'plans')
        self.plans = self.db.plans
        self.scans = self.db.scans
        with open(os.path.join(PLANS_ROOT, '%s.plan' % plan_name), 'r') as f:
            self.plan = json.load(f)
            self.plans.remove({'name': self.plan['name']})
            self.plans.insert(self.plan)

    @staticmethod
    def _get_plugin_name(full):
        """ Return the name of the plugin. """
        cls_name = full.split('.')[-1]
        return cls_name.split('Plugin')[0]

    def check_plugin_metadata(self, base, metadata):
        """ Given a base configuration, parse
        and verify the input metadata contains
        the following keys: 'version', 'class',
        'weight', and 'name' for each plugin. """

        for index, plugin in enumerate(metadata):
            p_name = self._get_plugin_name(base['workflow'][index]['plugin_name'])
            # the plugin list is either under the key plugin, plugins or
            # iself is already a list. We should consider using plugins
            # over plugin; that is, change the key name in /plugins endpoint.
            meta = plugin.get('plugin') or plugin.get('plugins') or plugin
            self.assertEqual('light', meta['weight'])
            self.assertEqual(p_name, meta['name'])
            self.assertEqual(base['workflow'][index]['plugin_name'], meta['class'])
            self.assertEqual("0.0", meta['version'])


    def create_user(self, email="bob@example.org", name="Bob", role="user", groups=[], headers=None):
        return _call('users', 'POST', data={"email": email, "name": name, "role": role, "groups":groups},
                     headers=headers)

    def update_user(self, user_email, user):
        return _call('user', 'POST', url_args={'user_email': user_email}, data=user)

    def get_user(self, user_email):
        return _call('user', 'GET', url_args={'user_email': user_email})

    def delete_user(self, user_email):
        return _call('user', 'DELETE', url_args={'user_email': user_email})

    def get_users(self):
        return _call('users', 'GET')

    def create_group(self, group_name=None, group_description=None, users=None):
        if group_name  is None:
            group_name = self.group_name
        if group_description  is None:
            group_description = self.group_description
        data = {'name': group_name, "description": self.group_description}
        if users is not None:
            data.update({'users': users})
        return _call('groups', 'POST', data=data)

    def get_groups(self):
        return _call('groups', 'GET')

    def get_group(self, group_name):
        return _call('group', 'GET', url_args={'group_name': group_name})

    def delete_group(self, group_name):
        return _call('group', 'DELETE', url_args={'group_name': group_name})

    def modify_group(self, group_name, data=None):
        return _call('group', 'PATCH', url_args={'group_name': group_name},
                data=data)

    def create_site(self, groups=None, plans=None):
        if groups is None:
            groups = [self.group_name,]
        data = {'url': self.target_url, 'groups': groups}
        if plans is not None:
            data.update({'plans': plans})
        return _call('sites', 'POST', data=data)

    def update_site(self, site_id, site):
        return _call('site', 'POST', url_args={'site_id': site_id}, data=site)

    def get_sites(self):
        return _call('sites', 'GET')

    def get_site(self, site_id):
        return _call('site', 'GET', url_args={'site_id': site_id})

    def get_plans(self):
        return _call('get_plans', 'GET')

    def get_plan(self, plan_name):
        return _call('get_plan', 'GET', url_args={'plan_name': plan_name})

    def get_plugins(self):
        return _call('get_plugins', 'GET')

    def create_scan(self):
        return _call('scans', 'POST',
                data={'plan': 'basic',
                    'configuration': {'target': self.target_url}})

    def get_scan(self, scan_id):
        return _call('scan', 'GET', url_args={'scan_id': scan_id})

    def control_scan(self, scan_id, state='START'):
        return _call('scan', 'PUT', url_args={'scan_id': scan_id},
                data=state, jsonify=False)

    def get_scan_summary(self, scan_id):
        return _call('scan_summary', 'GET', url_args={'scan_id': scan_id})

    def get_reports_history(self, user=None):
        data = {}
        if user is not None:
            data = {'user': user}
        return _call('history', 'GET', data=data)

    def get_reports_status(self, user=None):
        data = None
        if user is not None:
            data = {'user': user}
        return _call('status', 'GET', data=data)

    def get_reports_issues(self, user=None):
        data = None
        if user is not None:
            data = {'user': user}
        return _call('issues', 'GET', data=data)

    def _test_keys(self, target, expected):
        """
        Compare keys are in the response. If there
        is a difference (more or fewer) assertion
        will raise False.

        Parameters
        ----------
        target : tuple
            A tuple of keys from res.json().keys()
        expected : tuple
            A tuple of keys expecting to match
            against res.json().keys()

        """

        keys1 = set(expected)
        self.assertEqual(set(), keys1.difference(target))

class TestAccessToken(TestAPIBaseClass):
    def test_create_user_200(self):
        res = self.create_user()
        self.assertEqual(res.status_code, 200)

    #def test_create_user_401_without_header(self):
    #    res = self.create_user(headers={'Content-Type': 'application/json'})
    #    self.assertEqual(res.status_code, 401)

    #def test_create_user_401_with_incorrect_backend_key(self):
    #    res = self.create_user(headers={'Content-type': 'application/json',\
    #           'X-Minion-Backend-Key': 'I want to hack your server.'})
    #    self.assertEqual(res.status_code, 401)

    def test_create_user_200_lower_case_header(self):
        res = self.create_user(headers={'Content-type': 'application/json',\
                   'x-minion-backend-key': BACKEND_KEY})
        self.assertEqual(res.status_code, 200)

class TestUserAPIs(TestAPIBaseClass):
    def test_create_user(self):
        res = self.create_user()
        expected_top_keys = ('user', 'success')
        self._test_keys(res.json().keys(), expected_top_keys)
        expected_inner_keys = ('id', 'created', 'role', 'email')
        self._test_keys(res.json()['user'].keys(), expected_inner_keys)

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
        print j
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

class TestSitesAPIs(TestAPIBaseClass):
    def setUp(self):
        super(TestSitesAPIs, self).setUp()
        self.import_plan(plan_name='basic')
        self.import_plan(plan_name='nmap')
        self.import_plan(plan_name='zap')

    def test_create_site(self):
        res = self.create_user()
        res1 = self.create_group()
        res2 = self.create_site()
        expected_top_keys = ('success', 'site',)
        #pprint.pprint(res2.json(), indent=2)
        self._test_keys(res2.json().keys(), expected_top_keys)
        expected_inner_keys = ('id', 'url', 'plans', 'created',)
        self._test_keys(res2.json()['site'].keys(), expected_inner_keys)
        self.assertEqual(res2.json()['site']['url'], self.target_url)
        #self.assertEqual(res2.json()['site']['groups'], [self.group_name])
        self.assertEqual(res2.json()['site']['plans'], [])

    def test_create_duplicate_site(self):
        res = self.create_user()
        res1 = self.create_group()
        res2 = self.create_site()
        res3 = self.create_site()
        expected_top_keys = ('success', 'reason',)
        self._test_keys(res3.json().keys(), expected_top_keys)
        self.assertEqual(res3.json()['success'], False)
        self.assertEqual(res3.json()['reason'], 'site-already-exists')

    def test_get_all_sites(self):
        res = self.create_user()
        res1 = self.create_group()
        res2 = self.create_site()
        res3 = self.get_sites()
        expected_top_keys = ('success', 'sites', )
        self._test_keys(res3.json().keys(), expected_top_keys)
        expected_inner_keys = ('id', 'url','groups', 'created', 'plans')
        self._test_keys(res3.json()['sites'][0].keys(), expected_inner_keys)
        self.assertEqual(res3.json()['sites'][0]['url'], self.target_url)
        # groups should return self.group_name when #50 and #49 are fixed
        self.assertEqual(res3.json()['sites'][0]['groups'], [self.group_name])
        self.assertEqual(res3.json()['sites'][0]['plans'], [])

    def test_get_site(self):
        res = self.create_user()
        res1 = self.create_group()
        res2 = self.create_site()
        site_id = res2.json()['site']['id']
        res3 = self.get_site(site_id)
        expected_top_keys = ('success', 'site', )
        self._test_keys(res3.json().keys(), expected_top_keys)
        # until #49, #50, #51 are resolved, this is commented
        #self.assertEqual(res3.json()['site'], res2.json()['site'])

    def test_update_site(self):
        res = self.create_user()
        res1 = self.create_group('foo')
        res1 = self.create_group('bar')
        res1 = self.create_group('baz')
        res2 = self.create_site(groups=[], plans=[])
        original_site = res2.json()['site']
        # Verify that the new site has no plans and no groups
        self.assertEqual(original_site['plans'], [])
        self.assertEqual(original_site['groups'], [])
        # Update the site, add a plan and group
        self.update_site(original_site['id'], {'plans':['basic'], 'groups': ['foo']})
        # Verify that the site has these new settings
        r = self.get_site(original_site['id'])
        site = r.json()['site']
        self.assertEqual(sorted(site['plans']), sorted(['basic']))
        self.assertEqual(sorted(site['groups']), sorted(['foo']))
        self.assertEqual(original_site['url'], site['url'])
        # Update the site, replace plans and groups
        self.update_site(site['id'], {'plans':['nmap','zap'], 'groups': ['bar','baz']})
        # Verify that the site has these new settings
        r = self.get_site(original_site['id'])
        site = r.json()['site']
        self.assertEqual(sorted(site['plans']), sorted(['nmap', 'zap']))
        self.assertEqual(sorted(site['groups']), sorted(['bar', 'baz']))
        self.assertEqual(original_site['url'], site['url'])

    def test_update_unknown_site(self):
        r = self.update_site('e22dbe0c-b958-4050-a339-b9a88fa7cd01',
                             {'plans':['nmap','zap'], 'groups': ['bar','baz']})
        r.raise_for_status()
        j = r.json()
        self.assertEqual(j, {'success': False, 'reason': 'no-such-site'})

    def test_update_site_with_unknown_group(self):
        r = self.create_site(groups=[], plans=[])
        r.raise_for_status()
        site = r.json()['site']
        r = self.update_site(site['id'], {'plans':[], 'groups': ['doesnotexist']})
        r.raise_for_status()
        j = r.json()
        self.assertEqual(j, {'success': False, 'reason': 'unknown-group'})

    def test_update_site_with_unknown_plan(self):
        r = self.create_site(groups=[], plans=[])
        r.raise_for_status()
        site = r.json()['site']
        r = self.update_site(site['id'], {'plans':['doesnotexist'], 'groups': []})
        r.raise_for_status()
        j = r.json()
        self.assertEqual(j, {'success': False, 'reason': 'unknown-plan'})

    def test_update_only_change_plans(self):
        r = self.create_group('foo')
        r.raise_for_status()
        r = self.create_site(groups=['foo'], plans=['basic'])
        r.raise_for_status()
        original_site = r.json()['site']
        # Verify that the new site is correct
        self.assertEqual(['basic'], original_site['plans'])
        self.assertEqual(['foo'], original_site['groups'])
        # Update just the plans
        r = self.update_site(original_site['id'], {'plans':['nmap']})
        r.raise_for_status()
        # Make sure the groups have not been changed
        r = self.get_site(original_site['id'])
        site = r.json()['site']
        self.assertEqual(sorted(['nmap']), sorted(site['plans']))
        self.assertEqual(sorted(['foo']), sorted(site['groups']))

    def test_update_only_change_groups(self):
        r = self.create_group('foo')
        r = self.create_group('bar')
        r.raise_for_status()
        r = self.create_site(groups=['foo'], plans=['basic'])
        r.raise_for_status()
        original_site = r.json()['site']
        # Verify that the new site is correct
        self.assertEqual(['basic'], original_site['plans'])
        self.assertEqual(['foo'], original_site['groups'])
        # Update just the groups
        r = self.update_site(original_site['id'], {'groups':['bar']})
        r.raise_for_status()
        # Make sure the plans have not been changed
        r = self.get_site(original_site['id'])
        site = r.json()['site']
        self.assertEqual(sorted(['basic']), sorted(site['plans']))
        self.assertEqual(sorted(['bar']), sorted(site['groups']))

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

        # test plugin name and weight. weight is now always light for the built-in
        plan = resp.json()
        self.check_plugin_metadata(self.plan, plan['plan']['workflow'])

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

test_app = Flask(__name__)
@test_app.route('/')
def basic_app():
    res = make_response('')
    res.headers['X-Content-Type-oPTIONS'] = 'nosniff'
    res.headers['X-Frame-Options'] = 'SAMEORIGIN'
    res.headers['X-XSS-Protection'] = '1; mode=block'
    res.headers['Content-Security-Policy'] = 'default-src *'
    return res

class TestScanAPIs(TestAPIBaseClass):
    def setUp(self):
        super(TestScanAPIs, self).setUp()
        self.import_plan()

    def test_create_scan(self):
        res1 = self.create_user()
        res2 = self.create_group()
        res3 = self.create_site(plans=['basic'])
        res4 = self.create_scan()
        expected_top_keys = ('success', 'scan',)
        self._test_keys(res4.json().keys(), expected_top_keys)

        expected_scan_keys = ('id', 'state', 'created', 'queued', 'started', \
                'finished', 'plan', 'configuration', 'sessions', 'meta',)
        self._test_keys(res4.json()['scan'].keys(), expected_scan_keys)

        scan = res4.json()['scan']
        for session in scan['sessions']:
            expected_session_keys = ('id', 'state', 'plugin', 'configuration', \
                    'description', 'artifacts', 'issues', 'created', 'started', \
                    'queued', 'finished', 'progress',)
            self._test_keys(session.keys(), expected_session_keys)
            self.assertEqual(session['configuration']['target'], self.target_url)

            self.assertEqual(session['state'], 'CREATED')
            self.assertEqual(session['artifacts'], {})
            self.assertEqual(session['issues'], [])
            for name in ('queued', 'started', 'finished', 'progress'):
                self.assertEqual(session[name], None)

    def test_get_scan(self):
        res1 = self.create_user()
        res2 = self.create_group()
        res3 = self.create_site(plans=['basic'])
        res4 = self.create_scan()
        scan_id = res4.json()['scan']['id']
        res5 = self.get_scan(scan_id)
        # since scan hasn't started, should == res4
        self.assertEqual(res4.json(), res5.json())

    def test_start_basic_scan(self):
        """
        This test is very comprehensive. It tests
        1. POST /scans
        2. GET /scans/<scan_id>
        3. PUT /scans/<scan_id>/control
        4. GET /scans/<scan_id>/summary
        5. GET /reports/history
        6. GET /reports/status
        7. GET /reports/issues
        """
        self.start_server()

        res1 = self.create_user()
        res2 = self.create_group(users=[self.email,])
        res3 = self.create_site(plans=['basic'])

        # POST /scans
        res4 = self.create_scan()
        scan_id = res4.json()['scan']['id']
        #pprint.pprint(res4.json(), indent=3)

        # PUT /scans/<scan_id>/control
        res5 = self.control_scan(scan_id, 'START')
        self.assertEqual(len(res5.json().keys()), 1)
        self.assertEqual(res5.json()['success'], True)
        #pprint.pprint(res5.json(), indent=3)

        # GET /scans/<scan_id>
        res6 = self.get_scan(scan_id)
        self._test_keys(res6.json().keys(), set(res4.json().keys()))
        self._test_keys(res6.json()['scan'].keys(), set(res4.json()['scan'].keys()))
        self.assertEqual(res6.json()['scan']['state'], 'QUEUED')
        #pprint.pprint(res6.json(), indent=3)

        # give scanner a few seconds
        time.sleep(10)
        # GET /scans/<scan_id>
        # now check if the scan has completed or not
        res7 = self.get_scan(scan_id)
        self.assertEqual(res7.json()['scan']['state'], 'FINISHED')
        #pprint.pprint(res6.json(), indent=3)

        # GET /scans/<scan_id>/summary
        res8 = self.get_scan_summary(scan_id)
        #pprint.pprint(res8.json(), indent=2)

        # GET /reports/history
        res9 = self.get_reports_history()
        expected_top_keys = ('report', 'success',)
        self._test_keys(res9.json().keys(), expected_top_keys)
        expected_inner_keys = ('configuration', 'created', 'finished', 'id',
                'issues', 'plan', 'queued', 'sessions', 'state',)
        self._test_keys(res9.json()['report'][0].keys(), expected_inner_keys)
        self.assertEqual(res9.json()['report'][0]['id'], scan_id)

        #pprint.pprint(res9.json(), indent=3)
        # GET /reports/status
        res10 = self.get_reports_status(user=self.email)
        expected_top_keys = ('success', 'report',)
        self._test_keys(res10.json().keys(), expected_top_keys)
        expected_inner_keys = ('plan', 'scan', 'target',)
        #pprint.pprint(res10.json(), indent=2)
        self._test_keys(res10.json()['report'][0].keys(), expected_inner_keys)
        self.assertEqual(res10.json()['report'][0]['plan'], 'basic')
        self.assertEqual(res10.json()['report'][0]['target'], self.target_url)

        # GET /reports/issues
        res11 = self.get_reports_issues(user=self.email)
        expected_top_keys = ('report', 'success', )
        self._test_keys(res11.json().keys(), expected_top_keys)
        expected_inner_keys = ('issues', 'target',)
        self._test_keys(res11.json()['report'][0].keys(), expected_inner_keys)

        issues = res11.json()['report'][0]['issues']
        # only 5 are reported. three of which are actually Info
        self.assertEqual(len(issues), 5)
        self.assertEqual(issues[3]['severity'], 'Medium')
        self.assertEqual(issues[3]['summary'], "Site sets the 'Server' header")
        self.assertEqual(issues[4]['severity'], 'Medium')
        self.assertEqual(issues[4]['summary'], 'No robots.txt found')
        self.assertEqual(res11.json()['report'][0]['target'], self.target_url)
        self.stop_server()
        #pprint.pprint(res11.json(), indent=3)
