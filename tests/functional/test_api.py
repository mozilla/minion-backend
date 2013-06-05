# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import json
import unittest
import requests

from pymongo import MongoClient

from minion.backend.api import BUILTIN_PLUGINS, TEST_PLUGINS

BASE = 'http://localhost:8383'
APIS = {'get_plans': 
            {'GET': '/plans'},
        'get_plan':
            {'GET': '/plans/{plan_name}'},
        'get_plugins':
            {'GET': '/plugins'},
}

def get_api(api_name, method, args=None):
    """ Return a full url and map each key
    in args to the url found in APIS. """
    api = ''.join([BASE, APIS[api_name][method]])
    if args:
        return api.format(**args)
    else:
        return api

#TODO: We should be able to test other plugins other than basic.plan.
# At that point, we probably should create more generic functional tests.
class TestBackendAPIs(unittest.TestCase):
    def setUp(self):
        ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        PLANS_ROOT = os.path.join(ROOT, 'plans')

        self.mongodb = MongoClient()
        self.db = self.mongodb.test_minion
        self.plans = self.db.plans
        self.scans = self.db.scans
        with open(os.path.join(PLANS_ROOT, 'basic.plan'), 'r') as f:
            self.plan = json.load(f)
            self.plans.remove({'name': self.plan['name']})
            self.plans.insert(self.plan)
    
    @staticmethod
    def _get_plugin_name(full):
        """ Return the name of the plugin. """
        cls_name = full.split('.')[-1]
        return cls_name.split('Plugin')[0]

    def test_get_plans(self):
        API = get_api('get_plans', 'GET')
        expected = {
            u"plans": 
            [
                {
                    u"description": u"Run basic tests", 
                    u"name": u"basic"
                }
            ],
            u"success": True
        }
        resp = requests.get(API)
        self.assertEqual(200, resp.status_code)
        self.assertEqual(expected, resp.json())

    @staticmethod
    def _check_plugin_metadata(tself, base, metadata):
        """ Given a base configuration, parse
        and verify the input metadata contains
        the following keys: 'version', 'class',
        'weight', and 'name' for each plugin. """

        for index, plugin in enumerate(metadata):
            p_name = tself._get_plugin_name(base['workflow'][index]['plugin_name'])
            # the plugin list is either under the key plugin, plugins or
            # itself is already a list. We should consider using plugins
            # over plugin; that is, change the key name in /plugins endpoint.
            meta = plugin.get('plugin') or plugin.get('plugins') or plugin
            tself.assertEqual('light', meta['weight'])
            tself.assertEqual(p_name, meta['name'])
            tself.assertEqual(base['workflow'][index]['plugin_name'], meta['class'])
            tself.assertEqual("0.0", meta['version'])
    
    def test_get_plan(self):
        API = get_api('get_plan', 'GET', args={'plan_name': 'basic'})
        resp = requests.get(API)
        self.assertEqual(200, resp.status_code)

        # test plugin name and weight. weight is now always light for the built-in
        plan = resp.json()
        self._check_plugin_metadata(self, self.plan, plan['plan']['workflow'])
    
    def test_get_built_in_plugins(self):
        API = get_api('get_plugins', 'GET')
        resp = requests.get(API)
        self.assertEqual(200, resp.status_code)
        # check top-leve keys agreement
        self.assertEqual(True, 'plugins' in resp.json().keys())
        self.assertEqual(True, 'success' in resp.json().keys())
        # num of total built-in plugins should match
        plugins_count = len(TEST_PLUGINS) + len(BUILTIN_PLUGINS)
        self.assertEqual(plugins_count, len(resp.json()['plugins']))
        # check following keys are returned for each plugin
        for plugin in resp.json()['plugins']:
            self.assertEqual(['class', 'name', 'version', 'weight'],
                sorted(plugin.keys()))
        #TODO: Need to fix this last part of the test.
        # Apparently the plugins within the plugins list is not oredered
        # like the one returned from get_plans or get_plan. Robots comes
        # first before Alive.
        # check plugin name, weight, class, version
        # self._check_plugin_metadata(self, self.plan, resp.json()['plugins'])
