# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import json
import unittest
import requests
import importlib

from pymongo import MongoClient

BASE = 'http://localhost:8383'
APIS = {'get_plans': 
            {'GET': '/plans'},
        'get_plan':
            {'GET': '/plans/{plan_name}'}
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


    def test_get_plan(self):
        API = get_api('get_plan', 'GET', args={'plan_name': 'basic'})
        resp = requests.get(API)
        self.assertEqual(200, resp.status_code)
        # at this stage, let's get some tests done before we worry about
        # testing other plugins.
        #
        # weight is all 'light' and 'name' is always the class name minus
        # 'Plugin'.
        def _get_plug_name(full):
            cls_name = full.split('.')[-1]
            return cls_name.split('Plugin')[0]

        orig_plan = dict(self.plan)
        plan = resp.json()
        workflow = plan['plan']['workflow']
        for index, plugin in enumerate(workflow):
            expected_plg_name = _get_plug_name(orig_plan['workflow'][index]['plugin_name'])
            self.assertEqual('light', plugin['plugin']['weight'])
            self.assertEqual(expected_plg_name, plugin['plugin']['name'])            
