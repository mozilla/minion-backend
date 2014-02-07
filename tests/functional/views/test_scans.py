# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import time

from base import (TestAPIBaseClass, User, Site, Group, Plan, Scan, Scans, Reports)

class TestScanAPIs(TestAPIBaseClass):
    TEST_PLAN = {
        "name": "test-plan",
        "description": "Plan that runs DelayPlugin",
        "workflow": [
            {
                "plugin_name": "minion.plugins.test.DelayedPlugin",
                "description": "",
                "configuration": {
                    "message": "Testing"
                }
            }
        ]
    }

    def create_plan(self):
        self.plan = Plan(self.TEST_PLAN)
        res = self.plan.create()
        self.assertEqual(res.json()["success"], True)
        self.user = User(self.email)
        self.user.create()
        self.site = Site(self.target_url, plans=[self.plan.plan["name"]])
        self.site.create()
        self.group = Group("testgroup", sites=[self.site.url], users=[self.user.email])
        self.group.create()

    def setUp(self):
        super(TestScanAPIs, self).setUp()
        self.create_plan()

    def test_create_scan_with_credential(self):
        scan = Scan(self.user.email, self.TEST_PLAN["name"], {"target": self.target_url})
        res = scan.create()
        expected_top_keys = ('success', 'scan',)
        self.assertEqual(res.json()["success"], True)
        expected_scan_keys = set(['id', 'state', 'created', 'queued', 'started', \
                'finished', 'plan', 'configuration', 'sessions', 'meta'])
        self.assertEqual(set(res.json()["scan"].keys()), expected_scan_keys)

        meta = res.json()['scan']['meta']
        # this scan is not tagged
        self.assertEqual(meta['tags'], [])
        # bug #106 add owner of the scan
        self.assertEqual(meta['user'], self.user.email)
        self.assertEqual(res.json()['scan']['configuration']['target'],
            self.target_url)

        scan = res.json()['scan']
        expected_session_keys = ['id', 'state', 'plugin', 'configuration', \
                'description', 'artifacts', 'issues', 'created', 'started', \
                'queued', 'finished', 'progress']
        for session in scan['sessions']:
            self.assertEqual(set(session.keys()), set(expected_session_keys))
            self.assertEqual(session['configuration']['target'], self.target_url)

            self.assertEqual(session['state'], 'CREATED')
            self.assertEqual(session['artifacts'], {})
            self.assertEqual(session['issues'], [])
            for name in ('queued', 'started', 'finished', 'progress'):
                self.assertEqual(session[name], None)

    # NOTE: Uncomment when #296 is fixed.
    """
    def test_get_scan_details(self):
        scan = Scan(self.user.email, self.TEST_PLAN["name"], {"target": self.target_url})
        res1 = scan.create()
        scan_id = res1.json()['scan']['id']

        res2 = scan.get_scan_details(scan_id)
        # since scan hasn't started, should == res1
        self.assertEqual(res2.json(), res1.json())

        # bug #140 and bug #146
        res3 = scan.get_scan_details(scan_id, email=self.user.email)
        self.assertEqual(res3.json(), res2.json())
    """

    # bug #140 and bug #146
    def test_get_scan_details_filter_with_nonexistent_user(self):
        # If we give a non-existent user in the request argument, it will return user not found
        scan = Scan(self.user.email, self.TEST_PLAN["name"], {"target": self.target_url})
        res1 = scan.create()
        scan_id = res1.json()['scan']['id']

        res2 = scan.get_scan_details(scan_id, email="nonexistentuser@example.org")
        self.assertEqual(res2.json()["success"], False)
        self.assertEqual(res2.json()["reason"], "user-does-not-exist")

    # bug #140 and bug #146
    def test_get_scan_details_filter_with_incorrect_user(self):
        # Scan is started by Bob and only Bob's group has access to target_url.
        # Alice does not belong to Bob's group so she has no permission to the scan
        scan = Scan(self.user.email, self.TEST_PLAN["name"], {"target": self.target_url})
        res1 = scan.create()
        scan_id = res1.json()['scan']['id']

        alice = User("alice@example.org")
        res2 = alice.create()
        self.assertEqual(res2.json()["success"], True)

        res2 = scan.get_scan_details(scan_id, email=alice.email)
        self.assertEqual(res2.json()["success"], False)
        self.assertEqual(res2.json()["reason"], "not-found")

    # NOTE: Uncomment this when #296 is fixed
    ''' 
    def test_scan(self):
        """
        This is a comprehensive test that runs through the following
        endpoints:

        1. POST /scans
        2. GET /scans/<scan_id>
        3. PUT /scans/<scan_id>/control
        4. GET /scans/<scan_id>/summary
        5. GET /reports/history
        6. GET /reports/status
        7. GET /reports/issues

        """

        # Create user, site, group, plan and site
        # This is already handled in setUp call.

        # POST /scans
        # create a scan on target_url based on our test plan (which runs DelayPlugin)
        scan = Scan(self.user.email, self.TEST_PLAN["name"], {"target": self.target_url})
        res1 = scan.create()
        scan_id = res1.json()['scan']['id']

        # PUT /scans/<scan_id>/control
        # Start the scan now.
        res2 = scan.start(scan_id)
        self.assertEqual(res2.json()['success'], True)

        # GET /scans/<scan_id>
        # Check the status. It should be in QUEUED (hopefully it doesn't go too fast)
        res3 = scan.get_scan_details(scan_id)
        self.assertEqual(res3.json()["scan"]["state"], "QUEUED")
        # POST and GET scan details should have the same set of keys at the top-level
        # and at the "scan" level
        self.assertEqual(set(res3.json().keys()), set(res1.json().keys()))
        self.assertEqual(set(res3.json()["scan"].keys()), set(res1.json()["scan"].keys()))

        # give scanner a few seconds
        time.sleep(6)

        # GET /scans/<scan_id>
        # now check if the scan has completed or not
        res4 = scan.get_scan_details(scan_id)
        self.assertEqual(res4.json()['scan']['state'], 'FINISHED')
        
        # GET /scans/<scan_id>/summary
        res5 = scan.get_summary(scan_id)
        # bug #106 include scan creator in the output
        self.assertEqual(res5.json()['summary']['meta'], 
            {'user': self.email, 'tags': []})

        # GET /reports/history
        res6 = Reports().get_history()
        self.assertEqual(res6.json()["success"], True)
        expected_inner_keys = set(['configuration', 'created', 'finished', 'id',
                'issues', "meta", 'plan', 'queued', 'sessions', 'state'])
        self.assertEqual(set(res6.json()['report'][0].keys()), expected_inner_keys)
        self.assertEqual(res6.json()['report'][0]['id'], scan_id)

        # GET /reports/status
        res7 = Reports().get_status(user=self.user.email)
        self.assertEqual(res7.json()["success"], True)
        expected_inner_keys = set(['plan', 'scan', 'target'])
        self.assertEqual(set(res7.json()['report'][0].keys()), expected_inner_keys)
        self.assertEqual(res7.json()['report'][0]['plan'], self.plan.plan["name"])
        self.assertEqual(res7.json()['report'][0]['target'], self.target_url)

        # GET /reports/issues
        res8 = Reports().get_issues(user=self.user.email)
        self.assertEqual(res8.json()["success"], True)
        expected_inner_keys = ('issues', 'target',)
        self.assertEqual(set(res8.json()['report'][0].keys()), set(["issues", "target"]))

        issues = res8.json()['report'][0]['issues']
        # DelayPlugin emits only one issue
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["summary"], "Testing")
        self.assertEqual('Info', issues[0]['severity'])
        self.assertEqual(issues[0]["severity"], "Info")
        self.assertEqual(res8.json()['report'][0]['target'], self.target_url)
    '''
