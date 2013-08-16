# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import pprint
import requests

from base import BACKEND_KEY, BASE, _call, TestAPIBaseClass

class TestReportsAPIs(TestAPIBaseClass):

    PLAN = { "name": "test",
                          "description": "Test",
                          "workflow": [ { "plugin_name": "minion.plugins.basic.AlivePlugin",
                                          "description": "Test if the site is alive",
                                          "configuration": { "foo": "bar" }
                                          } ] }
    # issue #215
    def test_retrieve_issue_status_and_issues_by_group(self):
        """ Don't be shock. This test fits here; by querying
        user and group, we should only be given the lastest
        issue status. """

        res = self.create_user()
        res1 = self.create_plan(self.PLAN)
        res2 = self.create_group(group_name="test1", users=[self.email])
        res3 = self.create_group(group_name="test2", users=[self.email])
        res4 = self.create_site(groups=["test1"], site="http://foo.com", plans=["test"])
        res5 = self.create_site(groups=["test2"], site="http://bar.com", plans=["test"])
        # if we query just test1, should get back only foo.com
        res6 = self.get_reports_status(user=self.email, group_name="test1")
        r = res6.json()['report']
        self.assertEqual(len(r), 1) # there should just be one dict returned in the list
        self.assertEqual(r[0]['target'], "http://foo.com")

        # if we try it on get_report_issues we should see similar result
        res7 = self.get_reports_issues(user=self.email, group_name="test1")
        r = res7.json()['report']
        self.assertEqual(len(r), 1) # there should just be one dict returned in the list
        self.assertEqual(r[0]['target'], "http://foo.com")
