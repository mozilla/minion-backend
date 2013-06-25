# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import pprint

from base import BACKEND_KEY, BASE, _call, TestAPIBaseClass

# issue #114
class TestInviteAPIs(TestAPIBaseClass):
    def assertSMTPReceived(self, actual_msg, user_email, invite_url):
        msgs = actual_msg.split('\n')
        # the first and last elements must be '------- MESSAGE BEGING/END -------'
        # [2] --> From ,  [3] --> To,   [4] --> Subject ,  [5] --> X-Peer,
        # [6] --> len(actual_msg)-2  ---> rest of body
        self.assertEqual(True, user_email in msgs[1])
        self.assertEqual(True, invite_url in '\n'.join(msgs[6:-1]))

    def test_post_invite(self):
        res1 = self.create_user()
        res2 = self.create_invite(recipient=self.email2, sender=self.email)
        pprint.pprint(res2.json(), indent=2)
        self.assertSuccessfulResponse(res2)
        expected_top_keys = ('success', 'invite',)
        self._test_keys(res2.json().keys(), expected_top_keys)
        expected_inner_keys = ('id', 'recipient', 'sender', 'sent_on', 'accepted_on')
        self._test_keys(res2.json()['invite'].keys(), expected_inner_keys)
        self.assertEqual(res2.json()['invite']['recipient'], self.email2)
        self.assertEqual(res2.json()['invite']['sender'], self.email)
        self.assertEqual(True, res2.json()['invite']['accepted_on'] is None)
        self.assertEqual(True, res2.json()['invite']['sent_on'] is not None)
        self.assertEqual(True, res2.json()['invite']['id'] is not None)
        raw_input('00000')
