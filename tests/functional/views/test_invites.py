# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import copy
import pprint
import uuid

from base import BACKEND_KEY, BASE, _call, TestAPIBaseClass

# issue #114
class TestInviteAPIs(TestAPIBaseClass):
    def random_email(self):
        name = str(uuid.uuid4())
        name = ''.join(name.split('-'))
        return name + '@example.org'

    def assertSMTPReceived(self, actual_msg, user_email, invite_url):
        msgs = actual_msg.split('\n')
        # the first and last elements must be '------- MESSAGE BEGING/END -------'
        # [2] --> From ,  [3] --> To,   [4] --> Subject ,  [5] --> X-Peer,
        # [6] --> len(actual_msg)-2  ---> rest of body
        self.assertEqual(True, user_email in msgs[1])
        self.assertEqual(True, invite_url in '\n'.join(msgs[6:-1]))

    def test_post_invite(self):
        recipient = self.random_email()
        # must create both sender and user
        res1 = self.create_user()
        res2 = self.create_user(email=recipient, name='Alice')

        res3 = self.create_invites(recipient=recipient, sender=self.email)
        self.assertSuccessfulResponse(res3)
        expected_top_keys = ('success', 'invite',)
        self._test_keys(res3.json().keys(), expected_top_keys)
        expected_inner_keys = ('id', 'recipient', 'sender', 'sent_on', 'accepted_on', \
                'sender_name', 'recipient_name')
        self._test_keys(res3.json()['invite'].keys(), expected_inner_keys)
        self.assertEqual(res3.json()['invite']['recipient'], recipient)
        self.assertEqual(res3.json()['invite']['sender'], self.email)
        self.assertEqual(res3.json()['invite']['recipient_name'], 'Alice')
        self.assertEqual(res3.json()['invite']['sender_name'], 'Bob')
        self.assertEqual(True, res3.json()['invite']['accepted_on'] is None)
        self.assertEqual(True, res3.json()['invite']['sent_on'] is not None)
        self.assertEqual(True, res3.json()['invite']['id'] is not None)

    def test_get_all_invites(self):
        recipient1 = self.random_email()
        recipient2 = self.random_email()
        recipient3 = self.random_email()
        res1 = self.create_user()
        res1 = self.create_user(email=recipient1, name='Alice')
        res1 = self.create_user(email=recipient2, name='Betty')
        res1 = self.create_user(email=recipient3, name='Cathy')

        res2 = self.create_invites(recipient=recipient1, sender=self.email)
        res3 = self.create_invites(recipient=recipient2, sender=self.email)
        res4 = self.create_invites(recipient=recipient3, sender=self.email)

        res5 = self.get_invites()
        self.assertEqual(len(res5.json()['invites']), 3)
        self.assertEqual(res5.json()['invites'][0]['recipient'], recipient1)
        self.assertEqual(res5.json()['invites'][1]['recipient'], recipient2)
        self.assertEqual(res5.json()['invites'][2]['recipient'], recipient3)

    def test_get_invites_filter_by_sender_and_or_recipient(self):
        recipient1 = self.random_email()
        recipient2 = self.random_email()
        recipient3 = self.random_email()
        sender2 = self.random_email()
        
        # create senders
        res1 = self.create_user()
        res2 = self.create_user(email=sender2)

        # create recipients in the user table
        res2 = self.create_user(email=recipient1, name='Alice')
        res2 = self.create_user(email=recipient2, name='Betty')
        res2 = self.create_user(email=recipient3, name='Cathy')
        
        # create recipients
        res3 = self.create_invites(recipient=recipient1, sender=self.email)
        res4 = self.create_invites(recipient=recipient2, sender=sender2)
        res5 = self.create_invites(recipient=recipient3, sender=self.email)

        # only recipient2 is returned given filter by sender
        res6 = self.get_invites(filters={'sender': sender2})
        self.assertEqual(len(res6.json()['invites']), 1)
        self.assertEqual(res6.json()['invites'][0]['recipient'], recipient2)
        self.assertEqual(res6.json()['invites'][0]['sender'], sender2)

        # recipient2 is not returned given filter by sender
        res7 = self.get_invites(filters={'sender': self.email})
        self.assertEqual(len(res7.json()['invites']), 2)
        self.assertEqual(res7.json()['invites'][0]['recipient'], recipient1)
        self.assertEqual(res7.json()['invites'][1]['recipient'], recipient3)

        # only recipient1 is returned given filter by recipient
        res8 = self.get_invites(filters={'recipient': recipient1})
        self.assertEqual(len(res8.json()['invites']), 1)
        self.assertEqual(res8.json()['invites'][0]['recipient'], recipient1)

        # only recipient1 is returned given filter by recipient AND sender
        res9 = self.get_invites(
            filters={'recipient': recipient1, 'sender': self.email})
        self.assertEqual(len(res9.json()['invites']), 1)
        self.assertEqual(res9.json()['invites'][0]['recipient'], recipient1)

    def test_get_invite_by_id(self):
        recipient1 = self.random_email()
        recipient2 = self.random_email()

        # create senders
        res1 = self.create_user()

        # create recipients in the user table
        res1 = self.create_user(email=recipient1, name='Alice')
        res1 = self.create_user(email=recipient2, name='Betty')

        # create invites
        res2 = self.create_invites(recipient=recipient1, sender=self.email)
        res3 = self.create_invites(recipient=recipient2, sender=self.email)

        # get recipient1
        recipient1_id = res2.json()['invite']['id']
        res4 = self.get_invite(id=recipient1_id)
        self.assertEqual(res4.json().get('invite'), res2.json()['invite'])
        self.assertEqual(res4.json()['invite']['recipient'], recipient1)
        self.assertEqual(res4.json()['invite']['sender'], self.email)
        self.assertEqual(res4.json()['invite']['id'], recipient1_id)

    def test_resent_invite(self):
        recipient = self.random_email()
        # create senders
        res1 = self.create_user()
        
        # create recipients in the user table
        res1 = self.create_user(email=recipient, name='Alice')

        res2 = self.create_invites(recipient=recipient, sender=self.email)
        res3 = self.update_invite(id=res2.json()['invite']['id'],
                resend=True)

        self.assertEqual(res2.json(), res3.json())

    def test_decline_invite(self):
        recipient = self.random_email()
        res1 = self.create_user()
        res2 = self.create_user(email=recipient, name='Alice')
        res3 = self.create_invites(recipient=recipient, sender=self.email)
        res4 = self.update_invite(id=res3.json()['invite']['id'],
                decline=True)
        self.assertEqual(res4.json()['invite']['status'], 'declined')

    def test_delete_invite(self):
        recipient1 = self.random_email()
        recipient2 = self.random_email()

        res1 = self.create_user()
        # create recipients in the user table
        res1 = self.create_user(email=recipient1, name='Alice')
        res1 = self.create_user(email=recipient2, name='Betty')

        res2 = self.create_invites(recipient=recipient1, sender=self.email)
        recipient1_id = res2.json()['invite']['id']
        res3 = self.create_invites(recipient=recipient2, sender=self.email)
        recipient2_id = res3.json()['invite']['id']

        # ensure we have two records
        res4 = self.get_invites()
        self.assertEqual(len(res4.json()['invites']), 2)
        self.assertEqual(res4.json()['invites'][0]['recipient'], recipient1)
        self.assertEqual(res4.json()['invites'][1]['recipient'], recipient2)
        
        # we need to ensure these users are created
        res4 = self.get_user(recipient1)
        self.assertEqual(res4.json()['user']['email'], recipient1)
        res4 = self.get_user(recipient2)
        self.assertEqual(res4.json()['user']['email'], recipient2)
        
        # now delete recipient1
        res5 = self.delete_invite(id=recipient1_id)
        self.assertEqual(res5.json()['success'], True)

        # re-delete should yield false
        res6 = self.delete_invite(id=recipient1_id)
        self.assertEqual(res6.json()['success'], False)
        self.assertEqual(res6.json()['reason'], 'no-such-invitation')
        
        # recipient1 should not even be in users table anymore
        res7 = self.get_user(recipient1)
        self.assertEqual(res7.json()['success'], False)
        self.assertEqual(res7.json()['reason'], 'no-such-user')

        # we should only get one back
        res8 = self.get_invites()
        self.assertEqual(len(res8.json()['invites']), 1)
        self.assertEqual(res8.json()['invites'][0]['recipient'], recipient2)
