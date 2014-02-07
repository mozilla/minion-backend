# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import uuid

from base import (TestAPIBaseClass, User, Group, Invite, Invites, Site, Group)

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
        sender = User(self.email, name="Bob")
        sender.create()
        recipient = User(self.random_email(), name="Alice")
        recipient.invite()
        invite = Invite(sender.email, recipient.email)
        res = invite.create()
        self.assertEqual(res.json()["success"], True)

        expected_inner_keys = ("id", "recipient", "sender", "sent_on", \
                "accepted_on", "sender_name", "recipient_name", \
                "status", "expire_on", "max_time_allowed", "notify_when")

        self.assertEqual(set(res.json()['invite'].keys()),
            set(expected_inner_keys))

        self.assertEqual(res.json()['invite']['recipient'], recipient.email)
        self.assertEqual(res.json()['invite']['sender'], sender.email)
        self.assertEqual(res.json()['invite']['recipient_name'], recipient.name)
        self.assertEqual(res.json()['invite']['sender_name'], sender.name)
        self.assertEqual(True, res.json()['invite']['accepted_on'] is None)
        self.assertEqual(True, res.json()['invite']['sent_on'] is not None)
        self.assertEqual(True, res.json()['invite']['id'] is not None)
        # issue 172
        self.assertEqual(res.json()['invite']['status'], 'pending')

    # bug #133
    def test_send_invite_with_groups_and_sites(self):
        sender = User(self.email, name="Bob")
        sender.create()
        recipient = User(self.random_email(), name="Alice")
        recipient.invite()

        # create the invitation
        invite = Invite(sender.email, recipient.email)
        res = invite.create() 
        invite_id = res.json()['invite']['id']

        # create a site in minion
        site = Site(self.target_url)
        res2 = site.create()
        site_id = res2.json()["site"]["id"]

        # Uncomment the following checks when #297 is resolved.
        """
        # create a group in minion
        group = Group(self.group_name, sites=[site.url], users=[recipient.email])
        res3 = group.create()

        # site should exists in group and recipient should also be in the same group
        res4 = group.get()
        self.assertEqual(res4.json()['group']['users'], [recipient.email,])

        res5 = site.get(site_id)
        self.assertEqual(res5.json()["site"]["groups"], [group.group_name])

        # finally, if we query recipient's user object, user should be in
        # the group and have access to a site.
        res6 = recipient.get()
        self.assertEqual(res6.json()["user"]["sites"], [site.url])
        self.assertEqual(res6.json()["user"]["groups"], [group.group_name])
        """

    def test_invite_an_existing_user(self):
        sender = User(self.email)
        sender.create()
        recipient = User(self.random_email(), name="Alice")
        # don't invite, do a physical creation
        recipient.create()

        # try invite recipient even though recipient is an active member
        invite = Invite(sender.email, recipient.email)
        res = invite.create()
        self.assertEqual(res.json()['success'], False)
        self.assertEqual(res.json()['reason'], 'recipient-already-joined')

    def test_duplicate_invitations(self):
        sender = User(self.email)
        sender.create()
        recipient = User(self.random_email(), name="Alice")
        recipient.invite()

        # send first invitation to recipient
        invite = Invite(sender.email, recipient.email)
        res = invite.create()
        self.assertEqual(res.json()["success"], True)

        # send a second invitation to recipient
        res2 = invite.create()
        self.assertEqual(res2.json()['success'], False)
        self.assertEqual(res2.json()['reason'], 'duplicate-invitation-not-allowed')
        

    def test_sender_not_found(self):
        recipient = User(self.random_email(), name="Alice")
        recipient.invite()

        invite = Invite(self.email, recipient.email)
        res = invite.create()

        # sender self.email has not yet been created in minion
        self.assertEqual(res.json()['success'], False)
        self.assertEqual(res.json()['reason'], 'sender-not-found-in-user-record')

    def test_get_all_invites(self):
        # create a couple invitations and GET /invites should
        # return all the invitations in the system
        recipient1 = User(self.random_email())
        recipient1.invite()
        recipient2 = User(self.random_email())
        recipient2.invite()
        recipient3 = User(self.random_email())
        recipient3.invite()

        sender = User(self.random_email())
        sender.create()

        invite1 = Invite(sender.email, recipient1.email)
        invite1.create()
        invite2 = Invite(sender.email, recipient2.email)
        invite2.create()
        invite3 = Invite(sender.email, recipient3.email)
        invite3.create()

        res = Invites().get()
        self.assertEqual(len(res.json()['invites']), 3)
        self.assertEqual(res.json()['invites'][0]['recipient'], recipient1.email)
        self.assertEqual(res.json()['invites'][1]['recipient'], recipient2.email)
        self.assertEqual(res.json()['invites'][2]['recipient'], recipient3.email)

    def test_get_invites_filter_by_sender_and_or_recipient(self):
        # recipient1 will be invited by sender1
        # recipient2 and 3 will be invited by sender23
        recipient1 = User(self.random_email())
        recipient1.invite()
        recipient2 = User(self.random_email())
        recipient2.invite()
        recipient3 = User(self.random_email())
        recipient3.invite()

        sender1 = User(self.random_email())
        sender1.create()
        sender23 = User(self.random_email())
        sender23.create()

        invite1 = Invite(sender1.email, recipient1.email)
        invite1.create()
        invite2 = Invite(sender23.email, recipient2.email)
        invite2.create()
        invite3 = Invite(sender23.email, recipient3.email)
        invite3.create()

        # recipient1 should be given filter=sender1
        res1 = Invites().get(sender=sender1.email)
        self.assertEqual(len(res1.json()['invites']), 1)
        self.assertEqual(res1.json()['invites'][0]['recipient'], recipient1.email)
        self.assertEqual(res1.json()['invites'][0]['sender'], sender1.email)

        # recipient2 and 3 are returned given filter=sender23
        res2 = Invites().get(sender=sender23.email)
        self.assertEqual(len(res2.json()['invites']), 2)
        self.assertEqual(res2.json()['invites'][0]['recipient'], recipient2.email)
        self.assertEqual(res2.json()['invites'][1]['recipient'], recipient3.email)

        # no recipient is returned given filter=unknwon
        res3 = Invites().get(sender="unknown@example.org")
        self.assertEqual(len(res3.json()['invites']), 0)

        # recipient1 is returned given filter recipient=recipient1
        res4 = Invites().get(recipient=recipient1.email)
        self.assertEqual(len(res4.json()['invites']), 1)
        self.assertEqual(res4.json()['invites'][0]['recipient'], recipient1.email)

        # recipient2 is returned given filter recipient=recipient2 and sender=sender23
        res5 = Invites().get(recipient=recipient2.email,
            sender=sender23.email)
        self.assertEqual(len(res5.json()['invites']), 1)
        self.assertEqual(res5.json()['invites'][0]['recipient'], recipient2.email)

    def test_fetch_invite_by_id(self):
        recipient = User(self.random_email())
        recipient.invite()

        sender = User(self.random_email())
        sender.create()

        invite = Invite(sender.email, recipient.email)
        res = invite.create()
        self.assertEqual(res.json()["success"], True)
        invite_id = res.json()["invite"]["id"]

        res2 = invite.get(invite_id)
        self.assertEqual(res2.json()['invite']['recipient'], recipient.email)
        self.assertEqual(res2.json()['invite']['sender'], sender.email)
        self.assertEqual(res2.json()['invite']['id'], invite_id)

    def test_resend_invite(self):
        recipient = User(self.random_email())
        recipient.invite()

        sender = User(self.random_email())
        sender.create()

        invite = Invite(sender.email, recipient.email)
        res1 = invite.create()
        self.assertEqual(res1.json()["success"], True)
        old_invite_id = res1.json()["invite"]["id"]

        # resent invitation to recipient should produce a new invitiation id
        res2 = invite.update(old_invite_id, "resend", login=recipient.email)
        self.assertNotEqual(res2.json()['invite']['id'], old_invite_id)

    def test_decline_invite(self):
        recipient = User(self.random_email())
        recipient.invite()
        sender = User(self.random_email())
        sender.create()

        invite = Invite(sender.email, recipient.email)
        res1 = invite.create()
        invite_id = res1.json()["invite"]["id"]

        # create a group in minion that includes the recipient (bug#175)
        group = Group(self.group_name, users=[recipient.email])
        group.create()

        # ensure now the recipient is part of the new group
        res2 = recipient.get()
        self.assertEqual(res2.json()['user']['groups'], [group.group_name])

        # recipient has declined the invitation
        res3 = invite.update(invite_id, "decline", login=recipient.email)
        self.assertEqual(res3.json()['invite']['status'], 'declined')

        # when recipient declined, user account is deleted (bug #175)
        res4 = recipient.get()
        self.assertEqual(res4.json()['success'], False)
        self.assertEqual(res4.json()['reason'], 'no-such-user')

        # when recipient declined, user is also not part of a group anymore (bug #175)
        res5 = group.get()
        self.assertEqual(res5.json()['group']['users'], [])

    def test_delete_not_used_invitation(self):
        recipient = User(self.random_email())
        recipient.invite()
        sender = User(self.random_email())
        sender.create()

        invite = Invite(sender.email, recipient.email)
        res1 = invite.create()
        invite_id = res1.json()["invite"]["id"]

        # create a group in minion that includes the recipient (bug#175)
        group = Group(self.group_name, users=[recipient.email])
        group.create()

        # ensure now the recipient is part of the new group
        res2 = recipient.get()
        self.assertEqual(res2.json()['user']['groups'], [group.group_name])
        # also, this user is still marked as "invited"
        self.assertEqual(res2.json()['user']['status'], 'invited')

        # admin deletes this invitation off minion
        res3 = invite.delete(invite_id)
        self.assertEqual(res3.json()["success"], True)

        # since invitation is gone, user should be gone too
        res4 = recipient.get()
        self.assertEqual(res4.json()['success'], False)
        self.assertEqual(res4.json()['reason'], 'no-such-user')

        # recipient is also gone from any group association
        res5 = group.get()
        self.assertEqual(res5.json()['group']['users'], [])

    # bug #123
    def test_delete_invite_does_not_delete_accepted_user(self):
        # Delete recipient's invite does not delete the user if
        # recipient has already accepted the invitation.
        recipient = User(self.random_email())
        recipient.invite()
        sender = User(self.random_email())
        sender.create()

        invite = Invite(sender.email, recipient.email)

        res1 = invite.create()
        invite_id = res1.json()["invite"]["id"]

        # accept the invitation with the same invitation email
        res2 = invite.update(invite_id, "accept", login=recipient.email)
        self.assertEqual(res2.json()["success"], True)

        # upon invitation acceptance, user status changed to active
        res3 = recipient.get()        
        self.assertEqual(res3.json()['user']['email'], recipient.email)
        self.assertEqual(res3.json()['user']['status'], 'active')

        # now admin chooses to delete the invitation
        res4 = invite.delete(invite_id)
        self.assertEqual(res4.json()["success"], True)

        # check invitation is gone
        res5 = invite.get(invite_id)
        self.assertEqual(res5.json()['success'], False)
        self.assertEqual(res5.json()['reason'], 'invitation-does-not-exist')

        # yet, the user is still present
        res6 = recipient.get()
        self.assertEqual(res6.json()['success'], True)
        self.assertEqual(res6.json()['user']['email'], recipient.email)
        self.assertEqual(res6.json()['user']['status'], 'active')

    # bug #155
    def test_accept_invite_with_a_different_login_email(self):
        # we allow recipient to login with a different email address.
        recipient = User(self.random_email())
        recipient.invite()
        sender = User(self.random_email())
        sender.create()

        invite = Invite(sender.email, recipient.email)
        res1 = invite.create()
        invite_id = res1.json()["invite"]["id"]

        # create a group and a site and add the recipient to the group
        site = Site(self.target_url)
        res2 = site.create()

        # NOTE: Uncomment the following checks when #296 is resolved.
        """
        # create a group in minion
        group = Group(self.group_name, sites=[site.url], users=[recipient.email])
        group.create()

        # ensure user and site are in this new group
        res3 = group.get()
        self.assertEqual(res3.json()["group"]["sites"], [site.url])
        self.assertEqual(res3.json()["group"]["users"], [recipient.email])

        # user should have access to the group and the site
        res4 = recipient.get()
        self.assertEqual(res4.json()["user"]["sites"], [site.url])
        self.assertEqual(res4.json()["user"]["groups"], [group.group_name])

        # recipient accepts the invitation with a different login email address
        actual_login = self.random_email()
        recipient_2 = User(actual_login)
        res5 = invite.update(invite_id, "accept", login=recipient_2.email)
        self.assertEqual(res5.json()["success"], True)

        # upon invitation acceptance, user status changed to active
        res6 = recipient_2.get()
        self.assertEqual(res6.json()['user']['email'], recipient_2.email)
        self.assertEqual(res6.json()['user']['status'], 'active')
        # the new email address has access to the group and site
        self.assertEqual(res6.json()["user"]["groups"], [group.group_name])
        self.assertEqual(res6.json()["user"]["sites"], [site.url])

        # if we query the old recipient email, it should not be found
        res7 = recipient.get()
        self.assertEqual(res7.json()["success"], False)
        self.assertEqual(res7.json()["reason"], "no-such-user")

        # group should agree that user and site are still member of the group
        res8 = group.get()
        self.assertEqual(res8.json()["group"]["sites"], [site.url])
        self.assertEqual(res8.json()["group"]["users"], [recipient_2.email])
        """
