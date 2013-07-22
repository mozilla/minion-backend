#!/usr/bin/env python

import calendar
import datetime
import uuid
from flask import jsonify, request

import minion.backend.utils as backend_utils
import minion.backend.tasks as tasks
from minion.backend.app import app
from minion.backend.views.base import api_guard, backend_config, invites, users, groups, sites
from minion.backend.views.users import _find_groups_for_user, _find_sites_for_user

def search(model, filters=None):
    if filters:
        filters = {field: value for field, value in filters.iteritems() if value is not None}
        return model.find(filters)
    else:
        return model.find()

def sanitize_invite(invite):
    if invite.get('_id'):
        del invite['_id']
    if invite.get('sent_on'):
        invite['sent_on'] = calendar.timegm(invite['sent_on'].utctimetuple())
    if invite.get('accepted_on'):
        invite['accepted_on'] = calendar.timegm(invite['accepted_on'].utctimetuple())
    if invite.get('expire_on'):
        invite['expire_on'] = calendar.timegm(invite['expire_on'].utctimetuple())
    return invite

def sanitize_invites(invite_results):
    results = []
    for invite in invite_results:
        results.append(sanitize_invite(invite))
    return results

def update_group_association(old_email, new_email):
    """ Update all associations with the old email
    to the new email. """

    # first update all associations found in a group
    groups.update({'users': old_email}, 
        {'$set': {'users.$': new_email}},
        upsert=False,
        multi=True)
    
    
#
#
# Create a new invite
#
#  POST /invites
# 
#  {'recipient': 'recipient@example.org,
#    'sender': 'sender@example.org'}
#
#
#  Returns (id, recipient, recipient_name, 
#           sender, sender_name, sent_on, accepted_on,
#           expire_on, status)

@app.route('/invites', methods=['POST'])
@api_guard('application/json')
def create_invites():
    recipient = request.json['recipient']
    sender = request.json['sender']
    recipient_user = users.find_one({'email': recipient})
    recipient_invite = invites.find_one({'recipient': recipient})
    sender_user = users.find_one({'email': sender})
    # issue #120
    # To ensure no duplicate invitation is allowed, and to ensure
    # we don't corrupt user record in user table, any POST invitation
    # must check
    # (1) if user is not created in users collection - FALSE
    # (2) if user is created, BUT status is not 'invited' - FALSE
    # (3) recipient email is found in existing invitation record - FALSE
    if not recipient_user:
        return jsonify(success=False, 
                reason='recipient-not-found-in-user-record')
    elif recipient_user.get('status') != 'invited':
        return jsonify(success=False, 
                reason='recipient-already-joined')
    if recipient_invite:
        return jsonify(success=False,
                reason='duplicate-invitation-not-allowed')
    if not sender_user:
        return jsonify(success=False,
                reason='sender-not-found-in-user-record')

    invite_id = str(uuid.uuid4())
    # some users may not have name filled out?
    invite = {'id': invite_id,
              'recipient': recipient,
              'recipient_name': recipient_user['name'] or recipient,
              'sender': sender,
              'sender_name': sender_user['name'] or sender,
              'sent_on': None,
              'accepted_on': None,
              'status': 'pending',
              'expire_on': None,
              'max_time_allowed': request.json.get('max_time_allowed') \
                      or backend_config.get('invitation').get('max_time_allowed')}

    backend_utils.send_invite(
        invite['recipient'], 
        invite['recipient_name'], 
        invite['sender'],
        invite['sender_name'],
        request.json['base_url'],
        invite_id)
    invite['sent_on'] = datetime.datetime.utcnow()
    invite['expire_on'] = invite['sent_on'] + \
        datetime.timedelta(seconds=invite['max_time_allowed'])
    invites.insert(invite)
    return jsonify(success=True, invite=sanitize_invite(invite))


# 
# Get a list of invites based on filters.
# 
# GET /invites
# GET /invites?sender=<sender_email>
# GET /invites?recipient=<recipient_email>
#
# Returns a list of invites based on filters. Default to no filter.
# [{'id': 7be9f3b0-ca70-45df-a78a-fc86e541b5d6,
#   'recipient': 'recipient@example.org',
#   'recipient_name': 'recipient',
#   'sender': 'sender@example.org',
#   'sender_name': 'sender',
#   'sent_on': '1372181278',
#   'accepted_on': '1372181279',
#   'expire_on': 1372191288',
#   'status': 'used/expired/declined',
#   ....]
#

@app.route('/invites', methods=['GET'])
@api_guard
def get_invites():
    recipient = request.args.get('recipient', None)
    sender = request.args.get('sender', None)
    results = search(invites, filters={'sender': sender, 'recipient': recipient})
    return jsonify(success=True, invites=sanitize_invites(results))

# 
# GET an invitation record given the invitation id
#
# GET /invites/<id>
#
# Returns the invites data structure
# {'id': 7be9f3b0-ca70-45df-a78a-fc86e541b5d6,
#   'recipient': 'recipient@example.org',
#   'recipient_name': 'recipient',
#   'sender': 'sender@example.org',
#   'sender_name': 'sender',
#   'sent_on': '1372181278',
#   'accepted_on': '1372181279',
#   'expire_on': 1372191288',
#   'status': 'used/expired/declined'}
#

@app.route('/invites/<id>', methods=['GET'])
@api_guard
def get_invite(id):
    invitation = invites.find_one({'id': id})
    if invitation:
        return jsonify(success=True, invite=sanitize_invite(invitation))
    else:
        return jsonify(success=False, reason='invitation-does-not-exist')

#
# DELETE an invitation given the invitation id
#

@app.route('/invites/<id>', methods=['DELETE'])
@api_guard
def delete_invite(id):
    invitation = invites.find_one({'id': id})
    if not invitation:
        return jsonify(success=False, reason='no-such-invitation')
    # do not delete users that are not invite pending (bug #123)
    email = invitation['recipient']
    user = users.find_one({'email': email})
    if user and user.get('status') == "invited":
        users.remove(user)
        # bug #133 delete user associations
        for group_name in _find_groups_for_user(email):
            groups.update({'name':group_name}, {'$pull': {'users': email}})
        for site in _find_sites_for_user(email):
            sites.update({'url':site}, {'$pull': {'users': email}})
    invites.remove({'id': id})
    return jsonify(success=True)

## POST /invites/<id>/control
# {'action': 'resend'}
# {'action': 'accept'}
# {'action': 'decline'}
# Returns an updated invitation record
@app.route('/invites/<id>/control', methods=['POST'])
@api_guard('application/json')
def update_invite(id):
    timenow = datetime.datetime.utcnow()
    action = request.json['action'].lower()
    
    invitation = invites.find_one({'id': id})
    if invitation:
        max_time_allowed = invitation.get('max_time_allowed') \
            or backend_config.get('invitation').get('max_time_allowed')
        recipient = invitation['recipient']
        recipient_name = invitation['recipient_name']
        sender = invitation['sender']
        sender_name = invitation['sender_name']
        sent_on = invitation['sent_on']
        accepted_on = invitation['accepted_on']
        expire_on = invitation['expire_on']

        user = users.find_one({'email': recipient})
        if user is None:
            return jsonify(success=False, reason="user-not-created")
        if accepted_on is not None:
            return jsonify(success=False, reason="invitation-has-been-used")
        if not action in ('resend', 'accept', 'decline'):
            return jsonify(success=False, reason='invalid-action')

        if action == 'resend':
            new_id = str(uuid.uuid4())
            base_url = request.json['base_url']
            backend_utils.send_invite(recipient, recipient_name, sender, sender_name, base_url, new_id)
            # generate new record
            sent_on = datetime.datetime.utcnow()
            expire_on = sent_on + datetime.timedelta(seconds=max_time_allowed)
            invitation['id'] = new_id
            invitation['sent_on'] = sent_on
            invitation['expire_on'] = expire_on
            invites.update({'id': id}, {'$set': 
                {'sent_on': invitation['sent_on'],
                 'id': invitation['id']}})
            return jsonify(success=True, invite=sanitize_invite(invitation))
        elif action == 'accept':
            # if time now is ahead of expire_on, the delta is negative
            if (expire_on - timenow).seconds < 0:
                invitation['status'] = 'expired'
                invites.update({'id': id}, {'$set': {'status': 'expired'}})
                return jsonify(success=False, reason='invitation-expired')
            else:
                invitation['status'] = 'used'
                invitation['accepted_on'] = datetime.datetime.utcnow()
                invites.update({'id': id},{'$set': 
                    {'accepted_on': invitation['accepted_on'],
                     'status': 'used'}})
                users.update({'email': recipient}, {'$set': 
                    {'status': 'active', \
                     'email': request.json['login']}})
                if invitation['recipient'] != request.json['login']:
                    update_group_association(invitation['recipient'], request.json['login'])
                # if user's persona email is different
                invitation['recipient'] = request.json['login']
                return jsonify(success=True, invite=sanitize_invite(invitation))
        elif action == 'decline':
            invitation['status'] = 'declined'
            invites.update({'id': id}, {'$set': {'status': 'declined'}})
            return jsonify(success=True, invite=sanitize_invite(invitation))
    else:
        return jsonify(success=False, reason='invitation-does-not-exist')

