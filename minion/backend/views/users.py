#!/usr/bin/env python

import calendar
import datetime
import uuid
from flask import jsonify, request

from minion.backend.app import app
from minion.backend.views.base import api_guard, groups, sites, users
from minion.backend.views.groups import _check_group_exists

def _find_groups_for_user(email):
    """Find all the groups the user is in"""
    return [g['name'] for g in groups.find({"users":email})]

def _find_sites_for_user(email):
    """Find all sites that the user has access to"""
    sitez = set()
    for g in groups.find({"users":email}):
        for s in g['sites']:
            sitez.add(s)
    return list(sitez)

def sanitize_user(user):
    if '_id' in user:
        del user['_id']
    if 'created' in user:
        user['created'] = calendar.timegm(user['created'].utctimetuple())
    return user

# API Methods to manage users

@app.route('/login', methods=['PUT'])
@api_guard('application/json')
def login_user():
    email = request.json['email']
    user = users.find_one({'email': email})
    if user:
        if user['status'] == 'active':
            return jsonify(success=True, user=sanitize_user(user))
        else:
            return jsonify(success=False, reason=user['status'])
    else:
        return jsonify(success=False, reason='user-does-not-exist')

@app.route('/users/<email>', methods=['GET'])
@api_guard
def get_user(email):
    email = email.lower()
    user = users.find_one({'email': email})
    if not user:
        return jsonify(success=False, reason='no-such-user')
    user['groups'] = _find_groups_for_user(user['email'])
    user['sites'] = _find_sites_for_user(user['email'])
    return jsonify(success=True, user=sanitize_user(user))

#
# Create a new user
#
#  POST /users
#
# Expects a partially filled out user record
#
#  { email: "foo@bar",
#    name: "Foo",
#    groups: ["foo"],
#    role: "user" }
#
# Optionally, the POST accepts creating user via invitations by adding
# 'invitation', 'url' and an optional 'sender' to the json input above.
# Returns the full user record
#
#  { "success": true
#    "user": { "created": 1371044067,
#              "groups": ["foo"],
#              "role": "user",
#              "id": "51f8417d-f7b0-48d1-8c18-dbf5e06c3261",
#              "name": "Foo",
#              "email": "foo@bar" } }
#

@app.route('/users', methods=['POST'])
@api_guard('application/json')
def create_user():
    user = request.json
    # Verify incoming user: email must not exist yet, groups must exist, role must exist
    if users.find_one({'email': user['email']}) is not None:
        return jsonify(success=False, reason='user-already-exists')
    for group_name in user.get('groups', []):
        if not _check_group_exists(group_name):
            return jsonify(success=False, reason='unknown-group')
    if user.get("role") not in ("user", "administrator"):
        return jsonify(success=False, reason="invalid-role")
    new_user = { 'id': str(uuid.uuid4()),
                 'status': 'invited' if user.get('invitation') else 'active',
                 'email':  user['email'],
                 'name': user.get('name'),
                 'role': user['role'],
                 'created': datetime.datetime.utcnow() }
    users.insert(new_user)
    # Add the user to the groups - group membership is stored in the group objet, not in the user
    for group_name in user.get('groups', []):
        groups.update({'name':group_name},{'$addToSet': {'users': user['email']}})
    new_user['groups'] = user.get('groups', [])
    return jsonify(success=True, user=sanitize_user(new_user))

#
# Expects a partially filled out user as POST data. The user with the
# specified user_email (in the URL) will be updated.
#
# Fields that can be changed:
#
#  name
#  role
#  groups
#
# Fields that are specified in the new user object will replace those in
# the existing user object.
#
# Returns the full user record.
#

@app.route('/users/<user_email>', methods=['POST'])
@api_guard
def update_user(user_email):
    new_user = request.json
    # Verify the incoming user: user must exist, groups must exist, role must exist
    old_user = users.find_one({'email': user_email})
    if old_user is None:
        return jsonify(success=False, reason='unknown-user')
    old_user['groups'] = _find_groups_for_user(user_email)
    old_user['sites'] = _find_sites_for_user(user_email)
    
    if 'groups' in new_user:
        for group_name in new_user.get('groups', []):
            if not _check_group_exists(group_name):
                return jsonify(success=False, reason='unknown-group')
    if 'role' in new_user:
        if new_user["role"] not in ("user", "administrator"):
            return jsonify(success=False, reason="invalid-role")
    if 'status' in new_user:
        if new_user['status'] not in ('active', 'banned'):
            return jsonify(success=False, reason='unknown-status-option')
    # Update the group memberships
    if 'groups' in new_user:
        # Add new groups
        for group_name in new_user.get('groups', []):
            if group_name not in old_user['groups']:
                groups.update({'name':group_name},{'$addToSet': {'users': user_email}})
        # Remove old groups
        for group_name in old_user['groups']:
            if group_name not in new_user.get('groups', []):
                groups.update({'name':group_name},{'$pull': {'users': user_email}})
    # Modify the user
    changes = {}
    if 'name' in new_user:
        changes['name'] = new_user['name']
    if 'role' in new_user:
        changes['role'] = new_user['role']
    if 'groups' in new_user:
        changes['groups'] = new_user['groups']
    if 'status' in new_user:
        changes['status'] = new_user['status']
    users.update({'email': user_email}, {'$set': changes})
    # Return the updated user
    user = users.find_one({'email': user_email})
    if not user:
        return jsonify(success=False, reason='unknown-user')
    user['groups'] = _find_groups_for_user(user_email)
    return jsonify(success=True, user=sanitize_user(user))

#
# Retrieve all users in minion
#
#  GET /users
#
# Returns a list of users
#
#  [{ 'id': 'b263bdc6-8692-4ace-aa8b-922b9ec0fc37',
#     'email': 'someone@somedomain',
#     'role': 'user',
#     'sites': ['https://www.mozilla.com'],
#     'groups': ['mozilla', 'key-initiatives'] },
#    ...]
#

@app.route('/users', methods=['GET'])
@api_guard
def list_users():
    userz = []
    for user in users.find():
        user['groups'] = _find_groups_for_user(user['email'])
        user['sites'] = _find_sites_for_user(user['email'])
        userz.append(sanitize_user(user))
    return jsonify(success=True, users=userz)

#
# Delete a user
#
#  DELETE /users/{email}
#

@app.route('/users/<user_email>', methods=['DELETE'])
@api_guard
def delete_user(user_email):
    user = users.find_one({'email': user_email})
    if not user:
        return jsonify(success=False, reason='no-such-user')
    # Remove the user
    users.remove({'email': user_email})
    # Remove user group membership
    for group_name in _find_groups_for_user(user_email):
        groups.update({'name':group_name},{'$pull': {'users': user_email}})
    return jsonify(success=True)


