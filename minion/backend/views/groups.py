#!/usr/bin/env python

import calendar
import datetime
import uuid
from flask import jsonify, request

import minion.backend.utils as backend_utils
import minion.backend.tasks as tasks
from minion.backend.app import app
from minion.backend.views.base import groups, api_guard

def _check_group_exists(group_name):
    return groups.find_one({'name': group_name}) is not None

def sanitize_group(group):
    if '_id' in group:
        del group['_id']
    if 'created' in group:
        group['created'] = calendar.timegm(group['created'].utctimetuple())
    return group

# Retrieve all groups in minion
#
#  GET /groups
#
# Returns a list of groups
#
#  [{ 'id': 'b263bdc6-8692-4ace-aa8b-922b9ec0fc37',
#     'created': 7261728192,
#     'name': 'someone@somedomain',
#     'description': 'user' },
#    ...]
#

@app.route('/groups', methods=['GET'])
@api_guard
def list_groups():
    return jsonify(success=True, groups=[sanitize_group(group) for group in groups.find()])

#
# Expects a partially filled out site as POST data:
#
#  POST /groups
#
#  { "name": "mozilla",
#    "description": "Mozilla Web Properties" }
#
# Returns the full group record including the generated id:
#
#  { "success": True,
#    "group": { "id': "b263bdc6-8692-4ace-aa8b-922b9ec0fc37",
#               "created": 7262918293,
#               "name': "mozilla",
#               "description": "Mozilla Web Properties" } }
#
# Or returns an error:
#
#  { 'success': False, 'reason': 'group-already-exists' }
#

@app.route('/groups', methods=['POST'])
@api_guard('application/json')
def create_group():
    group = request.json
    # TODO Verify incoming group: name must be valid, group must not exist already
    if groups.find_one({'name': group['name']}) is not None:
        return jsonify(success=False, reason='group-already-exists')
    new_group = { 'id': str(uuid.uuid4()),
                  'name':  group['name'],
                  'description': group.get('description', ""),
                  'sites': group.get('sites', []),
                  'users': group.get('users', []),
                  'created': datetime.datetime.utcnow() }
    groups.insert(new_group)
    return jsonify(success=True, group=sanitize_group(new_group))

@app.route('/groups/<group_name>', methods=['GET'])
@api_guard
def get_group(group_name):
    group = groups.find_one({'name': group_name})
    if not group:
        return jsonify(success=False, reason='no-such-group')
    return jsonify(success=True, group=sanitize_group(group))

#
# Delete the named group
#
#  DELETE /groups/:group_name
#

@app.route('/groups/<group_name>', methods=['DELETE'])
@api_guard
def delete_group(group_name):
    group = groups.find_one({'name': group_name})
    if not group:
        return jsonify(success=False, reason='no-such-group')
    groups.remove({'name': group_name})
    return jsonify(success=True)

#
# Patch (modify) a group record
#
#  POST /groups/:groupName
#
# Expects a JSON structure that contains patch operations as follows:
#
#  { addSites: ["http://foo.com"],
#    removeSites: ["http://bar.com"],
#    addUsers: ["foo@cheese"],
#    removeUsers: ["bar@bacon"] }
#

@app.route('/groups/<group_name>', methods=['PATCH'])
@api_guard('application/json')
def patch_group(group_name):
    group = groups.find_one({'name': group_name})
    if not group:
        return jsonify(success=False, reason='no-such-group')
    # Process the edits. These can probably be done in one operation.
    patch = request.json
    for site in patch.get('addSites', []):
        if isinstance(site, unicode):
            groups.update({'name':group_name},{'$push': {'sites': site}})
    for site in patch.get('removeSites', []):
        if isinstance(site, unicode):
            groups.update({'name':group_name},{'$pull': {'sites': site}})
    for user in patch.get('addUsers', []):
        if isinstance(user, unicode):
            groups.update({'name':group_name},{'$push': {'users': user}})
    for user in patch.get('removeUsers', []):
        if isinstance(user, unicode):
            groups.update({'name':group_name},{'$pull': {'users': user}})
    # Return the modified group
    group = groups.find_one({'name': group_name})
    return jsonify(success=True, group=sanitize_group(group))

