#!/usr/bin/env python

import calendar
import datetime
import functools
import importlib
import json
import operator
import re
import uuid

from flask import abort, Flask, render_template, redirect, url_for, session, jsonify, request, session
from pymongo import MongoClient

import minion.backend.utils as backend_utils
import tasks

backend_config = backend_utils.backend_config()

mongo_client = MongoClient(host=backend_config['mongodb']['host'], port=backend_config['mongodb']['port'])
plans = mongo_client.minion.plans
scans = mongo_client.minion.scans
users = mongo_client.minion.users
sites = mongo_client.minion.sites
groups = mongo_client.minion.groups

app = Flask(__name__)

def api_guard(view):
    """ Decorate a view function to be protected by requiring
    a secret key in X-Minion-Backend-Key header for the decorated
    backend API. If 'key' is False or not found in the config file,
    the decorator will assume no protection is needed and will grant
    access to all incoming request. """
    @functools.wraps(view)
    def verify_key(*args, **kwargs):
        token_in_header = request.headers.get('x-minion-backend-key')
        secret_key = backend_config['api'].get('key')
        if secret_key:
            if token_in_header:
                if token_in_header == secret_key:
                    return view(*args, **kwargs)
                else:
                    abort(401)
            else:
                abort(401)
        return view(*args, **kwargs)
    return verify_key

BUILTIN_PLUGINS = [
    'minion.plugins.basic.AlivePlugin',
    'minion.plugins.basic.HSTSPlugin',
    'minion.plugins.basic.XFrameOptionsPlugin',
    'minion.plugins.basic.XContentTypeOptionsPlugin',
    'minion.plugins.basic.XXSSProtectionPlugin',
    'minion.plugins.basic.ServerDetailsPlugin',
    'minion.plugins.basic.RobotsPlugin',
    'minion.plugins.basic.CSPPlugin',
]

TEST_PLUGINS = [
    'minion.plugins.test.DelayedPlugin',
    'minion.plugins.test.ExceptionPlugin',
    'minion.plugins.test.ErrorPlugin',
]

# This should move to a configuration file
OPTIONAL_PLUGINS = [
    'minion.plugins.garmr.GarmrPlugin',
    'minion.plugins.nmap.NMAPPlugin',
    'minion.plugins.skipfish.SkipfishPlugin',
    'minion.plugins.zap_plugin.ZAPPlugin',
    'minion.plugins.ssl.SSLPlugin'
]

#
# Build the plugin registry
#

plugins = {}

def _plugin_descriptor(plugin):
    return {'class': plugin.__module__ + "." + plugin.__name__,
            'name': plugin.name(),
            'version': plugin.version(),
            'weight': plugin.weight()}

def _split_plugin_class_name(plugin_class_name):
    e = plugin_class_name.split(".")
    return '.'.join(e[:-1]), e[-1]

def _register_plugin(plugin_class_name):
    package_name, class_name = _split_plugin_class_name(plugin_class_name)
    plugin_module = importlib.import_module(package_name, class_name)
    plugin_class = getattr(plugin_module, class_name)
    plugins[plugin_class_name] = {'clazz': plugin_class,
                                  'descriptor': _plugin_descriptor(plugin_class)}

for plugin_class_name in BUILTIN_PLUGINS:
    try:
        _register_plugin(plugin_class_name)
    except ImportError as e:
        pass

for plugin_class_name in OPTIONAL_PLUGINS:
    try:
        _register_plugin(plugin_class_name)
    except ImportError as e:
        pass

if app.debug:
    for plugin_class_name in TEST_PLUGINS:
        try:
            _register_plugin(plugin_class_name)
        except ImportError as e:
            pass

def sanitize_plan(plan):
    if plan.get('_id'):
        del plan['_id']
    for field in ('created',):
        if plan.get(field) is not None:
            plan[field] = calendar.timegm(plan[field].utctimetuple())
    return plan

def sanitize_session(session):
    for field in ('created', 'queued', 'started', 'finished'):
        if session.get(field) is not None:
            session[field] = calendar.timegm(session[field].utctimetuple())
    return session

def sanitize_scan(scan):
    if scan.get('plan'):
        sanitize_plan(scan['plan'])
    if scan.get('_id'):
        del scan['_id']
    for field in ('created', 'queued', 'started', 'finished'):
        if scan.get(field) is not None:
            scan[field] = calendar.timegm(scan[field].utctimetuple())
    if 'sessions' in scan:
        for session in scan['sessions']:
            sanitize_session(session)
    return scan

def sanitize_user(user):
    if '_id' in user:
        del user['_id']
    if 'created' in user:
        user['created'] = calendar.timegm(user['created'].utctimetuple())
    return user

def sanitize_site(site):
    if '_id' in site:
        del site['_id']
    if 'created' in site:
        site['created'] = calendar.timegm(site['created'].utctimetuple())
    return site

def sanitize_group(group):
    if '_id' in group:
        del group['_id']
    if 'created' in group:
        group['created'] = calendar.timegm(group['created'].utctimetuple())
    return group

def summarize_scan(scan):
    def _count_issues(scan, severity):
        count = 0
        for session in scan['sessions']:
            for issue in session['issues']:
                if issue['Severity'] == severity:
                    count += 1
        return count
    summary = { 'id': scan['id'],
                'state': scan['state'],
                'configuration': scan['configuration'],
                'plan': scan['plan'],
                'sessions': [ ],
                'created': scan.get('created'),
                'queued': scan.get('queued'),
                'finished': scan.get('finished'),
                'issues': { 'high': _count_issues(scan, 'High'),
                            'low': _count_issues(scan, 'Low'),
                            'medium': _count_issues(scan, 'Medium'),
                            'info': _count_issues(scan, 'Info') } }
    for session in scan['sessions']:
        summary['sessions'].append({ 'plugin': session['plugin'],
                                     'id': session['id'],
                                     'state': session['state'] })
    return summary

def _find_groups_for_site(site):
    """Find all the groups the site is part of"""
    return [g['name'] for g in groups.find({"sites":site})]

def _find_sites_for_user(email):
    """Find all sites that the user has access to"""
    sitez = set()
    for g in groups.find({"users":email}):
        for s in g['sites']:
            sitez.add(s)
    return list(sitez)

def _find_groups_for_user(email):
    """Find all the groups the user is in"""
    return [g['name'] for g in groups.find({"users":email})]

# Validation methods to be used on incoming objects

def _check_required_fields(o, fields):
    for field in fields:
        if field not in o:
            return False
    return True

def _check_site_url(url):
    regex = re.compile(r"^(http|https)://(localhost|([a-z0-9][-a-z0-9]+)(\.[a-z0-9][-a-z0-9]+)+)(:\d+)?$")
    return regex.match(url) is not None

def _check_group_exists(group_name):
    return groups.find_one({'name': group_name}) is not None

def _check_plan_exists(plan_name):
    return plans.find_one({'name': plan_name}) is not None

# API Methods to manage users

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
@api_guard
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
    #
    if 'groups' in new_user:
        for group_name in new_user.get('groups', []):
            if not _check_group_exists(group_name):
                return jsonify(success=False, reason='unknown-group')
    if 'role' in new_user:
        if new_user["role"] not in ("user", "administrator"):
            return jsonify(success=False, reason="invalid-role")
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

#
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
@api_guard
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
@api_guard
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

# API Methods to manage sites

#
# Expects a site id to GET:
#
#  GET /sites/b263bdc6-8692-4ace-aa8b-922b9ec0fc37
#
# Returns the site record:
#
#  { 'success': True,
#    'site': { 'id': 'b263bdc6-8692-4ace-aa8b-922b9ec0fc37',
#              'url': 'https://www.mozilla.com',
#              'groups': ['mozilla', 'key-initiatives'] } }
#
# The groups list is not part of the site but is generated by querying the groups records.
#
# Or returns an error:
#
#  { 'success': False, 'reason': 'site-already-exists' }
#
#

@app.route('/sites/<site_id>', methods=['GET'])
@api_guard
def get_site(site_id):
    site = sites.find_one({'id': site_id})
    if not site:
        return jsonify(success=False, reason='no-such-site')
    site['groups'] = _find_groups_for_site(site['url'])
    return jsonify(success=True, site=sanitize_site(site))

#
# Expects a partially filled out site as POST data:
#
#  POST /sites
#
#  { 'url': 'https://www.mozilla.com',
#    'plans': ['basic', 'nmap'],
#    'groups': ['mozilla', 'key-initiatives'] }
#
# Returns the full site record including the generated id:
#
#  { 'success': True,
#    'site': { 'id': 'b263bdc6-8692-4ace-aa8b-922b9ec0fc37',
#              'url': 'https://www.mozilla.com',
#              'plans': ['basic', 'nmap'],
#              'groups': ['mozilla', 'key-initiatives'] } }
#
# Or returns an error:
#
#  { 'success': False, 'reason': 'site-already-exists' }
#  { 'success': False, 'reason': 'Group xyz does not exist' }
#

@app.route('/sites', methods=['POST'])
@api_guard
def create_site():
    site = request.json
    # Verify incoming site: url must be valid, groups must exist, plans must exist
    if not _check_site_url(site.get('url')):
        return jsonify(success=False, reason='invalid-url')
    if not _check_required_fields(site, ['url']):
        return jsonify(success=False, reason='missing-required-field')
    for group in site.get('groups', []):
        if not _check_group_exists(group):
            return jsonify(success=False, reason='unknown-group')
    for plan_name in site.get('plans', []):
        if not _check_plan_exists(plan_name):
            return jsonify(success=False, reason='unknown-plan')
    if sites.find_one({'url': site['url']}) is not None:
        return jsonify(success=False, reason='site-already-exists')
    # Create the site
    new_site = { 'id': str(uuid.uuid4()),
                 'url':  site['url'],
                 'plans': site.get('plans', []),
                 'created': datetime.datetime.utcnow() }
    sites.insert(new_site)
    # Add the site to the groups - group membership is stored in the group object, not in the site
    for group_name in site.get('groups', []):
        # No need to check if the site is already in the group as we just added the site
        groups.update({'name':group_name},{'$addToSet': {'sites': site['url']}})
    new_site['groups'] = site.get('groups', [])
    # Return the new site
    return jsonify(success=True, site=sanitize_site(new_site))

#
# Expects a partially filled out site as POST data. The site with the
# specified site_id (in the URL) will be updated.
#
# It is not possible to change the url. For that you need to delete the
# site and create a new one.
#
#  POST /sites/<site_id>
#
#  { 'url': 'https://www.mozilla.com',
#    'plans': ['basic', 'nmap'],
#    'groups': ['mozilla', 'key-initiatives'] }
#
# Returns the full site record including the generated id:
#
#  { 'success': True,
#    'site': { 'id': 'b263bdc6-8692-4ace-aa8b-922b9ec0fc37',
#              'url': 'https://www.mozilla.com',
#              'plans': ['basic', 'nmap'],
#              'groups': ['mozilla', 'key-initiatives'] } }
#
# Or returns an error:
#
#  { 'success': False, 'reason': 'no-such-site' }
#  { 'success': False, 'reason': 'unknown-group' }
#  { 'success': False, 'reason': 'unknown-plan' }
#

@app.route('/sites/<site_id>', methods=['POST'])
@api_guard
def update_site(site_id):
    new_site = request.json
    # Verify incoming site. It must exist, groups must exist, plans must exist.
    site = sites.find_one({'id': site_id})
    if not site:
        return jsonify(success=False, reason='no-such-site')
    site['groups'] = _find_groups_for_site(site['url'])
    for group in new_site.get('groups', []):
        if not _check_group_exists(group):
            return jsonify(success=False, reason='unknown-group')
    for plan_name in new_site.get('plans', []):
        if not _check_plan_exists(plan_name):
            return jsonify(success=False, reason='unknown-plan')
    if 'groups' in new_site:
        # Add new groups
        for group_name in new_site.get('groups', []):
            if group_name not in site['groups']:
                groups.update({'name':group_name},{'$addToSet': {'sites': site['url']}})
        # Remove old groups
        for group_name in site['groups']:
            if group_name not in new_site.get('groups', []):
                groups.update({'name':group_name},{'$pull': {'sites': site['url']}})
    if 'plans' in new_site:
        # Update the site. At this point we can only update plans.
        sites.update({'id': site_id}, {'$set': {'plans': new_site.get('plans')}})
    # Return the updated site
    site = sites.find_one({'id': site_id})
    if not site:
        return jsonify(success=False, reason='no-such-site')
    site['groups'] = _find_groups_for_site(site['url'])
    return jsonify(success=True, site=sanitize_site(site))

#
# Retrieve all sites in minion
#
#  GET /sites
#
# Returns a list of sites
#
#  [{ 'id': 'b263bdc6-8692-4ace-aa8b-922b9ec0fc37',
#     'url': 'https://www.mozilla.com',
#     'groups': ['mozilla', 'key-initiatives'] },
#    ...]
#

@app.route('/sites', methods=['GET'])
@api_guard
def list_sites():
    sitez = [sanitize_site(site) for site in sites.find()]
    for site in sitez:
        site['groups'] = _find_groups_for_site(site['url'])
    return jsonify(success=True, sites=sitez)

# API Methods to return reports

#
# Returns a scan history report, which is simply a list of all
# scans that have been recently done.
#
# If the user is specified then only scans are returned that
# the user can see.

@app.route('/reports/history', methods=['GET'])
@api_guard
def get_reports_history():
    history = []
    user_email = request.args.get('user')
    if user_email is not None:
        user = users.find_one({'email': user_email})
        if user is None:
            return jsonify(success=False, reason='no-such-user')
        for s in scans.find({'configuration.target': {'$in': _find_sites_for_user(user_email)}}).sort("created", -1).limit(100):
            history.append(summarize_scan(sanitize_scan(s)))
    else:
        for s in scans.find({}).sort("created", -1).limit(100):
            history.append(summarize_scan(sanitize_scan(s)))
    return jsonify(success=True, report=history)

#
# Returns a status report that lists each site and attached plans
# together with the results from the last scan done.
#
# If the user is specified then the report will only include data
# that the user can see.
#
#  { 'report':
#       [{ 'plan': 'basic',
#          'scan': [...],
#          'target': 'http://www.mozilla.com',
#       }],
#    'success': True }

@app.route('/reports/status', methods=['GET'])
@api_guard
def get_reports_sites():
    result = []
    user_email = request.args.get('user')
    if user_email is not None:
        # User specified, so return recent scans for each site/plan that the user can see
        user = users.find_one({'email': user_email})
        if user is None:
            return jsonify(success=False, reason='no-such-user')
        for site_url in sorted(_find_sites_for_user(user_email)):
            site = sites.find_one({'url': site_url})
            if site is not None:
                for plan_name in site['plans']:
                    l = list(scans.find({'configuration.target':site['url'], 'plan.name': plan_name}).sort("created", -1).limit(1))
                    if len(l) == 1:
                        scan = summarize_scan(sanitize_scan(l[0]))
                        s = {v: scan.get(v) for v in ('id', 'created', 'state', 'issues')}
                        result.append({'target': site_url, 'plan': plan_name, 'scan': scan})
                    else:
                        result.append({'target': site_url, 'plan': plan_name, 'scan': None})
    return jsonify(success=True, report=result)

#
# Returns a status report that lists each site and attached plans
# together with the results from the last scan done.
#
# If the user is specified then the report will only include data
# that the user can see.
#  { 'report':
#       [{ 'issues': [..],
#          'target': 'http://mozilla.com
#       }],
#    'success': True }

@app.route('/reports/issues', methods=['GET'])
@api_guard
def get_reports_issues():
    result = []
    user_email = request.args.get('user')
    if user_email is not None:
        # User specified, so return recent scans for each site/plan that the user can see
        user = users.find_one({'email': user_email})
        if user is None:
            return jsonify(success=False, reason='no-such-user')
        for site_url in sorted(_find_sites_for_user(user_email)):
            r = {'target': site_url, 'issues': []}
            site = sites.find_one({'url': site_url})
            if site is not None:
                for plan_name in site['plans']:
                    for s in scans.find({'configuration.target':site['url'], 'plan.name': plan_name}).sort("created", -1).limit(1):
                        for session in s['sessions']:
                            for issue in session['issues']:
                                r['issues'].append({'severity': issue['Severity'],
                                                    'summary': issue['Summary'],
                                                    'scan': { 'id': s['id'] },
                                                    'id': issue['Id']})
            result.append(r)
    return jsonify(success=True, report=result)

# API Methods to manage plans

#
# Return a list of available plans. Plans are global and not
# limited to a specific user.
#
#  GET /plans
#
# Returns an array of plan:
#
#  { "success": true,
#    "plans": [ { "description": "Run an nmap scan",
#                 "name": "nmap" },
#               ... ] }
#

@app.route("/plans")
@api_guard
def get_plans():
    def _plan_description(plan):
        return { 'description': plan['description'], 'name': plan['name'] }
    return jsonify(success=True, plans=[_plan_description(plan) for plan in plans.find()])

#
# Return a single plan description. Takes the plan name.
#
#  GET /plans/:plan_name
#
# Returns a JSON structure that contains the complete plan
#
#  { "success": true,
#    "plan": { "description": "Run an nmap scan",
#               "name": "nmap",
#               "workflow": [ { "configuration": {},
#                               "description": "Run the NMAP scanner.",
#                               "plugin": { "version": "0.2",
#                                           "class": "minion.plugins.nmap.NMAPPlugin",
#                                           "weight": "light",
#                                           "name": "NMAP" } } ] }
#

@app.route("/plans/<plan_name>")
def get_plan(plan_name):
    plan = plans.find_one({"name": plan_name})
    if not plan:
        return jsonify(success=False)
    # Fill in the details of the plugin
    for step in plan['workflow']:
        plugin = plugins.get(step['plugin_name'])
        if plugin:
            step['plugin'] = plugin['descriptor']
        del step['plugin_name']
    return jsonify(success=True, plan=sanitize_plan(plan))

# API Methods to manage plugins

#
# Return a list of available plugins
#
#  GET /plugins
#

@app.route("/plugins")
def get_plugins():
    return jsonify(success=True, plugins=[plugin['descriptor'] for plugin in plugins.values()])

# API Methods to manage scans

#
# Return a scan. Returns the full scan including all issues.
#

@app.route("/scans/<scan_id>")
def get_scan(scan_id):
    scan = scans.find_one({"id": scan_id})
    if not scan:
        return jsonify(success=False)
    return jsonify(success=True, scan=sanitize_scan(scan))

#
# Return a scan summary. Returns just the basic info about a scan
# and no issues. Also includes a summary of found issues. (count)
#

@app.route("/scans/<scan_id>/summary")
def get_scan_summary(scan_id):
    scan = scans.find_one({"id": scan_id})
    if not scan:
        return jsonify(success=False)
    return jsonify(success=True, summary=summarize_scan(sanitize_scan(scan)))

#
# Create a scan by POSTING a configuration to the /scan
# resource. The configuration looks like this:
#
#   {
#      "plan": "tickle",
#      "configuration": {
#        "target": "http://foo"
#      }
#   }
#

@app.route("/scans", methods=["POST"])
def put_scan_create():
    # try to decode the configuration
    configuration = request.json
    # See if the plan exists
    plan = plans.find_one({"name": configuration['plan']})
    if not plan:
        return jsonify(success=False)
    # Merge the configuration
    # Create a scan object
    now = datetime.datetime.utcnow()
    scan = { "id": str(uuid.uuid4()),
             "state": "CREATED",
             "created": now,
             "queued": None,
             "started": None,
             "finished": None,
             "plan": { "name": plan['name'], "revision": 0 },
             "configuration": configuration['configuration'],
             "sessions": [],
             "meta": { "owner": None, "tags": [] } }
    for step in plan['workflow']:
        session_configuration = step['configuration']
        session_configuration.update(configuration['configuration'])
        session = { "id": str(uuid.uuid4()),
                    "state": "CREATED",
                    "plugin": plugins[step['plugin_name']]['descriptor'],
                    "configuration": session_configuration, # TODO Do recursive merging here, not just at the top level
                    "description": step["description"],
                    "artifacts": {},
                    "issues": [],
                    "created": now,
                    "queued": None,
                    "started": None,
                    "finished": None,
                    "progress": None }
        scan['sessions'].append(session)
    scans.insert(scan)
    return jsonify(success=True, scan=sanitize_scan(scan))

@app.route("/scans/<scan_id>/control", methods=["PUT"])
def put_scan_control(scan_id):
    # Find the scan
    scan = scans.find_one({"id": scan_id})
    if not scan:
        return jsonify(success=False, error='no-such-scan')
    # Check if the state is valid
    state = request.data
    if state not in ('START', 'STOP'):
        return jsonify(success=False, error='unknown-state')
    # Handle start
    if state == 'START':
        if scan['state'] != 'CREATED':
            return jsonify(success=False, error='invalid-state-transition')
        # Queue the scan to start
        scans.update({"id": scan_id}, {"$set": {"state": "QUEUED", "queued": datetime.datetime.utcnow()}})
        tasks.scan.apply_async([scan['id']], countdown=3, queue='scan')
    # Handle stop
    if state == 'STOP':
        scans.update({"id": scan_id}, {"$set": {"state": "STOPPING", "queued": datetime.datetime.utcnow()}})
        tasks.scan_stop.apply_async([scan['id']], queue='state')
    return jsonify(success=True)
