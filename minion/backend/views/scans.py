#!/usr/bin/env python

import calendar
import datetime
import functools
import uuid
from flask import jsonify, request

import minion.backend.utils as backend_utils
import minion.backend.tasks as tasks
from minion.backend.app import app
from minion.backend.views.base import api_guard, groups, plans, plugins, scans, sanitize_session, users, sites
from minion.backend.views.plans import sanitize_plan

def permission(view):
    @functools.wraps(view)
    def has_permission(*args, **kwargs):
        email = request.args.get('email')
        if email:
            user = users.find_one({'email': email})
            if not user:
                return jsonify(success=False, reason='user-does-not-exist')
            scan = scans.find_one({"id": kwargs['scan_id']})
            if user['role'] == 'user':
                groupz = groups.find({'users': email, 'sites': scan['configuration']['target']})
                if not groupz.count():
                    return jsonify(success=False, reason='not-found')
        return view(*args, **kwargs) # if groupz.count is not zero, or user is admin
    return has_permission

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

def summarize_scan(scan):
    def _count_issues(scan, severity):
        count = 0
        for session in scan['sessions']:
            for issue in session['issues']:
                if issue['Severity'] == severity:
                    count += 1
        return count
    summary = { 'id': scan['id'],
                'meta': scan['meta'],
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

# API Methods to manage scans

#
# Return a scan. Returns the full scan including all issues.
#

@app.route("/scans/<scan_id>")
@api_guard
@permission
def get_scan(scan_id):
    scan = scans.find_one({"id": scan_id})
    if not scan:
        return jsonify(success=False, reason='not-found')
    return jsonify(success=True, scan=sanitize_scan(scan))

#
# Return a scan summary. Returns just the basic info about a scan
# and no issues. Also includes a summary of found issues. (count)
#

@app.route("/scans/<scan_id>/summary")
@api_guard
@permission
def get_scan_summary(scan_id):
    scan = scans.find_one({"id": scan_id})
    if not scan:
        return jsonify(success=False, reason='not-found')
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
@api_guard('application/json')
@permission
def post_scan_create():
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
             "meta": { "user": configuration['user'], "tags": [] } }
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

@app.route("/scans", methods=["GET"])
@permission
def get_scans():
    site = sites.find_one({'id': request.args.get('site_id')})
    if not site:
        return jsonify(success=False, reason='no-such-site')
    scanz = scans.find({"plan.name": request.args.get("plan_name"), "configuration.target": site['url']})
    return jsonify(success=True, scans=[summarize_scan(sanitize_scan(s)) for s in scanz])

@app.route("/scans/<scan_id>/control", methods=["PUT"])
@api_guard
@permission
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
