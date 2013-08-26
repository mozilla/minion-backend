#!/usr/bin/env python

import calendar
import datetime
import importlib
import uuid

from flask import jsonify, request

import minion.backend.utils as backend_utils
import minion.backend.tasks as tasks
from minion.backend.app import app
from minion.backend.views.base import api_guard, scans, sites, users
from minion.backend.views.users import _find_sites_for_user, _find_sites_for_user_by_group_name
from minion.backend.views.scans import sanitize_scan, summarize_scan

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
# Accept a filter query: groups?=<group_name>&user?=<email_address>
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
    group_name = request.args.get('group_name')
    user_email = request.args.get('user')
    if user_email is not None:
        # User specified, so return recent scans for each site/plan that the user can see
        user = users.find_one({'email': user_email})
        if user is None:
            return jsonify(success=False, reason='no-such-user')
        if group_name:
            site_list = _find_sites_for_user_by_group_name(user_email, group_name)
        else:
            site_list = _find_sites_for_user(user_email)
        for site_url in sorted(site_list):
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
# Accept a filter query: groups?=<group_name>&user?=<email_address>
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
    group_name = request.args.get('group_name')
    user_email = request.args.get('user')
    if user_email is not None:
        # User specified, so return recent scans for each site/plan that the user can see
        user = users.find_one({'email': user_email})
        if user is None:
            return jsonify(success=False, reason='no-such-user')
        if group_name:
            site_list = _find_sites_for_user_by_group_name(user_email, group_name)
        else:
            site_list = _find_sites_for_user(user_email)

        for site_url in sorted(site_list):
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
