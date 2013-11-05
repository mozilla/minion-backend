#!/usr/bin/env python

from flask import jsonify, request
from minion.backend.views.base import api_guard, groups, sites, scans, sanitize_time
from minion.backend.app import app

#
# Search for issues:
#
#  /GET /issues
#
# Parameters:
#
#  group_name
#  plan_name
#  issue_code
#
# Returns:
#
#  { success: true,
#    issues: [
#      { site: "", scan_id: "", issue_id: "" }
#    ] }
#
# Examples:
#
#
#  Find all Server Identifying issues:
#
#   GET /issues?group_name=miniminion&plan_name=miniminion&issue_code=SD-0
#

#
# TODO This is all really bad. We get away with it because mongo is so fast but we
# obviously need to make some big changes in the data model.
#

@app.route('/issues', methods=['GET'])
@api_guard
def get_issues():
    issue_codes = request.args.getlist('issue_code')

    issues = []

    group = groups.find_one({'name': request.args.get('group_name')})
    if group is not None:
        for target in group['sites']:
            scan = scans.find_one({"plan.name": request.args.get('plan_name'),
                                   "configuration.target": target,
                                   "state": "FINISHED",
                                   "sessions.issues.Code": {"$in": issue_codes}},
                                  {"id": 1, "created": 1, "started": 1, "finished": 1,
                                   "configuration.target": 1, "sessions.issues.$": 1})
            if scan:
                hit = {"site": {"url": scan["configuration"]["target"]},
                       "scan": {"id": scan["id"],
                                "created": sanitize_time(scan["created"]),
                                "started": sanitize_time(scan["started"]),
                                "finished": sanitize_time(scan["finished"]),
                                "sessions": []}}
                for session in scan["sessions"]:
                    s = {"plugin": {"class": session["plugin"]["class"]}, "issues": []}
                    for issue in session['issues']:
                        if issue['Code'] in issue_codes:
                            s["issues"].append({"summary": issue["Summary"], "id": issue["Id"], "code": issue["Code"]})
                    hit["scan"]["sessions"].append(s)
                issues.append(hit)

    return jsonify(success=True, issues=issues)
