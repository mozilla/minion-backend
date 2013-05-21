#!/usr/bin/env python

import datetime
import calendar
import json
import uuid

from flask import Flask, render_template, redirect, url_for, session, jsonify, request, session
from celery import Celery
from pymongo import MongoClient
from bson.json_util import dumps

import state_worker

mongodb = MongoClient()
db = mongodb.minion
plans = db.plans
scans = db.scans

app = Flask(__name__)

def sanitize_plan(plan):
    if plan.get('_id'):
        del plan['_id']
    for field in ('created',):
        if plan.get(field) is not None:
            plan[field] = calendar.timegm(plan[field].utctimetuple())
    return plan

def sanitize_scan(scan):
    if scan.get('plan'):
        sanitize_plan(scan['plan'])
    if scan.get('_id'):
        del scan['_id']
    for field in ('created', 'started', 'finished'):
        if scan.get(field) is not None:
            scan[field] = calendar.timegm(scan[field].utctimetuple())
    for session in scan['sessions']:
        for field in ('created', 'started', 'finished'):
            if session.get(field) is not None:
                session[field] = calendar.timegm(session[field].utctimetuple())
    return scan

@app.route("/scan/<scan_id>")
def get_scan(scan_id):
    scan = scans.find_one({"id": scan_id})
    if not scan:
        return jsonify(success=False)
    return jsonify(success=True, scan=sanitize_scan(scan))

@app.route("/plan/<plan_name>")
def get_plan(plan_name):
    plan = plans.find_one({"name": plan_name})
    if not plan:
        return jsonify(success=False)
    return jsonify(success=True, plan=sanitize_plan(plan))

@app.route("/scan/create/<plan_name>", methods=["PUT"])
def put_scan_create(plan_name):
    # try to decode the configuration
    configuration = request.json
    # See if the plan exists
    plan = plans.find_one({"name": plan_name})
    if not plan:
        return jsonify(success=False)
    # Merge the configuration
    # Create a scan object
    now = datetime.datetime.utcnow()
    scan = { "id": str(uuid.uuid4()),
             "state": "QUEUED",
             "created": now,
             "started": None,
             "finished": None,
             "plan": { "name": plan['name'], "revision": 0 },
             "configuration": configuration,
             "sessions": [],
             "meta": { "owner": None, "tags": [] } }
    for step in plan['workflow']:
        session_configuration = step['configuration']
        session_configuration.update(configuration)
        session = { "id": str(uuid.uuid4()),
                    "state": "QUEUED",
                    "plugin": { "version": "0.0", "name": "Unknown", "class": step["plugin_name"] },
                    "configuration": session_configuration, # TODO Do recursive merging here, not just at the top level
                    "description": step["description"],
                    "artifacts": {},
                    "issues": [],
                    "created": now,
                    "started": None,
                    "finished": None,
                    "progress": None }
        scan['sessions'].append(session)
    scans.insert(scan)
    return jsonify(success=True, scan=sanitize_scan(scan))

@app.route("/scan/<scan_id>/state", methods=["PUT"])
def put_scan_state(scan_id):
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
        if scan['state'] != 'QUEUED':
            return jsonify(success=False, error='invalid-state-transition')
        state_worker.scan_start.apply_async([scan['id']], queue='state')
    # Handle stop
    if state == 'STOP':
        if scan['state'] != 'STARTED':
            return jsonify(success=False, error='invalid-state-transition')
        state_worker.scan_stop.apply_async([scan['id']], queue='state')
    return jsonify(success=True)

if __name__ == "__main__":
   app.secret_key = "baconcheesebaconcheese"
   app.run(host='0.0.0.0', port=8383, debug=True)
