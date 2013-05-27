#!/usr/bin/env python

import datetime
import calendar
import importlib
import json
import uuid

from flask import Flask, render_template, redirect, url_for, session, jsonify, request, session
from pymongo import MongoClient

import state_worker
from minion.backend.utils import backend_config

cfg = backend_config()

mongodb = MongoClient(host=cfg['mongodb']['host'], port=cfg['mongodb']['port'])
db = mongodb.minion
plans = db.plans
scans = db.scans

app = Flask(__name__)

BUILTIN_PLUGINS = [
    'minion.plugins.basic.HSTSPlugin',
    'minion.plugins.basic.XFrameOptionsPlugin',
    'minion.plugins.basic.XContentTypeOptionsPlugin',
    'minion.plugins.basic.XXSSProtectionPlugin',
    'minion.plugins.basic.ServerDetailsPlugin',
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
    print "Registered plugin", plugin_class_name

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
    # Fill in the details of the plugin
    for step in plan['workflow']:
        plugin = plugins.get(step['plugin_name'])
        if plugin:
            step['plugin'] = plugin['descriptor']
    return jsonify(success=True, plan=sanitize_plan(plan))

@app.route("/plugins")
def get_plugins():
    return jsonify(success=True, plugins=[plugin['descriptor'] for plugin in plugins.values()])

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
                    "plugin": plugins[step['plugin_name']]['descriptor'],
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
