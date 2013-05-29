# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


import datetime

from celery import Celery
from celery.app.control import Control
from celery.utils.log import get_task_logger
from celery.execute import send_task
from celery.task.control import revoke
from celery.exceptions import TaskRevokedError
from pymongo import MongoClient

from minion.backend.utils import backend_config


cfg = backend_config()

celery = Celery('tasks', broker=cfg['celery']['broker'], backend=cfg['celery']['backend'])
mongodb = MongoClient(host=cfg['mongodb']['host'], port=cfg['mongodb']['port'])

db = mongodb.minion
plans = db.plans
scans = db.scans


logger = get_task_logger(__name__)


def queue_for_session(session, cfg):
    queue = 'plugin'
    if 'plugin_worker_queues' in cfg:
        weight = session['plugin']['weight']
        if weight in ('heavy', 'light'):
            queue = cfg['plugin_worker_queues'][weight]
    return queue

@celery.task(ignore_result=True)
def scan(scan_id):

    #
    # See if the scan exists.
    #

    scan = scans.find_one({'id': scan_id})
    if not scan:
        logger.error("Cannot find scan %s" % scan_id)
        return

    #
    # Is the scan in the right state to be started?
    #

    if scan['state'] != 'QUEUED':
        logger.error("Scan %s has invalid state. Expected QUEUED but got %s" % (scan_id, scan['state']))
        return

    #
    # Move the scan to the STARTED state
    #

    scan['state'] = 'STARTED'
    scans.update({"id": scan_id}, {"$set": {"state": "STARTED", "started": datetime.datetime.utcnow()}})
    
    #
    # Run each plugin session
    #

    for session in scan['sessions']:

        #
        # Mark the session as QUEUED
        #

        session['state'] = 'QUEUED'
        scans.update({"id": scan['id'], "sessions.id": session['id']}, {"$set": {"sessions.$.state": "QUEUED", "sessions.$.queued": datetime.datetime.utcnow()}})
        
        #
        # Execute the plugin. The plugin worker will set the session state and issues.
        #

        logger.info("Scan %s running plugin %s" % (scan['id'], session['plugin']['class']))

        queue = queue_for_session(session, cfg)
        result = send_task("minion.backend.plugin_worker.run_plugin", args=[scan_id, session['id']], queue=queue)
        scans.update({"id": scan_id, "sessions.id": session['id']}, {"$set": {"sessions.$._task": result.id}})

        try:
            plugin_result = result.get()
        except TaskRevokedError as e:
            plugin_result = "STOPPED"

        session['state'] = plugin_result

        #
        # If the user stopped the workflow or if the plugin aborted then stop the whole scan
        #
        
        if plugin_result in ('ABORTED', 'STOPPED'):
            # Mark the scan as failed
            scans.update({"id": scan_id}, {"$set": {"state": plugin_result, "finished": datetime.datetime.utcnow()}})
            # Mark all remaining sessions as cancelled
            for s in scan['sessions']:
                if s['state'] == 'CREATED':
                    s['state'] = 'CANCELLED'
                    scans.update({"id": scan['id'], "sessions.id": s['id']}, {"$set": {"sessions.$.state": "CANCELLED", "sessions.$.finished": datetime.datetime.utcnow()}})
            # We are done with this scan
            return
        
    #
    # Move the scan to the FINISHED state
    #

    scan['state'] = 'FINISHED'
    scans.update({"id": scan_id}, {"$set": {"state": "FINISHED", "finished": datetime.datetime.utcnow()}})
