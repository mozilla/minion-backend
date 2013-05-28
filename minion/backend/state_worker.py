# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


import datetime

from celery import Celery
from celery.app.control import Control
from celery.utils.log import get_task_logger
from celery.execute import send_task
from celery.task.control import revoke
from pymongo import MongoClient

from minion.backend.utils import backend_config


cfg = backend_config()

celery = Celery('tasks', broker=cfg['celery']['broker'], backend=cfg['celery']['backend'])
mongodb = MongoClient(host=cfg['mongodb']['host'], port=cfg['mongodb']['port'])

db = mongodb.minion
plans = db.plans
scans = db.scans


logger = get_task_logger(__name__)


#
# Utility methods
#

def find_session(scan, session_id):
    """Find a session in a scan"""
    for s in scan['sessions']:
        if s['id'] == session_id:
            return s

def find_next_session(scan):
    """Find the next unscheduled session in a scan"""
    for s in scan['sessions']:
        if s['state'] == 'QUEUED':
            return s

def queue_for_session(session, cfg):
    queue = 'plugin'
    if 'plugin_worker_queues' in cfg:
        weight = session['plugin']['weight']
        if weight in ('heavy', 'light'):
            queue = cfg['plugin_worker_queues'][weight]
    return queue

#
# start_scan - Called when the user wants to start a scan
#

@celery.task
def scan_start(scan_id):

    try:
    
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
        # Find the next plugin session that we can schedule. If there are none then this scan is done. We
        # mark the scan as FINISHED and are done with this workflow.
        #
        
        session = find_next_session(scan)
        if not session:
            logger.debug("Did not find next session")
            scans.update({"id": scan_id}, {"$set": {"state": "FINISHED", "finished": datetime.datetime.utcnow()}})
            return

        #
        # Start the session by queueing it. Remember the celery task id in the session so that we can
        # reference it later if we need to revoke the plugin session.
        #
        # Before we queue we need to know if this plugin goes in the fast or flow queue. We take this info
        # from the plugin meta data that is embedded in the session.
        #

        # TODO Is it possible to ask Celery if the queue actually exists? Would be nice to report an error.

        queue = queue_for_session(session, cfg)
        result = send_task("minion.backend.plugin_worker.run_plugin", args=[scan_id, session['id']], queue=queue)
        scans.update({"id": scan_id, "sessions.id": session['id']}, {"$set": {"sessions.$._task": result.id}})

    except Exception as e:

        logger.exception("Error while processing task. Marking scan as FAILED.")

        try:
            if scan:
                scans.update({"id": scan_id}, {"$set": {"state": "FAILED", "finished": datetime.datetime.utcnow()}})
        except Exception as e:
            logger.exception("Error when marking scan as FAILED")

#
# scan_stop
#

@celery.task
def scan_stop(scan_id):

    logger.debug("This is scan_stop " + str(scan_id))

    try:

        #
        # Find the scan we are asked to stop
        #

        scan = scans.find_one({'id': scan_id})
        if not scan:
            logger.error("Cannot find scan %s" % scan_id)
            return

        #
        # Set the scan to cancelled. Even though some plugins may still run.
        #

        scans.update({"id": scan_id}, {"$set": {"state": "STOPPED", "started": datetime.datetime.utcnow()}})

        #
        # Set all QUEUED and STARTED sessions to STOPPED and revoke the sessions that have been queued
        #

        for session in scan['sessions']:
            if session['state'] in ('QUEUED', 'STARTED'):
                scans.update({"id": scan_id, "sessions.id": session['id']}, {"$set": {"sessions.$.state": "STOPPED", "sessions.$.finished": datetime.datetime.utcnow()}})            
            if '_task' in session:
                revoke(session['_task'])

    except Exception as e:

        logger.exception("Error while processing task. Marking scan as FAILED.")

        try:
            if scan:
                scans.update({"id": scan_id}, {"$set": {"state": "FAILED", "finished": datetime.datetime.utcnow()}})
        except Exception as e:
            logger.exception("Error when marking scan as FAILED")


#
# session_start - Called when a plugin session has started
#

@celery.task
def session_start(scan_id, session_id):

    try:

        #
        # Find the scan
        #

        scan = scans.find_one({"id": scan_id, "sessions.id": session_id})
        if not scan:
            logger.error("Cannot find session %s/%s" % (scan_id, session_id))
            return

        #
        # Change the session state to STARTED
        #

        scans.update({"id": scan_id, "sessions.id": session_id}, {"$set": {"sessions.$.state": "STARTED", "sessions.$.started": datetime.datetime.utcnow()}})

    except Exception as e:

        logger.exception("Error while processing task. Marking scan as FAILED.")

        try:
            if scan:
                scans.update({"id": scan_id}, {"$set": {"state": "FAILED", "finished": datetime.datetime.utcnow()}})
        except Exception as e:
            logger.exception("Error when marking scan as FAILED")


#
# session_report_issue
#

@celery.task
def session_report_issue(scan_id, session_id, issue):

    try:

        #
        # Find the scan
        #

        scan = scans.find_one({"id": scan_id, "sessions.id": session_id})
        if not scan:
            logger.error("Cannot find scan %s" % scan_id)
            return

        #
        # Make sure the scan contains the session
        #

        session = find_session(scan, session_id)
        if not session:
            logger.error("Cannot find session %s/%s" % (scan_id, session_id))
            return

        #
        # Make sure the session is in the right state
        #

        if session['state'] != 'STARTED':
            logger.error("Session %s/%s has invalid state. Expected STARTED but got %s" % (scan_id, session['id'], session['state']))
            return        

        #
        # Add the issue to the session
        #

        scans.update({"id": scan_id, "sessions.id": session_id}, {"$push": {"sessions.$.issues": issue}})

    except Exception as e:

        logger.exception("Error while processing task. Marking scan as FAILED.")

        try:
            if scan:
                scans.update({"id": scan_id}, {"$set": {"state": "FAILED", "finished": datetime.datetime.utcnow()}})
        except Exception as e:
            logger.exception("Error when marking scan as FAILED")


#
# session_finish
#

@celery.task
def session_finish(scan_id, session_id):

    try:

        #
        # Find the scan
        #

        scan = scans.find_one({"id": scan_id, "sessions.id": session_id})
        if not scan:
            logger.error("Cannot find scan %s" % scan_id)
            return

        #
        # Make sure the scan contains the session
        #

        session = find_session(scan, session_id)
        if not session:
            logger.error("Cannot find session %s/%s" % (scan_id, session_id))
            return

        #
        # Make sure the session is in the right state
        #

        if session['state'] != 'STARTED':
            logger.error("Session %s/%s has invalid state. Expected STARTED but got %s" % (scan_id, session['id'], session['state']))
            return

        #
        # If the last issue reported is FATAL then we abort this whole run
        #

        issue = session['issues'][-1]
        if issue['Severity'] == 'Fatal':
            # Mark the scan as failed
            scans.update({"id": scan_id}, {"$set": {"state": "FAILED", "finished": datetime.datetime.utcnow()}})
            # Mark this session as failed
            session['state'] = 'FAILED'
            scans.update({"id": scan_id, "sessions.id": session['id']}, {"$set": {"sessions.$.state": "FAILED", "sessions.$.finished": datetime.datetime.utcnow()}})
            # Mark all queued sessions as cancelled
            for session in scan['sessions']:
                if session['state'] == 'QUEUED':
                    session['state'] = 'CANCELLED'
                    scans.update({"id": scan_id, "sessions.id": session['id']}, {"$set": {"sessions.$.state": "CANCELLED", "sessions.$.finished": datetime.datetime.utcnow()}})
            return
        
        #
        # Change the session state to FINISHED
        #

        session['state'] = 'FINISHED'
        scans.update({"id": scan_id, "sessions.id": session_id}, {"$set": {"sessions.$.state": "FINISHED", "sessions.$.finished": datetime.datetime.utcnow()}})

        #
        # Find the next plugin session that we can schedule. If there are
        # none then this scan is done. We mark the scan as FINISHED and
        # are done with this workflow.
        #

        session = find_next_session(scan)
        if not session:
            scans.update({"id": scan_id}, {"$set": {"state": "FINISHED", "finished": datetime.datetime.utcnow()}})
            return

        #
        # We have a next plugin to run so we start the session by queueing
        # it. Remember the celery task id in the session so that we can
        # reference it later.
        #
        # Before we queue we need to know if this plugin goes in the
        # fast or flow queue. We take this info from the plugin meta
        # data that is embedded in the session.
        #

        # TODO Is it possible to ask Celery if the queue actually
        # exists? Would be nice to report an error.

        queue = queue_for_session(session, cfg)
        result = send_task("minion.backend.plugin_worker.run_plugin", args=[scan_id, session['id']], queue=queue)
        scans.update({"id": scan_id, "sessions.id": session['id']}, {"$set": {"sessions.$._task": result.id}})

    except Exception as e:

        logger.exception("Error while processing task. Marking scan as FAILED.")

        try:
            if scan:
                scans.update({"id": scan_id}, {"$set": {"state": "FAILED", "finished": datetime.datetime.utcnow()}})
        except Exception as e:
            logger.exception("Error when marking scan as FAILED")
