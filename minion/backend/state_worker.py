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


def find_session(scan, session_id):
    for session in scan['sessions']:
        if session['id'] == session_id:
            return session


@celery.task
def scan_start(scan_id, t):
    scans.update({"id": scan_id},
                 {"$set": {"state": "STARTED",
                           "started": datetime.datetime.utcfromtimestamp(t)}})

@celery.task
def scan_finish(scan_id, state, t):
    scans.update({"id": scan_id},
                 {"$set": {"state": state,
                           "finished": datetime.datetime.utcfromtimestamp(t)}})

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
                revoke(session['_task'], terminate=True, signal='SIGUSR1')

    except Exception as e:

        logger.exception("Error while processing task. Marking scan as FAILED.")

        try:
            if scan:
                scans.update({"id": scan_id}, {"$set": {"state": "FAILED", "finished": datetime.datetime.utcnow()}})
        except Exception as e:
            logger.exception("Error when marking scan as FAILED")

@celery.task
def session_queue(scan_id, session_id, t):
    scans.update({"id": scan_id, "sessions.id": session_id},
                 {"$set": {"sessions.$.state": "QUEUED",
                           "sessions.$.queued": datetime.datetime.utcfromtimestamp(t)}})    

@celery.task
def session_start(scan_id, session_id, t):
    scans.update({"id": scan_id, "sessions.id": session_id},
                 {"$set": {"sessions.$.state": "STARTED",
                           "sessions.$.queued": datetime.datetime.utcfromtimestamp(t)}})    

@celery.task
def session_set_task_id(scan_id, session_id, task_id):
    scans.update({"id": scan_id, "sessions.id": session_id},
                 {"$set": {"sessions.$._task": task_id}})

@celery.task
def session_report_issue(scan_id, session_id, issue):
    scans.update({"id": scan_id, "sessions.id": session_id},
                 {"$push": {"sessions.$.issues": issue}})

@celery.task
def session_finish(scan_id, session_id, state, t, failure=None):
    if failure:
        scans.update({"id": scan_id, "sessions.id": session_id},
                     {"$set": {"sessions.$.state": state,
                               "sessions.$.finished": datetime.datetime.utcfromtimestamp(t),
                               "sessions.$.failure": failure}})
    else:
        scans.update({"id": scan_id, "sessions.id": session_id},
                     {"$set": {"sessions.$.state": state,
                               "sessions.$.finished": datetime.datetime.utcfromtimestamp(t)}})
