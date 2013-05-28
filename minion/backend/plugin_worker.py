# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


import datetime
import json
import os
import uuid
import signal
import socket
import subprocess
import traceback

from celery import Celery
from celery.signals import celeryd_after_setup
from celery.utils.log import get_task_logger
from celery.execute import send_task

from pymongo import MongoClient

from minion.backend.utils import backend_config

cfg = backend_config()

celery = Celery('tasks', broker=cfg['celery']['broker'], backend=cfg['celery']['backend'])
mongodb = MongoClient(host=cfg['mongodb']['host'], port=cfg['mongodb']['port'])

db = mongodb.minion
plans = db.plans
scans = db.scans


logger = get_task_logger(__name__)
plugin_runner_process = None

#
# run_plugin
#

def find_session(scan, session_id):
    for session in scan['sessions']:
        if session['id'] == session_id:
            return session

@celery.task
def run_plugin(scan_id, session_id):

    logger.debug("This is run_plugin " + str(scan_id) + " " + str(session_id))

    try:

        #
        # Find the scan for this plugin session. Bail out if the scan has been marked as STOPPED or if
        # the state is not STARTED.
        #

        scan = scans.find_one({"id": scan_id, "sessions.id": session_id})
        if not scan:
            logger.error("Cannot find session %s/%s" % (scan_id, session_id))
            return

        if scan['state'] in ('STOPPING', 'STOPPED'):
            return

        if scan['state'] != 'STARTED':
            logger.error("Scan %s has invalid state. Expected STARTED but got %s" % (scan_id, scan['state']))
            return

        #
        # Find the plugin session in the scan. Bail out if the session has been marked as STOPPED or if
        # the state is not QUEUED.
        #

        session = find_session(scan, session_id)
        if not session:
            logger.error("Cannot find session %s/%s" % (scan_id, session_id))
            return

        if session['state'] != 'QUEUED':
            logger.error("Session %s/%s has invalid state. Expected QUEUED but got %s" % (scan_id, session_id, session['state']))
            return

        #
        # Move the session in the STARTED state
        #

        scans.update({"id": scan['id'], "sessions.id": session['id']},
                     {"$set": {"sessions.$.state": "STARTED",
                               "sessions.$.started": datetime.datetime.utcnow()}})

        #
        # Start a subprocess with the plugin runner. The plugin runner manages running a plugin and ensures that
        # it will go through all start/issue/finish messages.
        #

        command = [ "minion-plugin-runner",
                    "-c", json.dumps(session['configuration']),
                    "-p", session['plugin']['class'],
                    "-s", session_id ]

        plugin_runner_process = subprocess.Popen(command, stdout=subprocess.PIPE)

        #
        # Read the plugin runner stdout, which will have JSON formatted messages that have status updates from
        # the plugin. We simply queue those to the state queue which will do the right thing.
        #

        finished = None

        for line in plugin_runner_process.stdout:
            # Ignore messages that we get after a finish message
            if finished is not None:
                logger.error("Plugin emitted (ignored) message after finishing: " + line)
                continue
            
            # Parse the message
            msg = json.loads(line)
            
            # Issue: persist it
            if msg['msg'] == 'issue':
                send_task("minion.backend.state_worker.session_report_issue",
                          args=[scan_id, session_id, msg['data']], queue='state').get()
                
            # Progress: update the progress
            if msg['msg'] == 'progress':
                pass # TODO
            
            # Finish: update the session state, wait for the plugin runner to finish, return the state
            if msg['msg'] == 'finish':
                finished = msg['data']['state']
                if msg['data']['state'] in ('FINISHED', 'FAILED', 'STOPPED', 'ABORTED'):
                    scans.update({"id": scan['id'], "sessions.id": session['id']},
                                 {"$set": {"sessions.$.state": msg['data']['state'],
                                           "sessions.$.finished": datetime.datetime.utcnow()}})

        plugin_runner_process.wait()

        return finished
    
    except Exception as e:

        #
        # Our exception strategy is simple: if anything was thrown above that we did not explicitly catch then
        # we assume there was a non recoverable error that made the plugin session fail. We mark it as such and
        # record the exception.
        #

        logger.exception("Error while running plugin session. Marking session FAILED.")

        try:
            failure = { "hostname": socket.gethostname(),
                        "message": str(e),
                        "exception": traceback.format_exc() }
            scans.update({"id": scan_id, "sessions.id": session_id},
                         {"$set": {"sessions.$.state": "FAILED",
                                   "sessions.$.finished": datetime.datetime.utcnow(),
                                   "sessions.$.failure": failure}})
        except Exception as e:
            logger.exception("Error when marking scan as FAILED")

        return "FAILED"
