import json
import uuid
import subprocess

from celery import Celery
from celery.utils.log import get_task_logger
from celery.execute import send_task
from pymongo import MongoClient


celery = Celery('tasks', broker='amqp://guest@127.0.0.1//')
mongodb = MongoClient()

db = mongodb.minion
plans = db.plans
scans = db.scans


logger = get_task_logger(__name__)


def find_session(scan, session_id):
    for session in scan['sessions']:
        if session['id'] == session_id:
            return session


#
# run_plugin
#

@celery.task
def run_plugin(scan_id, session_id):

    logger.debug("This is run_plugin " + scan_id + " " + session_id)

    scan = scans.find_one({"id": scan_id, "sessions.id": session_id})
    if not scan:
        logger.error("Cannot find session %s/%s" % (scan_id, session_id))
        return
    if scan['state'] != 'STARTED':
        logger.error("Scan %s has invalid state. Expected STARTED but got %s" % (scan_id, scan['state']))
        return

    session = find_session(scan, session_id)
    if not session:
        logger.error("Cannot find session %s/%s" % (scan_id, session_id))
        return
    if session['state'] != 'QUEUED':
        logger.error("Session %s/%s has invalid state. Expected QUEUED but got %s" % (scan_id, session_id, session['state']))
        return

    p = subprocess.Popen(["minion-plugin-runner", "-c", json.dumps(session['configuration']), "-p", session['plugin']['class'], "-s", session_id, "-m", "json"], stdout=subprocess.PIPE)
    for line in p.stdout:
        msg = json.loads(line)
        if msg['msg'] == 'start':
            send_task("minion.backend.state_worker.session_start", args=[scan_id, session_id], queue='state')
        if msg['msg'] == 'issue':
            send_task("minion.backend.state_worker.session_report_issue", args=[scan_id, session_id, msg['data']], queue='state')
        if msg['msg'] == 'finish':
            send_task("minion.backend.state_worker.session_finish", args=[scan_id, session_id], queue='state')
