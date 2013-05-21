import datetime

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


#
# start_scan
#
#  Move the scan status from QUEUED to STARTED
#  Queue the first plugin session
#

@celery.task(ignore_result=True)
def scan_start(scan_id):
    logger.debug("This is scan_start " + scan_id)
    scan = scans.find_one({'id': scan_id})
    if not scan:
        logger.error("Cannot find scan %s" % scan_id)
        return
    if scan['state'] != 'QUEUED':
        logger.error("Scan %s has invalid state. Expected QUEUED but got %s" % (scan_id, scan['state']))
        return
    scans.update({"id": scan_id}, {"$set": {"state": "STARTED", "started": datetime.datetime.utcnow()}})
    run_next_plugin.apply_async([scan_id], queue='state')

#
# scan_stop
#

@celery.task(ignore_result=True)
def scan_stop(scan_id):
    pass

#
# scan_finish
#

@celery.task(ignore_result=True)
def scan_finish(scan_id):
    scan = scans.find_one({'id': scan_id})
    if not scan:
        logger.error("Cannot find scan %s" % scan_id)
        return
    if scan['state'] != 'STARTED':
        logger.error("Scan %s has invalid state. Expected STARTED but got %s" % (scan_id, scan['state']))
        return
    scans.update({"id": scan_id}, {"$set": {"state": "FINISHED", "finished": datetime.datetime.utcnow()}})


#
# run_next_plugin
#
#  Find the next plugin to be started
#  If there is one, start it
#  Otherwise finish the scan
#

@celery.task(ignore_result=True)
def run_next_plugin(scan_id):
    logger.debug("run_next_plugin " + scan_id)
    scan = scans.find_one({'id': scan_id})
    if not scan:
        logger.error("Cannot find scan %s" % scan_id)
        return
    if scan['state'] != 'STARTED':
        logger.error("Scan %s has invalid state. Expected STARTED but got %s" % (scan_id, scan['state']))
        return
    logger.debug("Looking for next session")
    session = None
    for s in scan['sessions']:
        if s['state'] == 'QUEUED':
            session = s
            break
    if not session:
        logger.debug("Did not find next session")
        scan_finish.apply_async([scan_id], queue='state')
    else:
        logger.debug("Found session " + s['id'])
        send_task("plugin_worker.run_plugin", args=[scan_id, session['id']], queue='plugin')


@celery.task(ignore_result=True)
def session_start(scan_id, session_id):
    logger.debug("This is session_start")
    scan = scans.find_one({"id": scan_id, "sessions.id": session_id})
    if not scan:
        logger.error("Cannot find session %s/%s" % (scan_id, session_id))
        return
    scans.update({"id": scan_id, "sessions.id": session_id}, {"$set": {"sessions.$.state": "STARTED", "sessions.$.started": datetime.datetime.utcnow()}})


#
# session_report_issue
#
#  Add the issues to the scan
#

@celery.task(ignore_result=True)
def session_report_issue(scan_id, session_id, issue):
    scan = scans.find_one({"id": scan_id, "sessions.id": session_id})
    if not scan:
        logger.error("Cannot find session %s/%s" % (scan_id, session_id))
        return
    scans.update({"id": scan_id, "sessions.id": session_id}, {"$push": {"sessions.$.issues": issue}})


@celery.task(ignore_result=True)
def session_finish(scan_id, session_id):
    scan = scans.find_one({"id": scan_id, "sessions.id": session_id})
    if not scan:
        logger.error("Cannot find session %s/%s" % (scan_id, session_id))
        return
    scans.update({"id": scan_id, "sessions.id": session_id}, {"$set": {"sessions.$.state": "FINISHED", "sessions.$.finished": datetime.datetime.utcnow()}})
    run_next_plugin.apply_async([scan_id], queue='state')
