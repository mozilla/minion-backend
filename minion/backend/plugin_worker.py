# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


import datetime
import json
import os
import uuid
import requests
import signal
import socket
import subprocess
import time
import traceback

from twisted.internet import reactor
from twisted.internet.error import ProcessDone, ProcessTerminated, ProcessExitedAlready
from twisted.internet.protocol import ProcessProtocol

from celery import Celery
from celery.signals import celeryd_after_setup
from celery.utils.log import get_task_logger
from celery.execute import send_task

from minion.backend.utils import backend_config


cfg = backend_config()
celery = Celery('tasks', broker=cfg['celery']['broker'], backend=cfg['celery']['backend'])
logger = get_task_logger(__name__)
plugin_runner_process = None


#
#
#

class Runner(ProcessProtocol):

    def __init__(self, plugin_class, configuration, session_id, callback):
        self._plugin_class = plugin_class
        self._configuration = configuration
        self._session_id = session_id
        self._callback = callback
        self._exit_status = None
        self._process = None
        self._buffer = ""

    # ProcessProtocol Methods

    def _parseLines(self, buffer):
        lines = buffer.split("\n")
        if len(lines) == 1:
            return ([], buffer)
        elif buffer.endswith("\n"):
            return (lines[0:-1],"")
        else:
            return (lines[0:-1],lines[-1])

    def outReceived(self, data):
        # Parse incoming data, taking incomplete lines into account
        buffer = self._buffer + data
        lines, self._buffer = self._parseLines(buffer)
        # Process all the complete lines that we received
        for line in lines:
            self._process_message(line)

    def errReceived(self, data):
        print "ERR", data

    def processEnded(self, reason):
        if isinstance(reason.value, ProcessTerminated):
            self._exit_status = reason.value.status
            print "TERMINATED", str(reason.value.status)
        if isinstance(reason.value, ProcessDone):
            self._exit_status = reason.value.status
            print "ENDED", str(reason.value.status)
        self._process = None
        reactor.stop()

    # Runner

    def _process_message(self, message):
        # TODO Harden this by catching JSON parse errors and invalid messages
        m = json.loads(message)
        self._callback(m)

    def _locate_program(self, program_name):
        for path in os.getenv('PATH').split(os.pathsep):
            program_path = os.path.join(path, program_name)
            if os.path.isfile(program_path) and os.access(program_path, os.X_OK):
                return program_path

    def run(self):

        #
        # Setup the arguments
        #

        self._arguments = [ "minion-plugin-runner",
                           "-c", json.dumps(self._configuration),
                           "-p", self._plugin_class,
                           "-s", self._session_id ]
        
        #
        # Spawn a plugin-runner process
        #

        plugin_runner_path = self._locate_program("minion-plugin-runner")
        if plugin_runner_path is None:
            # TODO EMIT FAILURE
            return False

        self._process = reactor.spawnProcess(self, plugin_runner_path, self._arguments, env=None)
    
        #
        # Run the twisted reactor. It will be stopped either when the plugin-runner has
        # finished or when it has timed out.
        #

        reactor.run()

        return self._exit_status

    def terminate(self):
        if self._process is not None:
            try:
                self._process.signalProcess('KILL')
            except ProcessExitedAlready as e:
                pass
        if self._terminate_id is not None:
            if self._terminate_id.active():
                self._terminate_id.cancel()
            self._terminate_id = None

    def schedule_stop(self):
        
        #
        # Send the plugin runner a USR1 signal to tell it to stop. Also
        # start a timer to force kill the runner if it does not stop
        # on time.
        #

        self._process.signalProcess(signal.SIGUSR1)
        self._terminate_id = reactor.callLater(10, self.terminate)


def get_scan(api_url, scan_id):
    r = requests.get(api_url + "/scans/" + scan_id)
    r.raise_for_status()
    j = r.json()
    return j['scan']

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

        scan = get_scan(cfg['api']['url'], scan_id)
        if not scan:
            logger.error("Cannot load scan %s" % scan_id)
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

        #scans.update({"id": scan['id'], "sessions.id": session['id']},
        #             {"$set": {"sessions.$.state": "STARTED",
        #                       "sessions.$.started": datetime.datetime.utcnow()}})
        send_task("minion.backend.state_worker.session_start",
                  [scan_id, session_id, time.time()],
                  queue='state').get()

        #
        # Start a subprocess with the plugin runner. The plugin runner manages running a plugin and ensures that
        # it will go through all start/issue/finish messages.
        #

        if True:

            global finished
            finished = None

            def message_callback(msg):
                print "GOT A MESSAGE", str(msg)
                # Ignore messages that we get after a finish message
                global finished
                if finished is not None:
                    logger.error("Plugin emitted (ignored) message after finishing: " + line)
                    return
                # Issue: persist it
                if msg['msg'] == 'issue':
                    send_task("minion.backend.state_worker.session_report_issue",
                              args=[scan_id, session_id, msg['data']],
                              queue='state').get()
                # Progress: update the progress
                if msg['msg'] == 'progress':
                    pass # TODO
                # Finish: update the session state, wait for the plugin runner to finish, return the state
                if msg['msg'] == 'finish':
                    finished = msg['data']['state']
                    if msg['data']['state'] in ('FINISHED', 'FAILED', 'STOPPED', 'TERMINATED', 'TIMEOUT', 'ABORTED'):
                        send_task("minion.backend.state_worker.session_finish",
                                  [scan['id'], session['id'], msg['data']['state'], time.time()],
                                  queue='state').get()
                        #scans.update({"id": scan['id'], "sessions.id": session['id']},
                        #             {"$set": {"sessions.$.state": msg['data']['state'],
                        #                       "sessions.$.finished": datetime.datetime.utcnow()}})
                

            runner = Runner(session['plugin']['class'], session['configuration'], session_id, message_callback)

            # Install a signal handler that will stop the runner when this task is revoked
            signal.signal(signal.SIGUSR1, lambda signum, frame: reactor.callFromThread(runner.schedule_stop))

            # Run the runner. It will start a reactor and run the plugin.
            return_code = runner.run()

            return finished

        if False:

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
                              args=[scan_id, session_id, msg['data']],
                              queue='state').get()

                # Progress: update the progress
                if msg['msg'] == 'progress':
                    pass # TODO

                # Finish: update the session state, wait for the plugin runner to finish, return the state
                if msg['msg'] == 'finish':
                    finished = msg['data']['state']
                    if msg['data']['state'] in ('FINISHED', 'FAILED', 'STOPPED', 'ABORTED'):
                        send_task("minion.backend.state_worker.session_finish",
                                  [scan['id'], session['id'], msg['data']['state'], time.time()],
                                  queue='state').get()
                        #scans.update({"id": scan['id'], "sessions.id": session['id']},
                        #             {"$set": {"sessions.$.state": msg['data']['state'],
                        #                       "sessions.$.finished": datetime.datetime.utcnow()}})

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
            #scans.update({"id": scan_id, "sessions.id": session_id},
            #             {"$set": {"sessions.$.state": "FAILED",
            #                       "sessions.$.finished": datetime.datetime.utcnow(),
            #                       "sessions.$.failure": failure}})
            send_task("minion.backend.state_worker.session_finish",
                      [scan_id, session_id, "FAILED", time.time(), failure],
                      queue='state').get()
        except Exception as e:
            logger.exception("Error when marking scan as FAILED")

        return "FAILED"
