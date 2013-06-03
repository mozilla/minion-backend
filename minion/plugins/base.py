# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import logging
import os
import sys
import uuid

from twisted.internet import reactor
from twisted.internet.threads import deferToThread
from twisted.internet.error import ProcessDone, ProcessTerminated
from twisted.internet.protocol import ProcessProtocol
import zope.interface


class IPluginRunnerCallbacks(zope.interface.Interface):

    """
    Plugin implementations use these methods to notify the PluginRunner
    when its state has changed.
    """

    def report_start():
        """The plugin has started"""
    def report_progress(percentage, description):
        """This long running plugin has made some progress"""
    def report_issues(issues):
        """Plugin has issues to report."""
    def report_artifacts(name, paths):
        """Plugin has files available."""
    def report_finish(state = None):
        """Plugin is done"""


class IPlugin(zope.interface.Interface):

    """
    All plugins should implement this. This is their API.
    """

    # Plugin attributes, provided/configured by the PluginRunner.

    callbacks = zope.interface.Attribute("""The callbacks to send data back""")
    reactor = zope.interface.Attribute("""The reactor this plugin in running in""")
    configuration = zope.interface.Attribute("""The configuration""")
    work_directory = zope.interface.Attribute("""The path to the work directory""")
    session_id = zope.interface.Attribute("""The unique session id for this plugin""")

    # Plugin lifecycle methods. These are all called by the PluginRunner.

    def do_configure():
        """Configure the plugin"""
    def do_start():
        """Start the plugin"""
    def do_stop():
        """Stop the plugin"""


class AbstractPlugin:

    """
    Abstract plugin implementation that implements a plugin that does
    nothing. This is a good place for standard behaviour, etc.
    """

    @classmethod
    def name(cls):
        return getattr(cls, "PLUGIN_NAME", cls.__name__)

    @classmethod
    def version(cls):
        return getattr(cls, "PLUGIN_VERSION", "0.0")

    @classmethod
    def weight(cls):
        return getattr(cls, "PLUGIN_WEIGHT", "heavy")

    zope.interface.implements(IPlugin, IPluginRunnerCallbacks)

    # Plugins can finish in three states: succesfully, stopped and failed.

    EXIT_STATE_FINISHED = "FINISHED"
    EXIT_STATE_STOPPED  = "STOPPED"
    EXIT_STATE_FAILED   = "FAILED"
    EXIT_STATE_ABORTED  = "ABORTED"

    # Plugin methods. By default these do nothing.

    def do_configure(self):
        pass

    def do_start(self):
        pass

    def do_stop(self):
        pass

    # These are simply mapped to the callbacks for convenience

    def report_start(self):
        self.callbacks.report_start()

    def report_progress(self, percentage, description):
        self.callbacks.report_progress(percentage, description)

    def report_issues(self, issues):
        for issue in issues:
            issue['Id'] = str(uuid.uuid4())
        self.callbacks.report_issues(issues)

    def report_issue(self, issue):
        self.report_issues([issue])

    def report_artifacts(self, name, paths):
        self.callbacks.report_artifacts(name, paths)

    def report_finish(self, state=EXIT_STATE_FINISHED):
        self.callbacks.report_finish(state=state)
        reactor.stop()


class BlockingPlugin(AbstractPlugin):

    """
    Plugin that needs to run blocking code. It executes do_run() in a
    thread. When asked to stop it simply sets the stopped instance
    variable. This variable can be checked from the thread. If that
    is not sufficuent then a different strategy can be implemented
    by overriding do_stop and doing something different.
    """

    def __init__(self):
        self.stopped = False

    def do_run(self):
        self.report_issue({"Severity": "Error", "Summary": "You forgot to override BlockingPlugin.run()"})
        return AbstractPlugin.EXIT_STATUS_FAILED

    def _finish_with_success(self, result):
        logging.debug("BlockingPlugin._finish_with_success: %s" % str(result))
        if self.stopped:
            self.report_finish(state = result or AbstractPlugin.EXIT_STATE_STOPPED)
        else:
            self.report_finish(state = result or AbstractPlugin.EXIT_STATE_FINISHED)

    def _finish_with_failure(self, failure):
        logging.debug("BlockingPlugin._finish_with_failure: %s" % str(failure))
        self.report_issue({"Severity": "Error", "Summary": str(failure.value)}) # TODO Return a failure structure? {message, exception, etc...} ?
        self.report_finish(state = AbstractPlugin.EXIT_STATE_FAILED)

    def do_start(self):
        deferred = deferToThread(self.do_run)
        deferred.addCallback(self._finish_with_success)
        deferred.addErrback(self._finish_with_failure)
        return deferred

    def do_stop(self):
        self.stopped = True


class ExternalProcessProtocol(ProcessProtocol):

    """
    Protocol that delegates incoming data on stdout and stderr to the plugin. The
    plugin can capture the data and wait until the process is finished or process
    it immediately and report results back.
    """

    def __init__(self, plugin):
        self.plugin = plugin

    def outReceived(self, data):
        try:
            self.plugin.do_process_stdout(data)
        except Exception as e:
            logging.exception("Plugin threw an uncaught exception in do_process_stdout: " + str(e))
            self.plugin.report_finish(state = AbstractPlugin.EXIT_STATE_FAILED)

    def errReceived(self, data):
        try:
            self.plugin.do_process_stderr(data)
        except Exception as e:
            logging.exception("Plugin threw an uncaught exception in do_process_stderr: " + str(e))
            self.plugin.report_finish(state = AbstractPlugin.EXIT_STATE_FAILED)

    def processEnded(self, reason):
        logging.debug("ExternalProcessProtocol.processEnded: " + str(reason.value))
        if isinstance(reason.value, ProcessTerminated):
            try:
                self.plugin.do_process_ended(reason.value.status)
            except Exception as e:
                logging.exception("Plugin threw an uncaught exception in do_process_ended: " + str(e))
                self.plugin.report_finish(state = AbstractPlugin.EXIT_STATE_FAILED)
        elif isinstance(reason.value, ProcessDone):
            try:
                self.plugin.do_process_ended(reason.value.status)
            except Exception as e:
                logging.exception("Plugin threw an uncaught exception in do_process_ended: " + str(e))
                self.plugin.report_finish(state = AbstractPlugin.EXIT_STATE_FAILED)

class ExternalProcessPlugin(AbstractPlugin):

    """
    Plugin that spawns an external tool. This makes it simple to execute tools like
    nmap.

    The default behaviour of do_stop() is to simply kill the external tool. When the
    tool is killed and exits,
    """

    def __init__(self):
        self.stopping = False

    def locate_program(self, program_name):
        for path in os.getenv('PATH').split(os.pathsep):
            program_path = os.path.join(path, program_name)
            if os.path.isfile(program_path) and os.access(program_path, os.X_OK):
                return program_path

    def spawn(self, path, arguments):
        protocol = ExternalProcessProtocol(self)
        name = path.split('/')[-1]
        logging.debug("Executing %s %s" % (path, " ".join([name] + arguments)))
        self.process = reactor.spawnProcess(protocol, path, [name] + arguments)

    def do_process_ended(self, status):
        logging.debug("ExternalProcessPlugin.do_process_ended")
        if self.stopping:
            self.report_finish(AbstractPlugin.EXIT_STATE_STOPPED)
        else:
            self.report_finish()

    def do_process_stdout(self, data):
        pass

    def do_process_stderr(self, data):
        pass

    def do_stop(self):
        logging.debug("ExternalProcessPlugin.do_stop")
        self.stopping = True
        self.process.signalProcess('KILL')
