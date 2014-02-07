# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


import time
from minion.plugins.base import BlockingPlugin


class HelloWorldPlugin(BlockingPlugin):
    """ This plugin returns an issue immediately. """

    def do_run(self):
        issue = {"Summary": "Hello World", "Severity": "Info"}
        self.report_issues([issue])

class DelayedPlugin(BlockingPlugin):

    """
    This is a test plugin that waits 5 seconds, then emits an Info message
    and then waits another five seconds before it exits.
    """

    def do_run(self):
        for n in range(0,10):
            if self.stopped:
                return
            time.sleep(0.5)
        message = self.configuration.get('message', 'Hello, world')
        self.report_issues([{ "Summary":message, "Severity":"Info" }])
        for n in range(0,10):
            if self.stopped:
                return
            time.sleep(0.5)
        

class ExceptionPlugin(BlockingPlugin):

    """
    This is a test plugin that simply raises an exception.
    """

    def do_run(self):
        raise Exception("Failing plugins gonna fail")


class ErrorPlugin(BlockingPlugin):

    """
    This is a test plugin that simply trips an error.
    """

    def do_run(self):
        foo = bar
