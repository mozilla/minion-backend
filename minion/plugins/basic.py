# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import logging
import os
import time
import sys

from twisted.internet.task import LoopingCall

import requests
from minion.plugins.base import AbstractPlugin,BlockingPlugin,ExternalProcessPlugin


class XFrameOptionsPlugin(BlockingPlugin):

    """
    This is a minimal plugin that does one http request to find out if
    the X-Frame-Options header has been set. It does not override anything
    except start() since that one check is quick and there is no point
    in suspending/resuming/terminating.

    All plugins run in a separate process so we can safely do a blocking
    HTTP request. The PluginRunner catches exceptions thrown by start() and
    will report that back as an error state of the plugin.
    """

    def do_run(self):
        r = requests.get(self.configuration['target'], timeout=5.0)
        r.raise_for_status()
        if 'x-frame-options' in r.headers:
            if r.headers['x-frame-options'].upper() not in ('DENY', 'SAMEORIGIN'):
                self.report_issues([{ "Summary":"Site has X-Frame-Options header but it has an unknown or invalid value: %s" % r.headers['x-frame-options'],"Severity":"High" }])
            else:
                self.report_issues([{ "Summary":"Site has a correct X-Frame-Options header", "Severity":"Info" }])
        else:
            self.report_issues([{"Summary":"Site has no X-Frame-Options header set", "Severity":"High"}])


class HSTSPlugin(BlockingPlugin):

    """
    This plugin checks if the site sends out an HSTS header if it is HTTPS enabled.
    """

    def do_run(self):
        r = requests.get(self.configuration['target'], timeout=5.0)
        r.raise_for_status()
        if r.url.startswith("https://"):
            if 'strict-transport-security' not in r.headers:
                self.report_issues([{ "Summary":"Site does not set Strict-Transport-Security header", "Severity":"High" }])
            else:
                self.report_issues([{ "Summary":"Site sets Strict-Transport-Security header", "Severity":"Info" }])


class XContentTypeOptionsPlugin(BlockingPlugin):

    """
    This plugin checks if the site sends out a X-Content-Type-Options header
    """

    def do_run(self):
        r = requests.get(self.configuration['target'], timeout=5.0)
        r.raise_for_status()
        if 'X-Content-Type-Options' not in r.headers:
            self.report_issues([{ "Summary":"Site does not set X-Content-Type-Options header", "Severity":"High" }])
        else:
            if r.headers['X-Content-Type-Options'] == 'nosniff':
                self.report_issues([{ "Summary":"Site sets X-Content-Type-Options header", "Severity":"Info" }])
            else:
                self.report_issues([{ "Summary":"Site sets an invalid X-Content-Type-Options header", "Severity":"High" }])


class XXSSProtectionPlugin(BlockingPlugin):

    """
    This plugin checks if the site sends out a X-XSS-Protection header
    """

    def do_run(self):
        r = requests.get(self.configuration['target'], timeout=5.0)
        r.raise_for_status()
        if 'X-XSS-Protection' not in r.headers:
            self.report_issues([{ "Summary":"Site does not set X-XSS-Protection header", "Severity":"High" }])
        else:
            if r.headers['X-XSS-Protection'] == '1; mode=block':
                self.report_issues([{ "Summary":"Site sets X-XSS-Protection header", "Severity":"Info" }])
            elif r.headers['X-XSS-Protection'] == '0':
                self.report_issues([{ "Summary":"Site sets X-XSS-Protection header to disable the XSS filter", "Severity":"High" }])
            else:
                self.report_issues([{ "Summary":"Site sets an invalid X-XSS-Protection header: %s" % r.headers['X-XSS-Protection'], "Severity":"High" }])


class ServerDetailsPlugin(BlockingPlugin):

    """
    This plugin checks if the site sends out a Server or X-Powered-By header that exposes details about the server software.
    """

    def do_run(self):
        r = requests.get(self.configuration['target'], timeout=5.0)
        r.raise_for_status()
        HEADERS = ('Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version', 'X-Backend-Server')
        for header in HEADERS:
            if header in r.headers:
                self.report_issues([{ "Summary":"Site sets the '%s' header" % header, "Severity":"Medium" }])
