# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


import copy
import json
import os
import smtplib

DEFAULT_BACKEND_CONFIG = {
    'api': {
        'url': 'http://127.0.0.1:8383',
    },
    'celery': {
        'broker': 'amqp://guest@127.0.0.1:5672//',
        'backend': 'amqp'
    },
    'mongodb': {
        'host': '127.0.0.1',
        'port': 27017
    },
    'invitation': {
        'host': '127.0.0.1',
        'port': 25,
        'max_time_allowed': 3600 * 24 * 7 # seconds in 7 days
    }
}

DEFAULT_FRONTEND_CONFIG = {
    'mongodb': {
        'host': '127.0.0.1',
        'port': 27017
    }
}


def _load_config(name):
    if os.path.exists("/etc/minion/%s" % name):
        with open("/etc/minion/%s" % name) as fp:
            return json.load(fp)
    if os.path.exists(os.path.expanduser("~/.minion/%s" % name)):
        with open(os.path.expanduser("~/.minion/%s" % name)) as fp:
            return json.load(fp)

def backend_config():
    return _load_config("backend.json") or copy.deepcopy(DEFAULT_BACKEND_CONFIG)

def frontend_config():
    return _load_config("frontend.json") or copy.deepcopy(DEFAULT_FRONTEND_CONFIG)

def send_invite(recipient, recipient_name, sender, sender_name, base_url, id):
    """ Send an invitation to a recipient. """

    url = base_url.strip('/') + id
    invite_msg = """
Dear {recp_name}:

{sender_name} is inviting you to use Minion ({url}). Minion is a security testing framework \
built by Mozilla to bridge the gap between developers and security testers. Once you signup,
you can scan your projects and receive friendly web security assessment.

Thank you.

Sincerely,
Security Assurance Team at Mozilla

""".format(recp_name=recipient_name, sender_name=sender_name, url=url)

    config = backend_config()
    smtp = config['invitation']
    subject = "{sender_name} is inviting you to use Minion!".format(sender_name=sender_name)

    # we have the option to send this invitation 
    # via user's email (admin's own account) or
    # the email account specified by the config.
    # This option allows us to send invite by any
    # user in the future (if we wish to enabled that).
    # For now, we can assume admin's persona account
    # is passed.
    if sender is None:
        fromaddr = smtp['sender']
    else:
        fromaddr = sender
    toaddrs = ', '.join((recipient,))
    invite_msg = invite_msg.format(recp=recipient, url=url)
    body = ("From: %s\r\nTo: %s\r\nSubject: %s\r\n%s"
            %(fromaddr, toaddrs, subject, invite_msg))
    server = smtplib.SMTP(smtp['host'], smtp['port'])
    server.sendmail(fromaddr, toaddrs, body)
    server.quit()
