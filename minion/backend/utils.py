# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


import copy
import email as pyemail
import ipaddress
import re
import json
import jinja2
import os
import socket
import smtplib
import urlparse
import netaddr
from email.mime.text import MIMEText

DEFAULT_WHITELIST = []

DEFAULT_BLACKLIST = [
    '10.0.0.0/8',
    '127.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
    '169.254.0.0/16'
]

DEFAULT_SCAN_CONFIG = {
    'whitelist': DEFAULT_WHITELIST,
    'blacklist': DEFAULT_BLACKLIST
}

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
    'email': {
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

def scan_config():
    return _load_config("scan.json") or copy.deepcopy(DEFAULT_SCAN_CONFIG)

def scannable(target, whitelist=[], blacklist=[]):

    """
    Check the target url or CIDR network against a whitelist and blacklist.
    Returns whether the target is allowed to be scanned. Can throw exceptions
    if the hostname lookup fails.
    """

    def match(address, networks):
        for network in networks:
            network = ipaddress.IPv4Network(unicode(network))
            if ipaddress.IPv4Address(unicode(address)) in network:
                return True

    #
    # If the target is a CIDR network then for each IP address,
    # see if it matches the whitelist and blacklist. if it
    # matches the whitelist then we are good and check the next address. If it
    # matches the blacklist then we fail immediately.
    #

    try:
        cidr = netaddr.IPNetwork(target)

        for address in list(cidr):
            if match(str(address), whitelist):
                continue
            if match(str(address), blacklist):
                return False

        return True
    except:
        pass

    #
    # Else it's an url
    #

    url = urlparse.urlparse(target)

    #
    # Resolve the url's hostname to a list of IPv4 addresses. The getaddrinfo()
    # call is not ideal and should be replaced with a real dns module.
    #

    addresses = []

    infos = socket.getaddrinfo(url.hostname, None, socket.AF_INET, socket.SOCK_STREAM,
                               socket.IPPROTO_IP, socket.AI_CANONNAME)
    for info in infos:
        if info[0] == socket.AF_INET:
            addresses.append(info[4][0])

    #
    # For each IP address, see if it matches the whitelist and blacklist. if it
    # matches the whitelist then we are good and check the next address. If it
    # matches the blacklist then we fail immediately.
    #

    for address in addresses:
        if match(address, whitelist):
            continue
        if match(address, blacklist):
            return False

    return True

def get_template(template_file):
    template_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'templates')
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir))
    template = env.get_template(template_file)
    return template

def email(name, data):
    """ Send an email using a specific template. This uses
    Jinja2 template to render the text.

    We use the ``email`` module from the Python stdlib because
    it does prevent basic embedded header injections. """

    def _sanitize(data):
        """ Remove C0 and C1 control characters using regex. """
        ctrl_free_data = re.sub(r"[\x00-\x1F\x7F|\x80-\x9F]", "", data)
        return ctrl_free_data.strip(' \t\n\r')

    def _valid_email_address(email):
        """ Validate whether email address is valid or not. """
        return re.compile(r"[^@]+@[^@]+\.[^@]+").match(email)

    template_name = name + '.html'
    template = get_template(template_name)
    config = backend_config()

    # data should be free of control characters
    data = {key: _sanitize(value) for key, value in data.iteritems()}
    # if we happen to sanitize email to invalid email, abort
    if not data['from_email'] or not _valid_email_address(data['from_email']):
        raise ValueError("Invalid sender email address.")
    if not data['to_email'] or not _valid_email_address(data['to_email']):
        raise ValueError("Invalid receipient email address.")

    # setup email message
    body = template.render(data)
    msg = MIMEText(body)
    msg['To'] = pyemail.utils.formataddr((data['to_name'], data['to_email']))
    msg['From'] = pyemail.utils.formataddr((data['from_name'], data['from_email']))
    msg['Subject'] = data['subject']

    # setup SMTP
    s = smtplib.SMTP(config['email']['host'], config['email']['port'])
    try:
        s.sendmail(data['from_email'], data['to_email'], msg.as_string())
    finally:
        # caller should catch the smtplib exception
        # http://docs.python.org/2/library/smtplib.html
        s.quit()
