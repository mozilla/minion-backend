# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


import copy
import json
import os


DEFAULT_BACKEND_CONFIG = {
    'api': {
        'url': 'http://127.0.0.1:8383',
        'key': 'somethingrandomcheese'
    },
    'celery': {
        'broker': 'amqp://guest@127.0.0.1:5672//',
        'backend': 'amqp'
    },
    'mongodb': {
        'host': '127.0.0.1',
        'port': 27017
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
