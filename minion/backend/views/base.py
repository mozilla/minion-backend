#!/usr/bin/env python

import calendar
import functools
import importlib
import json
import operator

from flask import abort, Flask, jsonify, request, session
from pymongo import MongoClient

import minion.backend.utils as backend_utils
import minion.backend.tasks as tasks

backend_config = backend_utils.backend_config()

mongo_client = MongoClient(host=backend_config['mongodb']['host'], port=backend_config['mongodb']['port'])
invites = mongo_client.minion.invites
groups = mongo_client.minion.groups
plans = mongo_client.minion.plans
scans = mongo_client.minion.scans
sites = mongo_client.minion.sites
users = mongo_client.minion.users

def api_guard(*decor_args):
    """ Decorate a view function to be protected by requiring
    a secret key in X-Minion-Backend-Key header for the decorated
    backend API. If 'key' is False or not found in the config file,
    the decorator will assume no protection is needed and will grant
    access to all incoming request.

    """
    def decorator(view):
        @functools.wraps(view)
        def check_session(*args, **kwargs):
            if isinstance(decor_args[0], str):
                if request.headers.get('content-type') != decor_args[0]:
                    abort(415)
            token_in_header = request.headers.get('x-minion-backend-key')
            secret_key = backend_config['api'].get('key')
            if secret_key:
                if token_in_header:
                    if token_in_header == secret_key:
                        return view(*args, **kwargs)
                    else:
                        abort(401)
                else:
                    abort(401)
            return view(*args, **kwargs)
        return check_session

    # the decorator can implicilty take the function being
    # decorated. We must ensure the arg is actually callable.
    # Otherwise, we call the decorator without any argument.
    if len(decor_args) == 1 and callable(decor_args[0]):
        return decorator(decor_args[0])
    else:
        return decorator

BUILTIN_PLUGINS = [
    'minion.plugins.basic.AlivePlugin',
    'minion.plugins.basic.HSTSPlugin',
    'minion.plugins.basic.XFrameOptionsPlugin',
    'minion.plugins.basic.XContentTypeOptionsPlugin',
    'minion.plugins.basic.XXSSProtectionPlugin',
    'minion.plugins.basic.ServerDetailsPlugin',
    'minion.plugins.basic.RobotsPlugin',
    'minion.plugins.basic.CSPPlugin',
]

TEST_PLUGINS = [
    'minion.plugins.test.DelayedPlugin',
    'minion.plugins.test.ExceptionPlugin',
    'minion.plugins.test.ErrorPlugin',
]

# This should move to a configuration file
OPTIONAL_PLUGINS = [
    'minion.plugins.garmr.GarmrPlugin',
    'minion.plugins.nmap.NMAPPlugin',
    'minion.plugins.skipfish.SkipfishPlugin',
    'minion.plugins.zap_plugin.ZAPPlugin',
    'minion.plugins.ssl.SSLPlugin'
]

#
# Build the plugin registry
#

plugins = {}

def _plugin_descriptor(plugin):
    return {'class': plugin.__module__ + "." + plugin.__name__,
            'name': plugin.name(),
            'version': plugin.version(),
            'weight': plugin.weight()}

def _split_plugin_class_name(plugin_class_name):
    e = plugin_class_name.split(".")
    return '.'.join(e[:-1]), e[-1]

def _import_plugin(plugin_class_name):
    package_name, class_name = _split_plugin_class_name(plugin_class_name)
    plugin_module = importlib.import_module(package_name, class_name)
    return getattr(plugin_module, class_name)

def _register_plugin(plugin_class_name):
    plugin_class = _import_plugin(plugin_class_name)
    plugins[plugin_class_name] = {'clazz': plugin_class,
                                  'descriptor': _plugin_descriptor(plugin_class)}

for plugin_class_name in BUILTIN_PLUGINS:
    try:
        _register_plugin(plugin_class_name)
    except ImportError as e:
        pass

for plugin_class_name in OPTIONAL_PLUGINS:
    try:
        _register_plugin(plugin_class_name)
    except ImportError as e:
        pass
"""
if app.debug:
    for plugin_class_name in TEST_PLUGINS:
        try:
            _register_plugin(plugin_class_name)
        except ImportError as e:
            pass
"""

def sanitize_session(session):
    for field in ('created', 'queued', 'started', 'finished'):
        if session.get(field) is not None:
            session[field] = calendar.timegm(session[field].utctimetuple())
    return session


