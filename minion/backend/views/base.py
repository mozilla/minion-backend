#!/usr/bin/env python

import calendar
import functools
import importlib
import inspect
import json
import pkgutil
import operator

from flask import abort, Flask, jsonify, request, session
from pymongo import MongoClient

from minion.backend.app import app
import minion.plugins
import minion.backend.utils as backend_utils
import minion.backend.tasks as tasks
from minion.plugins.base import AbstractPlugin

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

#
# Build the plugin registry
#

plugins = {}

def load_plugin():
    """ Load plugins if they are subclass of AbstractPlugin and
    are not known base subclasses such as BlockingPlugin. """

    DEFAULT_BASE_CLASSES = ('AbstractPlugin', 'BlockingPlugin', 'ExternalProcessPlugin')
    candidates = []
    base_package = minion.plugins
    prefix = base_package.__name__ + "."
    for importer, package, ispkg in pkgutil.iter_modules(base_package.__path__, prefix):
        module = __import__(package, fromlist=['plugins'])
        for name in dir(module):
            obj = getattr(module, name)
            if inspect.isclass(obj) and issubclass(obj, AbstractPlugin) and name not in DEFAULT_BASE_CLASSES:
                app.logger.info("Found %s" % str(obj))
                candidates.append(str(obj))

    for candidate in candidates:
        try:
            _register_plugin(candidate)
        except ImportError as e:
            app.logger.error("Unable to import %s" % candidate)
            pass

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

def _check_required_fields(expected, fields):
    if isinstance(fields, dict):
        fields = fields.keys()
    for field in fields:
        if field not in expected:
            return False
    return True

def sanitize_session(session):
    for field in ('created', 'queued', 'started', 'finished'):
        if session.get(field) is not None:
            session[field] = calendar.timegm(session[field].utctimetuple())
    return session


load_plugin()
