#!/usr/bin/env python
from flask import jsonify

from minion.backend.app import app
from minion.backend.views.base import api_guard, plugins


# API Methods to manage plugins

#
# Return a list of available plugins
#
#  GET /plugins
#

@app.route("/plugins")
@api_guard
def get_plugins():
    return jsonify(success=True, plugins=[plugin['descriptor'] for plugin in plugins.values()])

