# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from flask import Flask

app = Flask(__name__)

from minion.backend import api

def configure_app(app, debug=False):
    app.debug = debug
    return app
