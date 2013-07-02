# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from flask import Flask
app = Flask(__name__)

import minion.backend.views.base
import minion.backend.views.groups
import minion.backend.views.invites
import minion.backend.views.reports
import minion.backend.views.users
import minion.backend.views.scans
import minion.backend.views.sites
import minion.backend.views.plans
import minion.backend.views.plugins

def configure_app(app, production=True, debug=False):
    app.debug = debug
    app.use_evalex = False
    return app
