# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from minion.backend.app import app, configure_app

# Configure the app. Even in production we run with debug as that will
# give us stacktraces in the log. The debug REPL is always disabled.

app = configure_app(app, production=True, debug=True)
