# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from flask import Flask, make_response, request

xframe_app = Flask(__name__)
@xframe_app.route('/test')
def endpoint():
    value = request.args.get("xframe-value")
    res = make_response("")
    if value:
        res.headers['X-Frame-Options'] = value
    return res

if __name__ == "__main__":
    xframe_app.run(host="localhost", port=1234)
