# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from flask import Flask, make_response, request

xcontent_app = Flask(__name__)
@xcontent_app.route('/test')
def endpoint():
    value = request.args.get("xcontent-value")
    res = make_response("")
    if value:
        res.headers['X-Content-Type-Options'] = value
    return res

if __name__ == "__main__":
    xcontent_app.run(host="localhost", port=1234)
