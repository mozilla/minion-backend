# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from flask import Flask, make_response, request

csp_app = Flask(__name__)
@csp_app.route('/test')
def endpoint():
    headers = request.args.getlist("headers")
    policy = request.args.get("policy", "default-src 'self';")
    res = make_response("")

    for h in headers:
        _h = h.lower()
        if _h == 'xcsp':
            res.headers.add('X-Content-Security-Policy', policy)
        elif _h == 'csp':
            res.headers.add('Content-Security-Policy', policy)
        elif _h == 'csp-ro':
            res.headers.add('Content-Security-Policy-Report-Only', policy)
        elif _h == "xcsp-ro":
            res.headers['X-Content-Security-Policy-Report-Only'] = policy
    return res

if __name__ == "__main__":
    csp_app.run(host="localhost", port=1234)
