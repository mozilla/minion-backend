# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from flask import Flask, make_response, request

server_details_app = Flask(__name__)
@server_details_app.route('/test')
def endpoint():
    headers = request.args.getlist("headers")
    values = request.args.getlist("values")

    res = make_response("")
    if headers and values:
        _headers = dict(zip(headers, values))
        for name, value in _headers.items():
            res.headers[name] = value
    return res

if __name__ == "__main__":
    server_details_app.run(host="localhost", port=1234)
