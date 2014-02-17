# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
from flask import Flask, make_response, request
from OpenSSL import SSL

hsts_app = Flask(__name__)
@hsts_app.route('/test')
def endpoint():
    value = request.args.get("hsts-value")
    res = make_response("")
    if value:
        res.headers['strict-transport-security'] = value
    return res

if __name__ == "__main__":
    data_path = os.path.join(os.path.dirname(__file__), "data")
    context = SSL.Context(SSL.SSLv23_METHOD)
    context.use_privatekey_file(os.path.join(data_path, "minion-test.key"))
    context.use_certificate_file(os.path.join(data_path, "minion-test.cert"))
    hsts_app.run(host='localhost', port=1234,
        ssl_context=context)
