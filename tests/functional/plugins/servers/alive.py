# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from flask import Flask, make_response, request

alive_app = Flask(__name__)
@alive_app.route('/test')
def endpoint():
    timeout = request.args.get("timeout")
    res = make_response("")

    if timeout:
        time.sleep(5)
        return res
    else:
        return res

if __name__ == "__main__":
    alive_app.run(host="localhost", port=1234)
