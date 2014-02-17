# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from flask import Flask, make_response

no_robot_app = Flask(__name__)
@no_robot_app.route('/')
def no_robots():
    res = make_response()
    return res

if __name__ == "__main__":
    no_robot_app.run(host="localhost", port=1236)
