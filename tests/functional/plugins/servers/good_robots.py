# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from flask import Flask, redirect, url_for

good_robot_app = Flask(__name__)
@good_robot_app.route('/robots.txt')
def view():
    return redirect(url_for('static', filename='robots.txt'))

if __name__ == "__main__":
    good_robot_app.run(host="localhost", port=1234)
