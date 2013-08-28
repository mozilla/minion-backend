# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from flask import Flask, make_response, redirect, url_for
from multiprocessing import Process

from base import TestPluginBaseClass, test_app

@test_app.route('/robots.txt')
def robot():
    return redirect(url_for('static', filename='robots.txt'))

test3_app = Flask(__name__)
@test3_app.route('/')
def home():
    res = make_response()
    return res

test2_app = Flask(__name__)
@test2_app.route('/robots.txt')
def bad_robots():
    return redirect(url_for('static', filename='bad-robots.txt'))

APPS = {'test_app': test_app,
    'test2_app': test2_app,
    'test3_app': test3_app}

class TestRobotsPlugin(TestPluginBaseClass):
    __test__ = True

    @classmethod
    def setUpClass(cls):
        """ We have to launch three ports in order to test this plugin. """
        def run_app(port, app):
            test_app = APPS[app]
            test_app.run(host='localhost', port=port)

        cls.server1 = Process(target=run_app, args=(1234, 'test_app',))
        cls.server2 = Process(target=run_app, args=(1235, 'test2_app',))
        cls.server3 = Process(target=run_app, args=(1443, 'test3_app',))
        cls.server1.daemon = True
        cls.server2.daemon = True
        cls.server3.daemon = True
        cls.server1.start()
        cls.server2.start()
        cls.server3.start()

        cls.pname = "RobotsPlugin"

    @classmethod
    def tearDownClass(cls):
        cls.server1.terminate()
        cls.server2.terminate()
        cls.server3.terminate()

    def validate_robots_plugin(self, runner_resp, request_resp, expected=None, expectation=True, url=None):
        if expectation is True:
            self.assertEqual("robots.txt found", runner_resp[1]['data']['Summary'])
            self.assertEqual("Site has a valid robots.txt", runner_resp[1]['data']['Description'])
            self.assertEqual("Info", runner_resp[1]['data']['Severity'])
            self.assertEqual('FINISHED', runner_resp[2]['data']['state'])
        elif expectation == 'INVALID':
            self.assertEqual("Invalid entry found in robots.txt", runner_resp[1]['data']['Summary'])
            self.assertEqual("robots.txt may contain an invalid or unsupport entry.", \
                runner_resp[1]['data']['Description'])
            self.assertEqual("Medium", runner_resp[1]['data']['Severity'])
        elif expectation is False:
            self.assertEqual("robots.txt not found", runner_resp[1]['data']['Summary'])
            self.assertEqual("Site has no robots.txt", runner_resp[1]['data']['Description'])
            self.assertEqual("Medium", runner_resp[1]['data']['Severity'])


    def test_valid_robots_found_given_direct_url(self):
        api_name = '/robots.txt'
        self.validate_plugin(api_name, self.validate_robots_plugin, expectation=True, \
                base='http://localhost:1234')

    def test_valid_robots_found_given_root(self):
        api_name = '/'
        self.validate_plugin(api_name, self.validate_robots_plugin, expectation=True, \
                base='http://localhost:1234')

    def test_valid_robots_found_given_url_with_second_level(self):
        api_name = '/second/'
        self.validate_plugin(api_name, self.validate_robots_plugin, expectation=True, \
                base='http://localhost:1234')

    # now tests robots.txt with invalid content
    def test_invalid_robots_found_given_direct_url_(self):
        api_name = '/robots.txt'
        self.validate_plugin(api_name, self.validate_robots_plugin, expectation='INVALID', \
                base='http://localhost:1235')

    def test_invalid_robots_found_given_root(self):
        api_name = '/'
        self.validate_plugin(api_name, self.validate_robots_plugin, expectation='INVALID', \
                base='http://localhost:1235')

    def test_invalid_robots_found_given_url_with_second_level(self):
        api_name = '/second/'
        self.validate_plugin(api_name, self.validate_robots_plugin, expectation='INVALID', \
                base='http://localhost:1235')

    # now tests missing robots
    def test_robots_missing_given_direct_url_(self):
        api_name = '/robots.txt'
        self.validate_plugin(api_name, self.validate_robots_plugin, expectation=False, \
                base='http://localhost:1443')

    def test_robots_missing_given_root(self):
        api_name = '/'
        self.validate_plugin(api_name, self.validate_robots_plugin, expectation=False, \
                base='http://localhost:1443')

    def test_robots_missing_given_url_with_second_level(self):
        api_name = '/second/'
        self.validate_plugin(api_name, self.validate_robots_plugin, expectation=False, \
                base='http://localhost:1443')
