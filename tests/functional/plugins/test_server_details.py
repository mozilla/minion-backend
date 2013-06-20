# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from flask import make_response, request

from base import TestPluginBaseClass, test_app

# headers to be exposed
HEADERS = {
    'X-Powered-By': 'PHP/5.2.6',
    'X-AspNet-Version': '5.0.111212',
    'X-AspNetMvc-Version': '4.0',
    'X-Backend-Server': 'cheese-burger'
}

@test_app.route('/expose-single/<name>')
def respond_with_a_header(name):
    res = make_response('')
    res.headers[name] = HEADERS[name]
    return res

@test_app.route('/expose-all')
def respond_with_all_headers():
    res = make_response('')
    for name, value in HEADERS.iteritems():
        res.headers[name] = value
    return res

class TestServerDetailsPlugin(TestPluginBaseClass):
    __test__ = True
    @classmethod
    def setUpClass(cls):
        super(TestServerDetailsPlugin, cls).setUpClass()
        cls.pname = "ServerDetailsPlugin"

    def validate_server_details_plugin(self, runner_resp, request_resp, expected=None, expectation=True):
        if expectation == 'ALL':
            # the first report json returned must be [1], thus the number of issues reported is 
            # len(msgs) - 2
            self.assertEqual(expected, len(runner_resp)-2)
            count = 1
            for name, value in HEADERS.iteritems():
                self.assertEqual("%s is found" % name, runner_resp[count]['data']['Summary'])
                self.assertEqual("Site has set %s header" % name, \
                        runner_resp[count]['data']['Description'])
                count += 1
                self.assertEqual('Medium', runner_resp[count]['data']['Severity'])
        elif expectation == 'SINGLE':
            self.assertEqual('Medium', runner_resp[2]['data']['Severity'])
            self.assertEqual("Site has set %s header" % expected, \
                    runner_resp[2]['data']['Description'])
            self.assertEqual("%s is found" % expected, \
                    runner_resp[2]['data']['Summary'])

    """
    def test_server_exposes_single(self):
        for name, value in HEADERS.iteritems():
            api_name = '/expose-single/{name}'
            self.validate_plugin(api_name.format(name=name), self.validate_server_details_plugin, \
                    expected=name, expectation='SINGLE')
    """
