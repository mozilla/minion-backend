# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import pprint

from minion.backend.api import BUILTIN_PLUGINS, TEST_PLUGINS
from base import BACKEND_KEY, TestAPIBaseClass

class TestAPIGuardDecorator(TestAPIBaseClass):
    def test_create_user_200(self):
        res = self.create_user()
        self.assertEqual(res.status_code, 200)

    #def test_create_user_401_without_header(self):
    #    res = self.create_user(headers={'Content-Type': 'application/json'})
    #    self.assertEqual(res.status_code, 401)

    #def test_create_user_401_with_incorrect_backend_key(self):
    #    res = self.create_user(headers={'Content-type': 'application/json',\
    #           'X-Minion-Backend-Key': 'I want to hack your server.'})
    #    self.assertEqual(res.status_code, 401)

    def test_create_user_200_lower_case_header(self):
        res = self.create_user(headers={'Content-type': 'application/json',\
                   'x-minion-backend-key': BACKEND_KEY})
        self.assertEqual(res.status_code, 200)

    def test_wrong_content_type_return_415(self):
        res = self.create_user(headers={'Content-type': 'text/plain',\
                   'x-minion-backend-key': BACKEND_KEY})
        self.assertEqual(res.status_code, 415)
