# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import unittest
from mock import MagicMock, patch

import minion.curly
from minion.backend import ownership

minion.curly.CurlyError = Exception
minion.curly.BadResponseError = Exception

class TestOwnership(unittest.TestCase):
    
    def setUp(self):
        self._mk1 = patch('minion.backend.ownership.urlparse')
        self._mk2 = patch('minion.backend.ownership.Popen')
        self._mk3 = patch('minion.backend.ownership.PIPE')
        self._mk4 = patch('minion.curly.get')
        

        self.mocks = []
        for i in xrange(1, 5):
            self.mocks.append(getattr(self, '_mk%s' % str(i)))

        self.mk_urlparse = self._mk1.start()
        self.mk_popen = self._mk2.start()
        self.mk_pipe = self._mk3.start()
        self.mk_curly = self._mk4.start()

        self.target = 'http://foobar.com'
        self.file_name = '/burger.txt'
        self.target_file = self.target + self.file_name

        # setup for verify_by_file
        self.mk_urlparse.urljoin.return_value = self.target_file
        self.r_obj = MagicMock()
        self.mk_curly.return_value = self.r_obj
    
        # setup for verify_by_header
        self.r_obj.headers = {}
        
        # setup for verify_by_dns_record
        self.mk_urlparse.urlparse.return_value = MagicMock()
        self.mk_urlparse.return_value.urlparse.netloc = "foobar.com"

    def tearDown(self):
        for mock in self.mocks:
            mock.stop()

    def _setup_exception(self, exception):
        self.mk_curly.return_value.raise_for_status.side_effect = exception("dummy")

    def test_verify_by_file_return_true(self):
        self.mk_curly.return_value.body = "cheese"
        resp = ownership.verify_by_file(self.target, "cheese", "burger.txt")
        self.assertEqual(True, resp)

    def test_verify_by_file_return_false(self):
        self.mk_curly.return_value.body = "ham"
        resp = ownership.verify_by_file(self.target, "cheese", "burger.txt")
        self.assertEqual(False, resp)

    # Now test verify_by_header

    def test_verify_by_header_return_true(self):
        self.mk_curly.return_value.headers['x-minion-site-ownership'] = 'foo'
        resp = ownership.verify_by_header(self.target, "foo")
        self.assertEqual(True, resp) 

    def test_verify_by_header_return_false(self):
        self.mk_curly.return_value.headers['x-minion-site-ownership'] = 'bar'
        resp = ownership.verify_by_header(self.target, "foo")
        self.assertEqual(False, resp) 

    # verify by dns record

    def test_verify_by_dns_record_return_True(self):
        self.mk_popen.return_value.communicate.return_value = ("cheese", "")
        resp = ownership.verify_by_dns_record(self.target, "cheese")
        self.assertEqual(True, resp)

    def test_verify_by_dns_record_return_False(self):
        self.mk_popen.return_value.communicate.return_value = ("ham", "")
        resp = ownership.verify_by_dns_record(self.target, "cheese")
        self.assertEqual(False, resp)
