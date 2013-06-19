from mock import MagicMock
from base import TestBaseClass

from minion.plugins.basic import XFrameOptionsPlugin

def report_issues(stuff):
    return stuff[0]

class TestXFrameOptionsUT(TestBaseClass):
    #def setUp(self):
    #    super(TestXFrameOptionsUT, self).setUp()
         
    def test_allow_from_validator_return_false_for_getting_allow_from_colon(self):
        """ Test validator return False because it has ALLOW-FORM: """
        plugin = XFrameOptionsPlugin()
        plugin.configuration = self.configuration
        # setup mock
        self.compile.findall.return_value = True

        value = "ALLOW_FORM:"
        resp = plugin._allow_from_validator(value)
        self.assertEqual(resp, False)
        self.compile.findall.assert_called_with(value)

    def test_allow_from_validator_return_false_for_no_match(self):
        """ Test validator return False because it has no match (invalid) """
        plugin = XFrameOptionsPlugin()
        plugin.configuration = self.configuration
        self.compile.findall.return_value = False
        self.compile.match.return_value = False

        value = "ALLOW-FROMNOSPACE-FOR-YOU"
        resp = plugin._allow_from_validator(value)
        self.assertEqual(resp, False)
        self.compile.findall.assert_called_with(value)
        self.compile.match.assert_called_with(value)

    def test_allow_from_validator_return_false_for_containing_q_f_in_url(self):
        """ Test validator return False because url has query/fragement. """
        plugin = XFrameOptionsPlugin()
        plugin.configuration = self.configuration
        self.compile.findall.return_value = False
        matches_mk = MagicMock(name='matches.group()')
        self.compile.match.return_value = matches_mk
        matches_mk.group.return_value = "some-url"
        self.mk_urlparse.urlsplit.return_value = ('sch', 'dom', 'p', 'q', 'f')

        value = "ALLOW-FROM http://example.org".upper()
        resp = plugin._allow_from_validator(value)
        self.assertEqual(resp, False)
        self.compile.findall.assert_called_with(value)
        self.compile.match.assert_called_with(value)
        self.mk_urlparse.urlsplit.assert_called_with("some-url")
        matches_mk.group.assert_called_with('url')

    def test_allow_from_validator_return_false_for_scheme_not_in_http_https(self):
        """ Test validator return False because url scheme is not http/https. """
        plugin = XFrameOptionsPlugin()
        plugin.configuration = self.configuration
        self.compile.findall.return_value = False
        matches_mk = MagicMock(name='matches.group()')
        self.compile.match.return_value = matches_mk
        matches_mk.group.return_value = "some-url"
        self.mk_urlparse.urlsplit.return_value = ('sch', 'dom', '', '', '')

        value = "ALLOW-FROM http://example.org".upper()
        resp = plugin._allow_from_validator(value)
        self.assertEqual(resp, False)
        self.compile.findall.assert_called_with(value)
        self.compile.match.assert_called_with(value)
        self.mk_urlparse.urlsplit.assert_called_with("some-url")
        matches_mk.group.assert_called_with('url')

    def test_allow_from_validator_return_true(self):
        plugin = XFrameOptionsPlugin()
        plugin.configuration = self.configuration
        self.compile.findall.return_value = False
        matches_mk = MagicMock(name='matches.group()')
        self.compile.match.return_value = matches_mk
        matches_mk.group.return_value = "some-url"
        self.mk_urlparse.urlsplit.return_value = ('http', '', '', '', '')

        value = "ALLOW-FROM http://example.org".upper()
        resp = plugin._allow_from_validator(value)
        self.assertEqual(resp, True)
        self.compile.findall.assert_called_with(value)
        self.compile.match.assert_called_with(value)
        self.mk_urlparse.urlsplit.assert_called_with("some-url")
        matches_mk.group.assert_called_with('url')
