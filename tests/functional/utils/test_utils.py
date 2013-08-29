import unittest

from minion.backend import utils

class TestIP4BinaryConversion(unittest.TestCase):
    def test_172_16_254_1_convert_to_binary_properly(self):
        ip = '172.16.254.1'
        expected = '10101100000100001111111000000001'
        self.assertEqual(utils.ip4_to_binary(ip), expected)

class TestIsScannable(unittest.TestCase):
    def setUp(self):
        self.whitelist = [
            "192.168.1.1",
            "192.168.1.3",
            "192.168.255.254",
            "192.255.255.254"
        ]

        self.blacklist = [
            "127.0.0.1",
            "192.168.1.1/24",
            "localhost"
        ]

    def _scannable(self, url):
        return utils.scannable(url, self.whitelist, self.blacklist)

    def test_192_168_1_1_is_scannable(self):
        url = "http://192.168.1.1"
        self.assertEqual(True, self._scannable(url))

    def test_192_168_1_3_is_scannable(self):
        url = 'http://192.168.1.3'
        self.assertEqual(True, self._scannable(url))

    def test_192_168_255_254_is_scannable(self):
        url = "http://192.168.255.254"
        self.assertEqual(True, self._scannable(url))

    def test_192_255_255_254_is_scannable(self):
        url = "http://192.255.255.254"
        self.assertEqual(True, self._scannable(url))

    def test_192_168_1_2_is_not_scannable(self):
        url = "http://192.168.1.2"
        self.assertEqual(False, self._scannable(url))

    def test_192_168_1_254_is_not_scannable(self):
        url = "http://192.168.1.254"
        self.assertEqual(False, self._scannable(url))

    def test_172_173_174_175_is_scannable(self):
        url = "htp://172.173.174.175"
        self.assertEqual(True, self._scannable(url))

    def test_localhost_is_not_scannable(self):
        url = "http://localhost"
        self.assertEqual(False, self._scannable(url))
