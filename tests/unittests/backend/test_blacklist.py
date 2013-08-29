# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


import unittest
from minion.backend.utils import scannable


class TestBlacklist(unittest.TestCase):

    blacklist = [ "192.168.0.0/16",   # Private
                  "10.0.0.0/8",       # Private
                  "172.16.0.0/12",    # Private
                  "127.0.0.0/8",      # Localhost
                  "169.254.0.0/16",   # Link-Local
                  "63.245.208.0/20" ] # Mozilla MOZNET-1

    whitelist = [ "192.168.0.42",   # In private space
                  "63.245.217.86" ] # mozillalabs.com/www.mozillalabs.com

    blacklisted_targets = [ "http://192.168.0.1",
                            "http://127.0.0.1",
                            "http://10.0.10.123",
                            "http://172.16.1.2",
                            "http://169.254.34.218",
                            "http://www.mozilla.com",                 # CNAME to A in MOZNET-1
                            "http://bl1.miniontest.arentz.ca",  # A 192.168.0.2
                            "http://bl2.miniontest.arentz.ca",  # CNAME blacklisted1
                            "http://bl3.miniontest.arentz.ca",  # CNAME to www.mozilla.com
                            "http://bl4.miniontest.arentz.ca",  # CNAME to arentz.ca,www.mo.o
                            "http://bl5.miniontest.arentz.ca" ] # A 46.23.88.82,127.0.0.1

    whitelisted_targets = [ "http://192.168.0.42",
                            "http://www.mozillalabs.com",
                            "http://mozillalabs.com" ]

    regular_targets = [ "http://www.apple.com",  # CNAME chain
                        "http://www.google.com", # multiple A
                        "http://46.23.88.82",    # direct ip
                        "http://www.soze.com" ]  # single CNAME

    def test_blacklisted_targets(self):
        for target in self.blacklisted_targets:
            self.assertFalse(scannable(target, self.whitelist, self.blacklist),
                             "Target is " + target)

    def test_whitelisted_targets(self):
        for target in self.whitelisted_targets:
            self.assertTrue(scannable(target, self.whitelist, self.blacklist),
                            "Target is " + target)

    def test_regular_targets(self):
        for target in self.regular_targets:
            self.assertTrue(scannable(target, self.whitelist, self.blacklist),
                            "Target is " + target)
