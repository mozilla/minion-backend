# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


import socket
import unittest
from minion.backend.utils import scannable

class TestBlacklist(unittest.TestCase):

    blacklist = [
        "0.0.0.0/8",            # Broadcast messages
        "10.0.0.0/8",           # Private
        "63.245.208.0/20",      # Mozilla MOZNET-1
        "100.64.0.0/10",        # RFC 6598
        "127.0.0.0/8",          # Loopback (localhost)
        "169.254.0.0/16",       # Link-Local
        "172.16.0.0/12",        # Private
        "192.0.0.0/24",         # RFC 5736
        "192.88.99.0/24",       # RFC 3068
        "192.168.0.0/16",       # Private
        "198.18.0.0/15",        # RFC 2544
        "224.0.0.0/4",          # Multicast
        "240.0.0.0/4",          # RFC 5771
        "255.255.255.255/32",   # Broadcast
        "::/128",               # Unspecified address
        "::1/128",              # Loopback (localhost)
        "::ffff:0:0/96",        # IPv4 mapped addresses
        "64:ff9b::/96",         # RFC 6052 (IPv4->IPv6 translation)
        "100::/64",             # RFC 6666 (black hole)
        "2001::/32",            # Teredo
        "2001:10::/28",         # Deprecated (ORCHID)
        "2001:20::/28",         # Orchidv2
        "2002::/16",            # 6to4
        "fc00::/7",             # Private
        "fd00::/8",             # Private
        "fe80::/10",            # Link-Local (IPv6)
        "ff00::/8",             # Multicast
        "www.nsa.gov",          # Random hostname without glob
        "*.gchq.gov.uk"         # Hostname without glob
    ]

    whitelist = [
        "63.245.217.86",        # mozillalabs.com/www.mozillalabs.com
        "192.0.2.0/24",         # TEST-NET, private space for IPv4 documentation/testing purposes, blacklisted in reality
        "198.51.100.0/24",      # TEST-NET2
        "203.0.113.0/24",       # TEST-NET3
        "2001:db8::/32",        # TEST-NET for IPv6
        "mozilla.com",
        "mozillalabs.com",
        "www.mozillalabs.com",
        "*.mozilla.org",
    ]

    blacklisted_targets = [
        "http://10.0.10.123",
        "http://127.0.0.1",
        "http://169.254.34.218",
        "http://172.16.1.2",
        "http://192.168.1.1",
        "http://localhost",
        "https://localhost",
        "http://localhost:8080",
        "https://localhost:8443",
        "https://www.nsa.gov",
        "http://www.gchq.gov.uk",
        "http://www.mozilla.com",           # CNAME to A in MOZNET-1
        "http://bl1.miniontest.arentz.ca",  # A 192.168.0.2
        "http://bl2.miniontest.arentz.ca",  # CNAME blacklisted1
        "http://bl3.miniontest.arentz.ca",  # CNAME to www.mozilla.com
        "http://bl4.miniontest.arentz.ca",  # CNAME to arentz.ca,www.mo.o
        "http://bl5.miniontest.arentz.ca",  # A 46.23.88.82,127.0.0.1
        "10.1.1.1",                         # IP inside 10.0.0.0/8
        "172.16.1.0/16",                    # CIDR inside 10.0.0.0/8
        "http://[fd00::7]/",                # IPv6 (http) inside fd00::/8
        "fc00::7"                           # IPv6 inside fc00::
    ]

    whitelisted_targets = [
        "http://192.0.2.64",                # IP address (http) inside 192.168.2.0/24
        "http://www.mozillalabs.com",       # IP address matches 63.245.217.86
        "http://mozillalabs.com",
        "https://mozillalabs.com",
        "http://mozillalabs.com:8080",
        "https://mozillalabs.com:8443",
        "https://mozilla.com",              # Hostname matches mozilla.com
        "https://blog.mozilla.org",         # Hostname matches *.mozilla.org
        "63.245.217.86",                    # IP matches 63.245.217.86
        "192.0.2.64/30",                    # CIDR inside 192.0.2.0/24
        "http://[2001:db8::7]",             # Hostname inside 2001:db8::
        "2001:db8::7"                       # IP inside 2001:db8::
    ]

    regular_targets = [
        "http://www.disney.com",
        "https://www.disney.com",
        "http://www.disney.com:8080",
        "https://www.disney.com:8443",
        "http://www.apple.com",               # CNAME chain
        "http://www.google.com",              # multiple A
        "http://46.23.88.82",                 # direct ip
        "https://[2607:f8b0:4000:80a::200e]", # google.com
        "http://www.soze.com"                 # single CNAME
    ]

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

    def setUp(self):
        try:
            socket.gethostbyname('mozilla.org')
        except socket.gaierror:
            print("Unable to do host lookups, failing blacklist tests")
            assert False

