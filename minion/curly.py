# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


import re
import urlparse

import pycurl


class HTTPResponse:
    def __init__(self, url):
        self.url = url
        self.body = ""
        self.status = None
        self.headers = {}
    def _body_callback(self, body):
        self.body += body
    def _header_callback(self, header):
        header = header.strip()
        m = re.match(r"HTTP/\d+\.\d+ (\d+) (.+)", header)
        if m:
            self.status = int(m.group(1))
        else:
            m = re.match(r"^(.+?): (.+)$", header)
            if m:
                self.headers[m.group(1).lower()] = m.group(2)


class Response:
    def __init__(self, responses):
        self._history = responses
    @property
    def history(self):
        return self._history
    @property
    def url(self):
        return self.history[-1].url
    @property
    def body(self):
        return self.history[-1].body
    @property
    def status(self):
        return self.history[-1].status
    @property
    def headers(self):
        return self.history[-1].headers
    def raise_for_status(self):
        if self.status != 200:
            raise Exception("Got a non-200 response: " + str(self.status))


def _get(c, url, headers={}, connect_timeout=None, timeout=None):
    http_response = HTTPResponse(url)
    c.setopt(c.WRITEFUNCTION, http_response._body_callback)
    c.setopt(c.HEADERFUNCTION, http_response._header_callback)
    c.setopt(pycurl.FOLLOWLOCATION, 0)
    #c.setopt(pycurl.FAILONERROR, True)
    c.setopt(c.URL, url.encode('ascii'))
    if timeout is not None:
        c.setopt(pycurl.CONNECTTIMEOUT, connect_timeout)
    if timeout is not None:
        c.setopt(pycurl.TIMEOUT, timeout)
    if len(headers):
        c.setopt(c.HTTPHEADER, ["%s: %s" % (name,value) for name,value in headers.items()])
    c.perform()
    return http_response


def get(url, headers={}, connect_timeout=None, timeout=None):
    c = pycurl.Curl()
    responses = []
    http_response = _get(c, url, headers=headers, connect_timeout=connect_timeout, timeout=timeout)
    responses.append(http_response)
    while http_response.status in (301, 302):
        new_url = http_response.headers['location']
        if new_url.startswith('/'):
            u = urlparse.urlparse(url)
            new_url = u.scheme + "://" + u.hostname + new_url
        http_response = _get(c, new_url, headers)
        responses.append(http_response)
    c.close()
    return Response(responses)
