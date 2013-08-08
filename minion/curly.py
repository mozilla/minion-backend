# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


import re
import urlparse

import pycurl

CURL_ERRORS = {
    'default': 
        {
            'Summary': 'cURL error encountered',
            'Description': 'Minion scan has encountered a cURL error that \
is not documented in Minion scan. The cURL error id is %s.',
            'Solution': 'Please visit \
http://curl.haxx.se/libcurl/c/libcurl-errors.html and find the corresponding \
error on that page using the id given.'
        },
    '60': 
        {
            'Summary': 'SSL certificate problem',
            'Description': "Unable to verify the HTTPS destination. This often means \
the SSL certificate sent by the HTTPS server is misconfigured:\n\
(1) the server's SSL certificate is misconfigured (check your certificate \
with openssl), or\n(2) certificate might be expired, or\n(3) name might \
not match the domain.\ncURL error id: %s",
            'Solution': 'Check your certificate is bundled correctly.'
        }
}

class CurlyError(Exception):
    """ Exception class for reporting CURL errors. """
    def __init__(self, id):
        self.id = id
        self.issue = CURL_ERRORS.get(str(id), CURL_ERRORS['default'])
        self.issue['Description'] = self.issue['Description'] % self.id
        self.issue['Severity'] = 'Error'
        self.message = self.issue['Summary']

class BadResponseError(Exception):
    def __init__(self, message=None, status_code=None):
        if message is None and status_code is not None:
            self.message = "The server has responded with %s status code. \
Please refer to http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html \
to learn about the meaning of the status code." % str(status_code)
        else:
            self.message = message
        super(BadResponseError, self).__init__(self.message)

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
            raise BadResponseError(status_code=self.status)

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
    try:
        c.perform()
        return http_response
    except pycurl.error as e:
        raise CurlyError(e[0])

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
