# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import urlparse
from subprocess import Popen, PIPE

import minion.curly

class OwnerVerifyError(Exception):
    def __init__(self, message):
        self.message = message

def verify_by_file(target, match, filename):
    """ Verify site ownership by matching the content
    of a target file. """
    
    target_file = urlparse.urljoin(target, filename)
    try:
        r = minion.curly.get(target_file)
        r.raise_status()
    except (minion.curly.CurlyError, minion.curly.BadResponseError) as error:
        raise OwnerVerifyError(error.message)
    
    if r.body != match:
        return False
    else:
        return True

def verify_by_header(target, match):
    """ Verify site ownership by matching 
    the X-Minion-Site-Ownership header. """

    try:
        r = minion.curly.get(target)
        r.raise_status()
    except (minion.curly.CurlyError, minion.curly.BadResponseError) as error:
        raise OwnerVerifyError(error.message)

    if 'x-minion-site-ownership' not in r.headers:
        return False
    else:
        if r.headers['x-minion-site-ownership'] == match:
            return True
        else:
            return False

def verify_by_dns_record(target, match):
    """ Verify site ownership by matching the TXT record. """

    url = urlparse.urlparse(target)
    p = Popen(['dig', 'TXT', url.netloc, '+short'], stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    if err:
        raise OwnerVerifyError("Unable to retrieve DNS error.")
    if not out:
        raise OwnerVerifyError("No TXT record found.")
    if match not in out:
        return False
    else:
        return True
