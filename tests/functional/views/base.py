# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import json
import requests
import unittest

from pymongo import MongoClient

import minion.backend.utils as backend_utils

BACKEND_KEY = backend_utils.backend_config()['api'].get('key')

class Resource(object):
    """ Base class for each backend endpoint.

    To subclass, the constructor must call super on
    this parent class. Access self.session to get
    a requests object.

    """

    domain = "http://localhost:8383"
    json_header = {"content-type": "application/json"}
    backend_header = {"x-minion-backend-key": BACKEND_KEY}

    def __init__(self):
        self.session = self._create_session()

    def _create_session(self):
        s = requests.Session()
        s.headers.update(self.backend_header)
        return s

class Users(Resource):
    def __init__(self):
        super(Users, self).__init__()
        self.api = self.domain + "/users"

    def get(self):
        return self.session.get(self.api)

class User(Resource):
    def __init__(self, email, name=None, role="user", groups=None):
        super(User, self).__init__()
        self.api = self.domain + "/users"

        self.email = email
        self.name = name
        self.role = role
        self.groups = groups or []

    def _create_user(self, invitation=False):
        return self.session.post(self.api,
            data=json.dumps({"email": self.email,
                  "groups": self.groups,
                  "name": self.name,
                  "role": self.role,
                  "invitation": invitation
            }),
            headers=self.json_header)

    def create(self):
        return self._create_user(invitation=False)

    def invite(self):
        return self._create_user(invitation=True)

    def login(self):
        return self.session.put(self.domain + "/login",
            data=json.dumps({"email": self.email}),
            headers=self.json_header)

    def get(self):
        return self.session.get(self.api + "/" + self.email,
            params={"email": self.email})

    def update(self, email=None, name=None, role=None, status="active", groups=None):
        data = {}
        if email:
            self.email = data["email"] = email
        if name:
            self.name = data["name"] = name
        if role:
            self.role = data["role"] = role
        if groups:
            self.groups = data["groups"] = groups
        if status:
            data["status"] = status

        return self.session.post(self.api + "/" + self.email,
            data=json.dumps(data), headers=self.json_header)

    def delete(self):
        return self.session.delete(self.api + "/" + self.email)

class Groups(Resource):
    def __init__(self):
        super(Groups, self).__init__()
        self.api = self.domain + "/groups"

    def get(self):
        return self.session.get(self.api)

class Group(Resource):
    def __init__(self, group_name, description=None, sites=None, users=None):
        super(Group, self).__init__()
        self.api = self.domain + "/groups"

        self.group_name = group_name
        self.description = description
        self.sites = sites or []
        self.users = users or []

    def create(self, invitation=False):
        return self.session.post(self.api,
            data=json.dumps({"name": self.group_name,
                "description": self.description,
                "users": self.users,
                "sites": self.sites
            }),
            headers=self.json_header)

    def get(self):
        return self.session.get(self.api + "/" + self.group_name)

    def update(self, add_sites=None, remove_sites=None, add_users=None, remove_users=None):
        data = {}
        if add_sites:
            self.sites = list(set(self.sites + add_sites))
            data["addSites"] = add_sites
        if remove_sites:
            self.sites = list(set(self.sites) - set(remove_sites))
            data["removeSites"] = remove_sites
        if add_users:
            self.users = list(set(self.users + add_users))
            data["addUsers"] = add_users
        if remove_users:
            self.users = list(set(self.users) - set(remove_users))
            data["removeUsers"] = remove_users

        return self.session.patch(self.api + "/" + self.group_name,
            data=json.dumps(data), headers=self.json_header)

    def delete(self):
        return self.session.delete(self.api + "/" + self.group_name)

class Sites(Resource):
    def __init__(self):
        super(Sites, self).__init__()
        self.api = self.domain + "/sites"

    def get(self, url=None):
        params = {}
        if url:
            params["url"] = url
        return self.session.get(self.api, params=params)

class Site(Resource):
    def __init__(self, url, groups=None, plans=None):
        super(Site, self).__init__()
        self.api = self.domain + "/sites"

        self.url = url
        self.groups = groups or []
        self.plans = plans or []

    def create(self, verify=False, value=None):
        return self.session.post(self.api,
            data=json.dumps({"url": self.url,
                "groups": self.groups,
                "plans": self.plans,
                "verification": {"enabled": verify, "value": None},
            }),
            headers=self.json_header)
        email = email or self.email

    def get(self, id):
        return self.session.get(self.api + "/" + id)

    def update(self, id, groups=None, plans=None):
        data = {"verification": {"enabled": False, "value": None}}
        if groups:
            self.groups = list(set(self.groups + groups))
            data["groups"] = groups
        if plans:
            self.plans = list(set(self.plans + plans))
            data["plans"] = plans
        return self.session.post(self.api + "/" + id,
            data=json.dumps(data), headers=self.json_header)

    def delete(self, id):
        return self.session.delete(self.api + "/" + id)

class Invites(Resource):
    def __init__(self):
        super(Invites, self).__init__()
        self.api = self.domain + "/invites"

    def get(self, recipient=None, sender=None):
        params = {}
        if recipient:
            params["recipient"] = recipient
        if sender:
            params["sender"] = sender
        return self.session.get(self.api, params=params)

class Invite(Resource):
    def __init__(self, sender, recipient, base_url=None):
        super(Invite, self).__init__()
        self.api = self.domain + "/invites"
        self.sender = sender
        self.recipient = recipient
        self.base_url = base_url or self.domain

    def create(self, verify=False, value=None):
        return self.session.post(self.api,
            data=json.dumps({"sender": self.sender,
                "recipient": self.recipient,
                "base_url": self.base_url}),
            headers=self.json_header)

    def get(self, id):
        return self.session.get(self.api + "/" + id)

    def update(self, id, action, login=None):
        data = {"action": action,
            "login": login or self.recipient,
            "base_url": self.base_url}
        return self.session.post(self.api + "/" + id + "/control",
            data=json.dumps(data), headers=self.json_header)

    def delete(self, id):
        return self.session.delete(self.api + "/" + id)

class Plans(Resource):
    def __init__(self):
        super(Plans, self).__init__()
        self.api = self.domain + "/plans"

    def get(self, name=None, email=None):
        params = {}
        if name:
            params["name"] = name
        if email:
            params["email"] = email
        return self.session.get(self.api, params=params)

class Plan(Resource):
    def __init__(self, plan):
        super(Plan, self).__init__()
        self.api = self.domain + "/plans"
        self.plan = plan

    def create(self):
        return self.session.post(self.api,
            data=json.dumps(self.plan), headers=self.json_header)

    def get(self, plan_name):
        return self.session.get(self.api + "/" + plan_name)

    def update(self, plan_name, new_plan):
        self.plan = new_plan
        return self.session.post(self.api + "/" + plan_name,
            data=json.dumps(self.plan), headers=self.json_header)

    def delete(self, plan_name):
        return self.session.delete(self.api + "/" + plan_name)

class Scans(Resource):
    def __init__(self):
        super(Scans, self).__init__()
        self.api = self.domain + "/scans"

    def get(self, limit=None, site_id=None):
        params = {}
        if limit:
            params["limit"] = limit
        if site_id:
            params["site_id"] = site_id
        return self.session.get(self.api, params=params)

class Scan(Resource):
    def __init__(self, email, plan_name, configuration):
        super(Scan, self).__init__()
        self.api = self.domain + "/scans"
        self.configuration = configuration
        self.email = email
        self.plan_name = plan_name

    def create(self):
        return self.session.post(self.api,
            data=json.dumps({
                "user": self.email,
                "configuration": self.configuration,
                "plan": self.plan_name
            }),
            headers=self.json_header)

    def get_scan_details(self, scan_id, email=None):
        return self.session.get(self.api + "/" + scan_id,
            params={"email": email})

    def get_summary(self, scan_id, email=None):
        return self.session.get(self.api + "/" + scan_id + "/summary",
            params={"email": email})

    def start(self, scan_id, email=None):
        return self._update(scan_id, "START", email=email)

    def stop(self, scan_id, email=None):
        return self._update(scan_id, "STOP", email=email)

    def _update(self, scan_id, state, email=None):
        return self.session.put(self.api + "/" + scan_id + "/control",
            data=state, params={"email": email})

class Plugins(Resource):
    def __init__(self):
        super(Plugins, self).__init__()
        self.api = self.domain + "/plugins"

    def get(self):
        return self.session.get(self.api)

class Reports(Resource):
    def __init__(self):
        super(Reports, self).__init__()
        self.api = self.domain + "/reports"

    def get_history(self, user=None):
        params = {}
        if user is not None:
            params = {'user': user}
        return self.session.get(self.api + "/history", params=params)

    def get_status(self, user=None, group_name=None):
        params = {}
        if user is not None:
            params['user'] = user
            if group_name:
                params["group_name"] = group_name
        return self.session.get(self.api + "/status", params=params)

    def get_issues(self, user=None, group_name=None):
        params = {}
        if user is not None:
            params["user"] = user
            if group_name:
                params["group_name"] = group_name
        return self.session.get(self.api + "/issues", params=params)

class TestAPIBaseClass(unittest.TestCase):
    def setUp(self):
        self.mongodb = MongoClient()
        self.mongodb.drop_database("minion")
        self.db = self.mongodb.minion

        self.email = "bob@example.org"
        self.role = "user"
        self.group_name = "minion-test-group"
        self.group_description = "minion test group is awesome."
        self.target_url = 'http://localhost:1234'
        self.target_badurl = 'http://badsite'
        self.target_ip = '127.0.0.1'
        self.target_cidr = '127.0.0.1/24'

    def tearDown(self):
        self.mongodb.drop_database("minion")
