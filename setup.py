# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from setuptools import setup

install_requires = [
    'celery==3.0.19',
    'flask==0.9',
    'pymongo==2.5.1',
    'requests==1.2.2',
    'twisted==13.0.0',
    'pycurl==7.19.0',
    'gunicorn==0.17.4',
    'ipaddress==1.0.4',
    'netaddr==0.7.11',
]

plugins_requires = [
    'robots_scanner==0.1.2',
]

tests_requires = [
    'nose',
    'mock',
    'pyopenssl==0.13.1',
]

setup(name="minion-backend",
      version="0.1",
      description="Minion Backend",
      url="https://github.com/mozilla/minion-backend",
      author="Mozilla",
      author_email="minion@mozilla.com",
      packages=['minion', 'minion.backend', 'minion.backend.views', 'minion.plugins'],
      namespace_packages=['minion','minion.backend', 'minion.plugins'],
      include_package_data=True,
      install_requires = install_requires + tests_requires + plugins_requires,
      tests_require = tests_requires,
      scripts=['scripts/minion-backend-api',
               'scripts/minion-create-plan',
               'scripts/minion-db-init',
               'scripts/minion-create-user',
               'scripts/minion-plugin-worker',
               'scripts/minion-scan',
               'scripts/minion-state-worker',
               'scripts/minion-scan-worker',
               'scripts/minion-plugin-runner'])
