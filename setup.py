# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from setuptools import setup

install_requires = [
    'celery',
    'flask',
    'pymongo',
    'requests',
    'twisted',
    'pycurl'
]

setup(name="minion-backend",
      version="0.1",
      description="Minion Backend",
      url="https://github.com/mozilla/minion-backend",
      author="Mozilla",
      author_email="minion@mozilla.com",
      packages=['minion', 'minion.backend', 'minion.plugins'],
      namespace_packages=['minion','minion.backend', 'minion.plugins'],
      include_package_data=True,
      install_requires = install_requires,
      scripts=['scripts/minion-create-plan',
               'scripts/minion-plugin-worker',
               'scripts/minion-start-scan',
               'scripts/minion-state-worker',
               'scripts/minion-plugin-runner'])
