[![Build Status](https://drone.io/github.com/mozilla/minion-backend/status.png)](https://drone.io/github.com/mozilla/minion-backend/latest)

This project contains the code for the Minion Backend. It provides an API to create and start scans and the machinery to execute the scan.

The Minion Backend consists of three parts:

* A lightweight REST API that is powered by Flask
* A MongoDB database where scans and plans (workflows) are stored
* Three 'workers' that execute the workflow

Setting up a Development Environment
------------------------------------

This assumes a recent version of Ubuntu. We currently test with Ubuntu 14.04 LTS (Trusty Tahr).

First install the essentials:

```
sudo apt-get install build-essential curl git libcurl4-openssl-dev libffi-dev mongodb-server postfix python python-dev rabbitmq-server stunnel
easy_install --upgrade setuptools
```

And the non-essentials, for various plugins:

```
sudo apt-get install nmap
```

Setup your system with the following directories and user accounts:

```
install -m 700 -o mongodb -g mongodb -d /data/db

useradd -m minion
install -m 700 -o minion -g minion -d /run/minion -d /var/lib/minion -d /var/log/minion
```

Note that /run/minion must be created before starting up minion; this should be part of your init scripts.

Then checkout the project and set it up:

```
git clone https://github.com/mozilla/minion-backend.git
cd minion-backend
virtualenv --no-site-packages env
source env/bin/activate
python setup.py develop
```

Make sure that both mongodb and rabbitmq are running. No configuration changes should be needed when running in the default install mode.

If the `setup.py` script executed without any errors then you can now run the following commands as user "minion" in 6 separate terminal windows.

```
scripts/minion-backend-api runserver
```

```
scripts/minion-state-worker
```

```
scripts/minion-scan-worker
```

```
scripts/minion-plugin-worker
```

```
scripts/minion-scanschedule-worker
```

```
scripts/minion-scanscheduler
```

Testing the development setup
-----------------------------

Minion comes with some basic plugins that are all executed from the `basic` plan. To get started with Minion, there are two methods to test development.

If you want to run all the test or running ``functional/views/test_scan.py``, you must whitelist ``127.0.0.1``:

```
mkdir /home/<minion-user>/.minion
echo '{"whitelist":["127.0.0.1"]}' > /home/<minion-user>/.minion/scan.json
```

#### Method 1: ``minion-db-init``

This script will load fixtures into the database in addition to prompting for user email address and user's name, and an option
for you to choose which set of sites to import into the database.

```
scripts/minion-db-init
```

After this, visit ``http://localhost:8080`` using a browser and login with the user email you have just provided.


#### Method 2: run individual scripts

First we need to create a user account by providing a Personal email address, the name of the user and the role of the user, respectively.

```
scripts/minion-create-user <your-persona-email-address> '<admin-name>' administrator
```

Next, we need to create the plan:

```
scripts/minion-create-plan plans/basic.plan
```

The `basic.plan` file simply contains a JSON structure that defines the workflow for the plan.

Now we can start a new scan:

```
scripts/minion-scan <your-persona-email-address> basic http://testfire.net/
```

The `minion-scan` script will create a new scan, start it and then monitor it until it finishes.


Running test cases in Minion
-----------------------------

We have a number of functional test cases; mostly of them are written to test plugins.
If you plan on running plugin function tests, you need to install ``stunnel``
since some of the plugins require HTTPS connection. We actually launch a Flask development
server as we run tests against each built-in plugin.

``stunnel`` should be available to your OS distriubtion. For example, on 
Ubuntu you can issue:

```
sudo apt-get install stunnel
```

The test folder already contains a stunnel configuration file, a RSA key pair,
and an SSL certificate file to run our tests. **WARNING:** Avoid running tests
on production server. We are using port 1234, 1235 and 1443 throughout all plugin tests.

Finally, you can run all the test cases assuming you already have cloned down
the repository to disk:

```
cd minion-backend
nosetests
```

``nose`` should be installed if you have run ``python setup.py develop``.


