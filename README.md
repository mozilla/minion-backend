This project contains the code for the Minion Backend. It provides an API to create and start scans and the machinery to execute the scan.

The Minion Backend consists of three parts:

* A lightweight REST API that is powered by Flask
* A MongoDB database where scans and plans (workflows) are stored
* Three 'workers' that execute the workflow

Setting up a Development Environment
------------------------------------

This assumes a recent version of Ubuntu. We have only tested with Ubuntu 12.04.2 and 13.04.

First install the essentials:

```
sudo apt-get install git build-essential python-virtualenv python-dev mongodb-server rabbitmq-server curl libcurl4-openssl-dev
```

Then checkout the project and set it up:

```
git clone https://github.com/st3fan/minion-backend.git
cd minion-backend
virtualenv --no-site-packages env
source env/bin/activate
python setup.py develop
```

If the `setup.py` script executed without any errors then you can now run the following commands in 4 separate terminal windows.

Make sure that both mongodb and rabbitmq are running. No configuration changes should be needed when running in the default install mode.

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

Testing the development setup
-----------------------------

Minion comes with some basic plugins that are all executed from the `basic` plan. First we need to create the plan:

```
scripts/minion-create-plan plans/basic.plan
```

The `basic.plan` file simply contains a JSON structure that defines the workflow for the plan.

Now we can start a new scan:

```
scripts/minion-scan basic http://testfire.net/
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


