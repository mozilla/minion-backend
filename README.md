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

If the `setup.py` script executed without any errors then you can now run the following commands in 4 separate terminal windows:

```
scripts/minion-backend
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
