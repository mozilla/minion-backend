This project contains the code for the Minion Backend. It provides an API to create and start scans and the machinery to
execute the scan.

The Minion Backend consists of three parts:

* A lightweight REST API that is powered by Flask
* A MongoDB database where scans and plans (workflows) are stored
* A scan scheduler daemon
* Four 'workers' that execute the workflow

Setting up a Development Environment
------------------------------------

This assumes a recent version of Ubuntu; we currently test with Ubuntu 14.04 LTS (Trusty Tahr). Although Minion can be
installed anywhere on your system, we recommend `/opt/minion/minion-backend` for the backend, and `/opt/minion/minion-env`
for your virtualenv.

First install the essentials:

```
# apt-get update
# apt-get install -y build-essential curl git libcurl4-openssl-dev libffi-dev \
    libssl-dev mongodb-server postfix python python-dev python-virtualenv \
    rabbitmq-server stunnel supervisor
```

Then, create and source your virtual environment.  This will help keep Minion isolated from the rest of your system. We
also need to upgrade setuptools from the version included with Ubuntu by default:

```
# mkdir -p /etc/minion /opt/minion
# cd /opt/minion
# virtualenv minion-env
# source minion-env/bin/activate

(minion-env)# easy_install --upgrade setuptools    # required for Mock
```

Next, setup your system with the following directories and the `minion` user account. We'll also create some convenience
shell commands, to make working with Minion easier when running as the `minion` user:

```
# useradd -m minion
# install -m 700 -o minion -g minion -d /run/minion -d /var/lib/minion -d /var/log/minion -d ~minion/.python-eggs

# echo -e "\n# Automatically source minion-backend virtualenv" >> ~minion.profile
# echo -e "source /opt/minion/minion-env/bin/activate" >> ~minion/.profile

# echo -e "\n# Minion convenience commands" >> ~minion/.bashrc
# echo -e "alias miniond=\"supervisord -c /opt/minion/minion-backend/etc/supervisord.conf\"" >> ~minion/.bashrc
# echo -e "alias minionctl=\"supervisorctl -c /opt/minion/minion-backend/etc/supervisord.conf\"" >> ~minion/.bashrc
```

Now we can checkout Minion and install it:

```
# cd /opt/minion
# git clone https://github.com/mozilla/minion-backend.git
# source minion-env/bin/activate
(minion-env)# python setup.py develop
```

To make sure that Minion starts when the system reboots, we need to install the Minion init script. We can also disable
the global `supervisord` installed with `apt-get install` above, if it wasn't being used before:

```
# cp /opt/minion/minion-backend/scripts/minion-init /etc/init.d/minion
# chown root:root /etc/init.d/minion
# chmod 755 /etc/init.d/minion
# update-rc.d minion defaults 40
# update-rc.d -f supervisor remove
```

Next, we enable debug logging and automatic reloading of Minion or plugins upon code changes:

```
# vi /opt/minion/minion-backend/etc/minion-backend.supervisor.conf
```

Add `--debug --reload` before `runserver` in the `command=minion-backend-api -a 0.0.0.0 -p 8383 runserver` line.

And that's it! Provided that everything installed successfully, we can start everything up:

```
# service mongodb start
# service rabbitmq-server start
# service minion start
```

From this point on, you should be able to control the Minion processes either as root or as the newly-created minion user.
Let's `su - minion`, and see if everything is running properly:

```
(minion-env)$ service minion status
minion-backend                   RUNNING    pid 18010, uptime 0:00:04
minion-plugin-worker             RUNNING    pid 18004, uptime 0:00:04
minion-scan-worker               RUNNING    pid 18009, uptime 0:00:04
minion-scanschedule-worker       RUNNING    pid 18008, uptime 0:00:04
minion-scanscheduler             RUNNING    pid 18007, uptime 0:00:04
minion-state-worker              RUNNING    pid 18005, uptime 0:00:04
```

Success! You can also use `minionctl` (an alias to `supervisorctl`, using the Minion `supervisord.conf` configuration)
to stop and start individual services, or check on status:

```
(minion-env)$ minionctl stop minion-backend
minion-backend: stopped

(minion-env)$ minionctl status minion-backend
minion-backend                   STOPPED    Sep 03 09:18 PM

(minion-env)$ minionctl start minion-backend
minion-backend: started

(minion-env)$ minionctl status minion-backend
minion-backend                   RUNNING    pid 18795, uptime 0:00:07
```

All that's left to do now is initialize the Minion database and create an administrator:

```
(minion-env)$ minion-db-init 'Your Name' 'youremail@mozilla.com' y
success: added 'Your Name' (youremail@mozilla.com) as administrator
```

And we're done! You should now be able to login to [minion-frontend](https://github.com/mozilla/minion-frontend) using the
newly created administrative account. All logs for Minion, including stdout, stderr, and debug logs, should appear
in `/var/log/minion`.


Securing your Minion environment
--------------------------------

By default, Minion will use the configuration files `frontend.json`, `backend.json`, and `scan.json` located in
`/opt/minion/minion-backend/etc` for its configuration.  If you would like to change these files, copy them into
`/etc/minion` and Minion will use them instead upon restart.

For example, `scan.json` blacklists all local IP address networks (such as 10.0.0.0/8 and 192.168.0.0/16) from being scanned.
If you would like to be able to scan your local networks, copy `scan.json` to `/etc/minion/scan.json` and either add
addresses to the whitelist or remove them from the blacklist.

Also note that due to the recommended configuration of running [minion-frontend](https://github.com/mozilla/minion-frontend) and
minion-backend on separate systems, minion-backend listens on *:8383 for API access. It is strongly suggested that you
restrict access to specific IP addresses running the frontend using firewall rules. Alternatively, you can lock it down 
in `etc/minion-backend.supervisor.conf` to `-a 127.0.0.1` if running the frontend and backend on the same system.



Running test cases in Minion
-----------------------------

We have a number of functional test cases; mostly of them are written to test plugins.
If you plan on running plugin function tests, you need to install ``stunnel``
since some of the plugins require HTTPS connection. We actually launch a Flask development
server as we run tests against each built-in plugin.

``stunnel`` should be available to your OS distribution. For example, on Ubuntu you can issue:

```
# apt-get install stunnel
```

The test folder already contains a stunnel configuration file, a RSA key pair,
and an SSL certificate file to run our tests. **WARNING:** Avoid running tests
on production server. We are using port 1234, 1235 and 1443 throughout all plugin tests.

Finally, you can run all the test cases assuming you already have cloned down
the repository to disk:

```
$ cd /opt/minion/minion-backend
$ nosetests
```

`nose` should be installed if you have run `python setup.py develop`.