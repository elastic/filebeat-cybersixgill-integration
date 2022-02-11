**Overview**

The Cybersixgill python script is meant to be executed on a schedule over time.

Depending on the Operating System this could for example be with Cronjobs, Systemd timers or Windows Task Scheduler.


**Installation**
Download the project either using git commands or manually downloading the project code, example below:
```
git clone https://github.com/elastic/filebeat-cybersixgill-integration
```

Install any python dependencies (this could be either using the `pip` or `pip3` command, depending on which python version is default):
```
pip3 install -r requirements.txt
```

Configure the script by filling out the configuration part at the top of `cybersixgill.py`:
```
##Cybersixgill Configuration##
# The ClientID used to authenticate with Cybersixgill
client_id = ""
# The Client Secret used to authenticate with Cybersixgill.
client_secret = ""

##Elastic Agent Configuration##
# The URL (hostname or IP address) in which the Elastic Agent configured to listen on. Including if its http/https.
url = "http://localhost"
# The port in which the Elastic Agent is configured to use.
port = 8181
# The username and password used when configuring the Elastic Agent.
username = ""
password = ""
```

Schedule the execution of the script with for example Systemd timers, depending on your architecture and operating system:

```
$sudo nano/etc/systemd/system/cybersixgill.service
```

Example unit file:
```
[Unit]
Description=Cybersixgill Python Script
[Service]
ExecStart=/bin/python /path/to/cybersixgill.py
```

Add timer file:
```
$sudo nano /etc/systemd/system/cybersxigill.timer
```

Example timer file:
```
[Unit]
Description=Run Cybersixgill Python Script every 10 minutes
[Timer]
OnBootSec=10min
OnUnitActiveSec=15min
[Install]
WantedBy=timers.target
```

Enable the timer:
```
$sudo systemctl enable cybersixgill.timer
$sudo systemctl start cybersixgill.timer
```