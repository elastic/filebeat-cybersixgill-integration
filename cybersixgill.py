import re
import requests
import json
from collections import defaultdict
from sixgill.sixgill_feed_client import SixgillFeedClient
from sixgill.sixgill_constants import FeedStream
from sixgill.sixgill_utils import is_indicator

##Cybersixgill Configuration##
# The ClientID used to authenticate with Cybersixgill
client_id = ""
# The Client Secret used to authenticate with Cybersixgill.
client_secret = ""
# The Channel ID received from Cybersixgill.
channel_id = ""

##Elastic Agent Configuration##
# The URL (hostname or IP address) in which the Elastic Agent configured to listen on. Including if its http/https.
url = "http://localhost"
# The port in which the Elastic Agent is configured to use.
port = 8181
username = ""
password = ""

##Optional Configuration##
# The URL prefix choosen when configuring the integration, defaults to /cybersixgill.
prefix = "/cybersixgill"
# The amount of indicators to retrieve from Cybersixgill for each time the script runs.
bulk_size = 20


def create_sixgill_client():
    sixgill_client = SixgillFeedClient(client_id=client_id, client_secret=client_secret, channel_id=channel_id,
                                       feed_stream=FeedStream.DARKFEED, bulk_size=bulk_size, verify=True)
    return sixgill_client


def process_events(records):
    if not records:
        exit()
    regex_parser = re.compile(
        r"([\w-]+?):(\w.+?) (?:[!><]?=|IN|MATCHES|LIKE) '(.*?)' *[OR|AND|FOLLOWEDBY]?")

    # This allows us to have nested dicts without having to initialize all of the keys.
    def d(): return defaultdict(d)

    # Converts json fields to either to Elastic ECS fields, or cybersixgill.
    for obj in records:
        event = d()
        for indicator_type, sub_type, value in regex_parser.findall(obj.get("pattern", "")):
            if indicator_type == "file":
                if "MD5" in sub_type:
                    event["threat"]["indicator"]["file"]["hash"]["md5"] = value
                elif "SHA-1" in sub_type:
                    event["threat"]["indicator"]["file"]["hash"]["sha1"] = value
                elif "SHA-256" in sub_type:
                    event["threat"]["indicator"]["file"]["hash"]["sha256"] = value
            elif indicator_type == "url":
                event["threat"]["indicator"]["url"]["full"] = value
            elif indicator_type == "domain-name":
                event["threat"]["indicator"]["url"]["domain"] = value
            elif indicator_type == "ipv4-addr":
                event["threat"]["indicator"]["ip"] = value
            event["threat"]["indicator"]["type"] = indicator_type
        event["threat"]["indicator"]["description"] = obj.get(
            "description")
        event["cybersixgill"]["feedname"] = obj.get("sixgill_feedname")
        event["threat"]["indicator"]["provider"] = obj.get(
            "sixgill_source")
        event["cybersixgill"]["title"] = obj.get("sixgill_posttitle")
        event["cybersixgill"]["actor"] = obj.get("sixgill_actor")
        event["threat"]["indicator"]["reference"] = "https://portal.cybersixgill.com/#/search?q=_id:" + \
            obj.get("sixgill_postid", "")
        event["tags"] = obj.get("labels")
        event["threat"]["indicator"]["confidence"] = obj.get(
            "sixgill_confidence")
        event["event"]["severity"] = obj.get(
            "sixgill_severity")
        event["threat"]["indicator"]["first_seen"] = obj.get("created")
        event["threat"]["indicator"]["last_seen"] = obj.get("modified")
        event["cybersixgill"]["valid_from"] = obj.get("valid_from")
        if obj.get("external_reference"):
            ext_obj = obj["external_reference"]
            for rec in ext_obj:
                if rec.get("source_name") == "VirusTotal":
                    event["cybersixgill"]["virustotal"]["pr"] = rec.get(
                        "positive_rate")
                    event["cybersixgill"]["virustotal"]["url"] = rec.get(
                        "url")
                if rec.get("source_name") == "mitre-attack":
                    event["cybersixgill"]["mitre"]["description"] = rec.get(
                        "description")
                    event["threat"]["tactic"]["name"] = rec.get(
                        "mitre_attack_tactic")
                    event["threat"]["tactic"]["id"] = rec.get(
                        "mitre_attack_tactic_id")
                    event["threat"]["tactic"]["reference"] = rec.get(
                        "mitre_attack_tactic_url")
        agent_request(event)


def agent_request(event):
    headers = {'Content-Type': 'application/json'}
    r = requests.post(url, json=event, auth=(
        username, password), headers=headers)
    if r.status_code != 200:
        print(
            "The Elastic agent denied the incoming request with HTTP code: ", r.status_code)
        exit()


# Validate that no required configuration options are empty, and strips certain characters from hostname
def validate_config():
    global url
    if not client_id or not client_secret or not channel_id:
        print("The Cybersixgill configuration requires a client_id, client_secret and channel_id")
        exit()
    if not url or not username or not password or not port:
        print("The Elastic Agent configuration requires a url, port, username and password")
        exit()
    url = strip_url(url) + ":" + str(port) + prefix


# Strip any trailing characters from url, to ensure we don't get a malformed URL
def strip_url(s):
    if s.startswith('/'):
        s = s[1:]
    if s.endswith('/'):
        s = s[:-1]
    return s


if __name__ == "__main__":
    # Quick validation to ensure all config is available before starting
    validate_config()

    # Instantiate Sigxill client and retrieve indicators from API.
    client = create_sixgill_client()
    raw_response = client.get_bundle()
    records_object = list(
        filter(is_indicator, raw_response.get("objects", [])))

    # Processing events then sending it to Elastic Agent
    process_events(records_object)

    # Indicators have been retrieved, and sent to Elastic Agent.
    # Sending a commit to the Cybersixgill API to ensure that only new events are retrieved
    client.commit_indicators()
