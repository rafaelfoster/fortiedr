import os
import json
from lib.connector import FortiEDR_API_GW
from config import Config

config = Config()

fortiedr = FortiEDR_API_GW()

class Collectors(object):
    
    # List all Devices
    def list(self):
        url = "/inventory/list-collectors"
        status, data = fortiedr.get(url)
        print(status)
        if status:
            if config.get("debug"):
                print(json.dumps(data, indent=4))

            # If request was successful, now you will be able to manipulate received data.
            # This is a brief example of what how to list each collector retrieved by API:

            for collector in data:
                print("Name: \t{PARAM}".format(PARAM=collector['name']))
                print("Group: \t{PARAM}".format(PARAM=collector['collectorGroupName']))
                print("OS: \t{PARAM}".format(PARAM=collector['operatingSystem']))
                print("state: \t{PARAM}".format(PARAM=collector['state']))
                print("IP Address: \t{PARAM}".format(PARAM=collector['ipAddress']))
                print("Last Seen: \t{PARAM}".format(PARAM=collector['lastSeenTime']))
                print("Logged User: \t{PARAM}".format(PARAM=collector['loggedUsers'][0]))


    # List all Unmanaged devices
    def list_unmanaged(self):
        url = "/inventory/list-unmanaged-devices"
        status, data = fortiedr.get(url)
        print(status)
        if status:
            if config.get("debug"):
                print(json.dumps(data, indent=4))
            for collector in data:
                print("Name: \t\t{PARAM}".format(PARAM=collector['name']))
                print("Group: \t\t{PARAM}".format(PARAM=collector['collectorGroupName']))
                print("OS: \t\t{PARAM}".format(PARAM=collector['operatingSystem']))
                print("state: \t\t{PARAM}".format(PARAM=collector['state']))
                print("IP Address: \t{PARAM}".format(PARAM=collector['ipAddress']))
                print("Last Seen: \t{PARAM}".format(PARAM=collector['lastSeenTime']))
                print("\n")


    def get(self, params = None):
        #?devices=myDevice,myDevice2&collectorGroups=OSX Users,Home Users&ips=1.2.3.4,5.6.7.8&os=windows 7 pro, windows 10 home edition&osFamilies=windows&states=Running,Degraded&lastSeenStart=2016-05-31 00:00:00&lastSeenEnd=2016-06- 01 00:00:00&versions=2.0.0,2.0.1

        pass
