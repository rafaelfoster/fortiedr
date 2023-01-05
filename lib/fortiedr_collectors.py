import os
import json
import urllib.parse
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

            return status, data


    # List all Unmanaged devices
    def list_unmanaged(self):
        url = "/inventory/list-unmanaged-devices"
        status, data = fortiedr.get(url)
        print(status)
        if status:
            if config.get("debug"):
                print(json.dumps(data, indent=4))
            return status, data

    # GET a single device 
    def get(self, params = None):
        #Query Parameters accepted: ?devices=myDevice,myDevice2&collectorGroups=OSX Users,Home Users&ips=1.2.3.4,5.6.7.8&os=windows 7 pro, windows 10 home edition&osFamilies=windows&states=Running,Degraded&lastSeenStart=2016-05-31 00:00:00&lastSeenEnd=2016-06- 01 00:00:00&versions=2.0.0,2.0.1
        pass

    # Create a group of collectors
    def create_group(self, params):
        url = "/inventory/create-collector-group"

        params_enconded = urllib.parse.urlencode(params)
        url = url + "?" + params_enconded

        if config.get("debug"):
            print(url)
            print(params)
            print(params_enconded)
            print(json.dumps(params, indent=4))

        return fortiedr.insert(url)
