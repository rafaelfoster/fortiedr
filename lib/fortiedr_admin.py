
import os
import json
from lib.connector import FortiEDR_API_GW
from config import Config

config = Config()

fortiedr = FortiEDR_API_GW()

class Admin(object):
    
    # List all Installers version
    def list_installers(self):

        url = "/admin/list-collector-installers"
        status, data = fortiedr.get(url)
        print(status)
        if status:
            if config.get("debug"):
                print(json.dumps(data, indent=4))

            return status, data

