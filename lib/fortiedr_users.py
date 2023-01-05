import os
import json
from lib.connector import FortiEDR_API_GW
from config import Config

config = Config()

fortiedr = FortiEDR_API_GW()

class Users(object):
    
    # List all Users
    def list(self):

        url = "/users/list-users"
        status, data = fortiedr.get(url)
        print(status)
        if status:
            if config.get("debug"):
                print(json.dumps(data, indent=4))

            return status, data

    def create(self, params):
        url = "/users/create-user"

        user_roles = params['roles'].split(",")
        # user_roles = user_roles
        params['roles'] = user_roles
        params["confirmPassword"] = params["password"]

        return fortiedr.insert(url, params)

    def delete(self, param):
        url = "/users/delete-user"
        status, data = fortiedr.delete(url)
        pass
