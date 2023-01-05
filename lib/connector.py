import sys
import json
import time
import urllib.parse
import requests
from lib.auth import Auth
import configparser as cp
from config import Config
from time import sleep, time
from datetime import datetime

config = Config()

sys.path.append('../../')

class FortiEDR_API_GW(object):

    # def __init__(self) -> None:  

    def get(self, url, params = None):
        return self._exec("GET", url, params)

    def insert(self, url, params = None):
        return self._exec("POST", url, params)

    def update(self, url, params = None):
        return self._exec("PATCH", url, params)
    
    def delete(self, url, params = None):
        return self._exec("DELETE", url, params)

    def _exec(self, method, url, params = None, type = None):
        auth = Auth()
        headers, host = auth.get_headers()
        url = "https://" + host + "/management-rest" + url

        if config.get("debug"):
            print("[*] - Starting {METHOD} request on FortiEDR Manager...".format(METHOD=method))
            print("[*] - Fetching URL: {URL}".format(URL=url))
            print("[*] - FortiEDR Manager Header: {HEADER}".format(HEADER=headers))
            # print(type(params))
            # params = json.loads(json.dumps(params))
            # print(type(params))
            print(json.dumps(headers, indent=4))
            print(json.dumps(params, indent=4))

        try:
            res = None
            if method == "GET":
                res = requests.get(url, headers=headers)
            elif method == "POST":
                res = requests.post(url, headers=headers, json=params)
            elif method == "PATCH":
                res = requests.patch(url, headers=headers, json=params)
            elif method == "DELETE":
                res = requests.delete(url, headers=headers, json=params)
            else:
                print("[!] - Method not found")
                print("[!] - Aborting execution.")
                exit()

            res_code = res.status_code
            if config.get("debug"):
                print("[*] - HTTP Return code: %d" % (res_code))
                print(res)

        except requests.exceptions.HTTPError :
            pass

        if res_code == 500:
            print("Internal Server Error")
            exit()
        elif res_code > 201:
            # if config.get("debug"):
            #     print(res_data)

            res_data = res.json()
            res_users_error_code = res_data['errorMessage']
            res_data['status_code'] = res_code
            print("\n[!] - Failed to perform this task")
            print("    - HTTP Code: %d"     % (res_code))
            print("    - Error message: %s" % (res_data['errorMessage']))
            
            if config.get("debug"):
                print("\n*******************************************************\n")
                print("    - Error Code: %s"    % (res_users_error_code))
                print("    - URL: {URL}".format(URL=url))
                print(json.dumps(res_data, indent=4))
                print("\n*******************************************************\n")
            # exit(1)
            return False, res_data

        if res_code == 200 or res_code == 201:
            res_data = res.json()
            return True, res_data
