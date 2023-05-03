import re
import sys
import json
import logging
import urllib.parse
import requests
from fortiedr.auth import Auth

debug_enabled = False

def debug():
    global debug_enabled
    import http.client as http_client
    http_client.HTTPConnection.debuglevel = 1
    
    logging.basicConfig()
    logger = logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True
    debug_enabled = True

class FortiEDR_API_GW:
    global debug_enabled
    
    host = None
    headers = None
    download_file = False
    
    def __init__(self, headers, host, enable_debug : bool = None) -> None:
        self.host = host
        self.headers = headers
        if enable_debug:
            debug()

    def get(self, url, params:dict = None, request_type = None):
        return self._exec("GET", url, params, request_type = request_type)

    def send(self, url, params = None, request_type = None):
        return self._exec("POST", url, params, request_type = request_type)

    def insert(self, url, params = None, request_type = None):
        return self._exec("PUT", url, params, request_type = request_type)

    def update(self, url, params = None, request_type = None):
        return self._exec("PATCH", url, params, request_type = request_type)

    def delete(self, url, params = None, request_type = None):
        return self._exec("DELETE", url, params, request_type = request_type)
    
    '''
    YET TO BE IMPLEMENTED 
    '''
    # def download(self, url, save_to_file, params = None ):
    #     self.download_file = True
    #     content = self._exec("GET", type = "download")
    #     try:
    #         with open(save_to_file, 'wb') as file:
    #             file.write(content)
    #     except OSError as e:
    #         print("[!] - Some error occour: ")
    #         print(e)
    #         return False

    def _exec(self, method, url, params = None, is_file = None, request_type = None):
        if not self.headers or not self.host:
            return "NOT AUTHENTICATED. Run Auth() first."
        
        headers = self.headers
        url = "https://" + self.host + url
        
        if request_type and request_type == "query":
            filtered = {k: v for k, v in params.items() if v is not None}
            params.clear()
            params.update(filtered)
            url_params = urllib.parse.urlencode(params)
            url = url + "?" + url_params

        if params:
            params = {k: v for k, v in params.items() if v is not None}
            print(json.dumps(params, indent=4))
        url = re.sub('\?$', "", url)
        print("URL = ", url)
        try:
            res = None
            if method == "GET":
                res = requests.get(url, headers=headers )
            elif method == "POST":
                res = requests.post(url, headers=headers, json=params)
            elif method == "PUT":
                res = requests.put(url, headers=headers, json=params)
            elif method == "PATCH":
                res = requests.patch(url, headers=headers, json=params)
            elif method == "DELETE":
                res = requests.delete(url, headers=headers, json=params)
            else:
                print("[!] - Method not found")
                print("[!] - Aborting execution.")

            res_code = res.status_code
          
        except requests.exceptions.HTTPError :
            pass

        if res_code > 201:

            res_data = res_code

            try:
                res_data = res.json()
                    
                res_users_error_code = res_data['errorMessage']
                res_data['status_code'] = res_code
                print("\n[!] - Failed to perform this task")
                print("    - HTTP Code: %d"     % (res_code))
                print("    - Error message: %s" % (res_data['errorMessage']))

            except:
                print(res)

            return False, res_data

        if res_code == 200 or res_code == 201:
            
            if is_file == "download":
                return res
            else:
                try:
                    res_data = res.json()
                except:
                    res_data = res

                return True, res_data
