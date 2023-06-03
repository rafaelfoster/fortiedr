import re
import sys
import json
import logging
import requests
import urllib.parse
from fortiedr.auth import Auth
requests.packages.urllib3.disable_warnings()

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
    SSL_Verify = True
    
    def conn(self, headers = None, host = None, enable_debug : bool = None, enable_ssl : bool = None) -> None:
        self.host = host
        self.headers = headers
        if enable_debug:
            debug()
        if not enable_ssl:
            self.SSL_Verify = False

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
    
    # '''
    # YET TO BE IMPLEMENTED 
    # '''
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
        if method not in ['GET', 'POST','PUT', 'PATCH', 'DELETE']:
            print("[!] - Method not found")
            print("[!] - Aborting execution.")
            exit()

        if not self.headers or not self.host:
            return "NOT AUTHENTICATED. Run Auth() first."

        headers = self.headers
        url = f"https://{self.host}{url}"

        if request_type and request_type == "query":
            filtered = {k: v for k, v in params.items() if v is not None}
            params.clear()
            params.update(filtered)
            url_params = urllib.parse.urlencode(params)
            url = f"{url}?{url_params}"

        if params:
            params = {k: v for k, v in params.items() if v is not None}

        url = re.sub('\?$', "", url)
        if debug_enabled:
            print(json.dumps(params, indent=4))
            print("URL = ", url)
        try:
            res = None
            res = requests.request(
                method,
                headers=headers,
                url=url,
                json=params,
                verify=self.SSL_Verify
            )

            # if method == "GET":
            #     res = requests.get(url, headers=headers, verify=self.SSL_Verify)
            # elif method == "POST":
            #     res = requests.post(url, headers=headers, json=params, verify=self.SSL_Verify)
            # elif method == "PUT":
            #     res = requests.put(url, headers=headers, json=params, ssl_verify=self.SSL_Verify)
            # elif method == "PATCH":
            #     res = requests.patch(url, headers=headers, json=params, ssl_verify=self.SSL_Verify)
            # elif method == "DELETE":
            #     res = requests.delete(url, headers=headers, json=params, ssl_verify=self.SSL_Verify)

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
                print(f"    - Error message: {res_data['errorMessage']}")

            except Exception:
                if debug_enabled:
                    print(res)

            return False, res_data

        if res_code in {200, 201}:
            if is_file == "download":
                return res
            try:
                res_data = res.json()
            except Exception:
                res_data = res

            return True, res_data
