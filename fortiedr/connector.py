import re
import json
import logging
import requests
import urllib.parse
from fortiedr.auth import Auth
from datetime import date, datetime

requests.packages.urllib3.disable_warnings()

class FortiEDR_API_GW:
    
    debug_enabled = False

    def _init_(self):
        self.host = None
        self.headers = None
        self.download_file = False
        self.SSL_Verify = True
        self.debug_enabled = False

    def enable_debug(self):
        import http.client as http_client
        http_client.HTTPConnection.debuglevel = 1

        logging.basicConfig()
        logger = logging.getLogger().setLevel(logging.DEBUG)
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True
        self.debug_enabled = True

    def conn(self, headers=None, host=None, enable_debug=False, enable_ssl=True):
        self.host = host
        self.headers = headers

        if enable_debug:
            self.enable_debug()

        self.SSL_Verify = enable_ssl

    def get(self, url, params=None, request_type=None):
        return self._exec("GET", url, params, request_type=request_type)

    def send(self, url, params=None, request_type=None):
        return self._exec("POST", url, params, request_type=request_type)

    def insert(self, url, params=None, request_type=None):
        return self._exec("PUT", url, params, request_type=request_type)

    def update(self, url, params=None, request_type=None):
        return self._exec("PATCH", url, params, request_type=request_type)

    def delete(self, url, params=None, request_type=None):
        return self._exec("DELETE", url, params, request_type=request_type)
    
    def download(self, url, params=None, request_type=None, file_format = 'zip'):
        return self._exec("GET", url, params, request_type=request_type, download_file=True, file_format=file_format)

    def _exec(self, method, url, params=None, download_file=None, request_type=None, file_format=None):
        if method not in ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']:
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
        
        if self.debug_enabled:
            print(json.dumps(params, indent=4))
            print("URL = ", url)

        StreamInfo = False
        if download_file:
            StreamInfo = True

        try:
            res = requests.request(
                method,
                headers=headers,
                url=url,
                json=params,
                verify=self.SSL_Verify,
                stream=StreamInfo
            )

            res_code = res.status_code

        except requests.exceptions.HTTPError:
            pass

        if res_code > 201:
            res_data = res_code

            try:
                res_data = res.json()
                res_users_error_code = res_data['errorMessage']
                res_data['status_code'] = res_code
                print("\n[!] - Failed to perform this task")
                print("    - HTTP Code: %d" % res_code)
                print(f"    - Error message: {res_data['errorMessage']}")

            except Exception:
                if self.debug_enabled:
                    print(res)

            return {
                'status': False,
                'data': res_data
            }

        if res_code in {200, 201}:
            if download_file:
                date_now = date.today().strftime("%Y%m%d")
                time_now = datetime.now().strftime("%H%M%S")
                url_get_resource = url.split("/")[-1]
                url_get_resource = url_get_resource.split("?")[0]
                local_filename = f"{url_get_resource}-{date_now}-{time_now}.{file_format}"
                # local_filename = local_filename.replace("?", "")
                with open(local_filename, 'wb') as f:
                    for chunk in res.iter_content(chunk_size=1024): 
                        if chunk: # filter out keep-alive new chunks
                            f.write(chunk)
                res_data = local_filename
            else:
                try:
                    res_data = res.json()
                except Exception:
                    res_data = res

            return {
                'status': True,
                'data': res_data
            }