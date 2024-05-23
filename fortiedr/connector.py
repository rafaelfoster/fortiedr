import json
import logging
import requests
from datetime import datetime

# Globally disable SSL warnings
requests.packages.urllib3.disable_warnings()

class FortiEDR_API_GW:

    def __init__(self):
        self.host = None
        self.headers = None
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

    def conn(self, headers=None, host=None, enable_debug=False, enable_ssl=True, organization = None):
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
    
    def upload(self, url, file, params=None, request_type=None ):
        return self._exec("POST", url, params, request_type=request_type, upload_file=file)

    def _exec(self, method, url, params=None, download_file=False, request_type=None, file_format=None, upload_file=None):
        if method not in ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']:
            raise ValueError("Method not supported")

        if not self.headers or not self.host:
            return "NOT AUTHENTICATED. Run Auth() first."

        params = {k: v for k, v in (params or {}).items() if v is not None}
        url = f"https://{self.host}{url}"

        # if request_type == "query":
        #     url = f"{url}?{urllib.parse.urlencode(params)}"
        if request_type:
            self.headers['Content-Type'] = request_type

        if self.debug_enabled:
            print("URL = ", url)
            print(json.dumps(self.headers, indent=4))
            print(json.dumps(params, indent=4))

        response = requests.request(
            method,
            url,
            headers=self.headers,
            json=params if method in ['POST', 'PUT', 'PATCH'] else None,
            params=params if method == 'GET' else None,
            verify=self.SSL_Verify,
            stream=download_file,
            files=upload_file
        )

        if not response.ok:
            try:
                error_message = response.json().get('errorMessage', response.text)
            except ValueError:
                error_message = response.text
            return {
                'status': False,
                'data': {'status_code': response.status_code, 'error_message': error_message}
            }

        if download_file:
            return self._handle_file_download(response, file_format)

        try:
            return {'status': True, 'data': response.json()}
        except ValueError:  # If response is not JSON
            return {'status': True, 'data': response.text}

    def _handle_file_download(self, response, file_format='zip'):
        date_now = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"{date_now}.{file_format}"
        with open(filename, 'wb') as f:
            for chunk in response.iter_content(chunk_size=1024):
                f.write(chunk)
        return {'status': True, 'data': filename}