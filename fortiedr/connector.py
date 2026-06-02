import asyncio
import functools
import json
import logging
import threading
from datetime import datetime

import niquests

# Globally disable SSL warnings (keeps legacy behaviour)
try:
    niquests.packages.urllib3.disable_warnings()
except Exception:
    pass

class FortiEDR_API_GW:

    def __init__(self):
        self.host = None
        self.headers = None
        self.SSL_Verify = True
        self.debug_enabled = False

        # Shared session for connection pooling / HTTP/2 (niquests)
        self._session = niquests.Session()

        # For async usage (via threadpool), ensure each worker thread gets its own session
        self._thread_local = threading.local()

    def enable_debug(self):
        import http.client as http_client
        http_client.HTTPConnection.debuglevel = 1

        logging.basicConfig()
        logging.getLogger().setLevel(logging.DEBUG)

        niquests_log = logging.getLogger("niquests.packages.urllib3")
        niquests_log.setLevel(logging.DEBUG)
        niquests_log.propagate = True

        self.debug_enabled = True

    def conn(self, headers=None, host=None, enable_debug=False, enable_ssl=True, organization = None):
        self.host = host
        self.headers = headers
        if enable_debug:
            self.enable_debug()

        self.SSL_Verify = enable_ssl
        try:
            self._session.verify = self.SSL_Verify
        except Exception:
            pass

    def get(self, url, params=None, request_type=None, async_req=False, **kwargs):
        async_req = bool(async_req or kwargs.pop('async', False) or kwargs.pop('async_', False))
        return self._exec("GET", url, params, request_type=request_type, async_req=async_req)

    def send(self, url, params=None, request_type=None, async_req=False, **kwargs):
        async_req = bool(async_req or kwargs.pop('async', False) or kwargs.pop('async_', False))
        return self._exec("POST", url, params, request_type=request_type, async_req=async_req)

    def insert(self, url, params=None, request_type=None, async_req=False, **kwargs):
        async_req = bool(async_req or kwargs.pop('async', False) or kwargs.pop('async_', False))
        return self._exec("PUT", url, params, request_type=request_type, async_req=async_req)

    def update(self, url, params=None, request_type=None, async_req=False, **kwargs):
        async_req = bool(async_req or kwargs.pop('async', False) or kwargs.pop('async_', False))
        return self._exec("PATCH", url, params, request_type=request_type, async_req=async_req)

    def delete(self, url, params=None, request_type=None, async_req=False, **kwargs):
        async_req = bool(async_req or kwargs.pop('async', False) or kwargs.pop('async_', False))
        return self._exec("DELETE", url, params, request_type=request_type, async_req=async_req)
    
    def download(self, url, params=None, request_type=None, file_format = 'zip', download_folder = '', async_req=False, **kwargs):
        async_req = bool(async_req or kwargs.pop('async', False) or kwargs.pop('async_', False))
        self.download_folder = download_folder
        return self._exec("GET", url, params, request_type=request_type, download_file=True, file_format=file_format, async_req=async_req)
    
    def upload(self, url, file, params=None, request_type=None, async_req=False, **kwargs):
        async_req = bool(async_req or kwargs.pop('async', False) or kwargs.pop('async_', False))
        return self._exec("POST", url, params, request_type=request_type, upload_file=file, async_req=async_req)

    def _get_thread_session(self):
        session = getattr(self._thread_local, 'session', None)
        if session is None:
            session = niquests.Session()
            self._thread_local.session = session

        try:
            session.verify = self.SSL_Verify
        except Exception:
            pass

        return session

    async def _run_in_thread(self, func, *args, **kwargs):
        # Python 3.8 compatibility: asyncio.to_thread exists only from 3.9+
        to_thread = getattr(asyncio, 'to_thread', None)
        if to_thread is not None:
            return await to_thread(func, *args, **kwargs)

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, functools.partial(func, *args, **kwargs))

    def _exec(self, method, url, params=None, download_file=False, request_type=None, file_format=None, upload_file=None, session=None, async_req=False):
        if async_req:
            session = self._get_thread_session()
            return self._run_in_thread(
                self._exec,
                method,
                url,
                params,
                download_file=download_file,
                request_type=request_type,
                file_format=file_format,
                upload_file=upload_file,
                session=session,
                async_req=False,
            )

        if method not in ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']:
            raise ValueError("Method not supported")

        if not self.headers or not self.host:
            return "NOT AUTHENTICATED. Run Auth() first."

        params = {k: v for k, v in (params or {}).items() if v is not None}
        url = f"https://{self.host}{url}"

        if request_type:
            self.headers['Content-Type'] = request_type

        if self.debug_enabled:
            print("URL = ", url)
            print(json.dumps(self.headers, indent=4))
            print(json.dumps(params, indent=4))

        session = session or self._session

        try:
            response = session.request(
                method,
                url,
                headers=self.headers,
                json=params if method in ['POST', 'PUT', 'PATCH'] else None,
                params=params if method == 'GET' else None,
                verify=self.SSL_Verify,
                stream=download_file,
                files=upload_file
            )
        except Exception as e:
            # Keep the same error contract as the previous requests-based implementation
            is_connection_error = False
            try:
                from niquests import exceptions as niquests_exceptions
                is_connection_error = isinstance(e, niquests_exceptions.ConnectionError)
            except Exception:
                pass

            if is_connection_error:
                return {
                    'status': False,
                    'data': {'status_code': 500, 'error_message': f'Failed to connect to {url}. Error: {e}'}
                }

            return {
                'status': False,
                'data': {'status_code': 500, 'error_message': e}
            }

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
            filename_function = url.split('/')[-1].replace('-','_')
            filename_function = filename_function.split('?')[0]
            if not self.download_folder:
                self.download_folder = '.'
            return self._handle_file_download(response, filename_function, file_format)

        try:
            return {'status': True, 'data': response.json()}
        except ValueError:  # If response is not JSON
            return {'status': True, 'data': response.text}

    def _handle_file_download(self, response, filename_prefix, file_format='zip'):
        date_now = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.download_folder}/{filename_prefix}_{date_now}.{file_format}"
        with open(filename, 'wb') as f:
            for chunk in response.iter_content(chunk_size=1024):
                f.write(chunk)
        return {'status': True, 'data': filename}