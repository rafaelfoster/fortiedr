import base64
import requests
from os import path

class Auth(object):
   
    def convertBase64(self, convert_string):
        string_bytes = convert_string.encode("ascii")

        b64_bytes = base64.b64encode(string_bytes)
        b64_string = b64_bytes.decode("ascii")

        return b64_string

    # @mwt(timeout=60*60)
    def get_headers(self, fedr_host: str, fedr_user: str, fedr_pass: str, fedr_org: str = None ):
        
        if fedr_org:
            user_pass = "{ORG}\{USER}:{PASSWORD}".format(ORG=fedr_org, USER=fedr_user,PASSWORD=fedr_pass)
        else:
            user_pass = "{USER}:{PASSWORD}".format(USER=fedr_user,PASSWORD=fedr_pass)

        auth_token = self.convertBase64(user_pass)
        headers = {
            "Authorization" : "Basic " + auth_token
        }

        status, data = self.test_authentication(headers, fedr_host)

        if not status:
            return None, data

        return headers, fedr_host
    
    def test_authentication(self, headers, host):
        url = 'https://' + host + '/management-rest/admin/list-system-summary'
        
        try:
            res = requests.get(url, headers=headers)

            res_code = res.status_code

            status = False
            if res_code == 401:
                data = "Unauthorized"
            elif res_code == 403:
                data = "Forbidden"
            elif res_code == 404:
                data = "Not Found"
            elif res_code == 500:
                data = "Internal Server Error"
            else:
                data = res
                status = True
            
            return status, data

        except requests.exceptions.RequestException as err:
            raise SystemExit(err)
        