import base64
import requests

class Auth:
      
    @staticmethod
    def convert_to_base64(convert_string):
        string_bytes = convert_string.encode("ascii")
        b64_bytes = base64.b64encode(string_bytes)
        return b64_bytes.decode("ascii")

    @staticmethod
    def test_authentication(headers, host):
        url = f'https://{host}/management-rest/admin/list-system-summary'

        try:
            res = requests.get(url, headers=headers, verify=False)
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
            raise SystemExit(err) from err

    @staticmethod
    def get_headers(fedr_host, fedr_user, fedr_pass, fedr_org=None):
        if fedr_org:
            user_pass = f"{fedr_org}\\{fedr_user}:{fedr_pass}"
        else:
            user_pass = f"{fedr_user}:{fedr_pass}"

        auth_token = Auth.convert_to_base64(user_pass)
        headers = {"Authorization": f"Basic {auth_token}"}

        status, data = Auth.test_authentication(headers, fedr_host)

        return (headers, fedr_host) if status else (None, data)