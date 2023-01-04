import base64
from os import path
from config import Config
import configparser as cp

config = Config()

class Auth(object):
    def get_file_location(self, process_path):
        dir_name = path.dirname(path.abspath(__file__))
        final_path = "{0}{1}".format(dir_name, process_path)
        return final_path

    def load_credentials(self, fedr_final_path, section, parameter):
        fedr_conf = cp.ConfigParser(allow_no_value=True)
        fedr_conf.read(fedr_final_path)
        return fedr_conf.get(section, parameter)

    def convertBase64(self, convert_string):
        string_bytes = convert_string.encode("ascii")

        b64_bytes = base64.b64encode(string_bytes)
        b64_string = b64_bytes.decode("ascii")

        return b64_string

    # @mwt(timeout=60*60)
    def get_headers(self):
        credentials_path = config.get("credentials_path")
        credentials_path = ("%s%s") % ("/..", credentials_path)
        credentails_real_path = self.get_file_location(credentials_path)
        print(credentails_real_path)

        fedr_org  = self.load_credentials(credentails_real_path, "access_credentials", "org")
        fedr_host = self.load_credentials(credentails_real_path, "access_credentials", "host")
        fedr_user = self.load_credentials(credentails_real_path, "access_credentials", "user")
        fedr_pass = self.load_credentials(credentails_real_path, "access_credentials", "pass")
        
        if fedr_org:
            user_pass = "{ORG}\{USER}:{PASSWORD}".format(ORG=fedr_org, USER=fedr_user,PASSWORD=fedr_pass)
        else:
            user_pass = "{USER}:{PASSWORD}".format(USER=fedr_user,PASSWORD=fedr_pass)

        auth_token = self.convertBase64(user_pass)
        headers = {
            "Authorization" : "Basic " + auth_token
        }

        return headers, fedr_host