from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class Reputation:
    def __init__(self, conn):
        self.conn = conn

    def get_file_reputation(self, fileHash: str, organization: str = None):
        params = {
            'fileHash': fileHash,
            'organization': organization
        }
        return self.conn.get("/management-rest/reputation/get-file-reputation", params=params)

    def get_ip_reputation(self, ip: str, organization: str = None):
        params = {
            'ip': ip,
            'organization': organization
        }
        return self.conn.get("/management-rest/reputation/get-ip-reputation", params=params)

    def get_url_reputation(self, url: str, organization: str = None):
        params = {
            'url': url,
            'organization': organization
        }
        return self.conn.get("/management-rest/reputation/get-url-reputation", params=params)
