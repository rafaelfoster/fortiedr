from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class SecureBrowser:
    def __init__(self, conn):
        self.conn = conn

    def disable(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.post("/api/secure-browser/disable", params=params)

    def enable(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.post("/api/secure-browser/enable", params=params)
