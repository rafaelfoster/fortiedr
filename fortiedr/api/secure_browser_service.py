from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class SecureBrowserService:
    def __init__(self, conn):
        self.conn = conn

    def get_settings(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get("/api/secure-browser-service/settings", params=params)

    def update_settings(self, settings: dict, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.put("/api/secure-browser-service/settings", json=settings, params=params)
