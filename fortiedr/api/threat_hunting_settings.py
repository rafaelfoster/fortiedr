from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class ThreatHuntingSettings:
    def __init__(self, conn):
        self.conn = conn

    def get_settings(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get("/management-rest/threat-hunting-settings/get-settings", params=params)

    def update_settings(self, settings: dict, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.update("/management-rest/threat-hunting-settings/update-settings", json=settings, params=params)
