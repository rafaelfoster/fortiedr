from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class IntegrationsSupport:
    def __init__(self, conn):
        self.conn = conn

    def get_ems_settings(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get("/management-rest/integrations-support/get-ems-settings", params=params)

    def get_hoster_details(self, hosterType: str, organization: str = None):
        params = {
            'hosterType': hosterType,
            'organization': organization
        }
        return self.conn.get("/management-rest/integrations-support/get-hoster-details", params=params)

    def get_hoster_types(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get("/management-rest/integrations-support/get-hoster-types", params=params)
