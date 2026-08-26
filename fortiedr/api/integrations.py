from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class Integrations:
    def __init__(self, conn):
        self.conn = conn

    def add_integration(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.send("/management-rest/integrations/add-integration", params=params)

    def delete_integration(self, integrationId: int, organization: str = None):
        params = {
            'integrationId': integrationId,
            'organization': organization
        }
        return self.conn.delete("/management-rest/integrations/delete-integration", params=params)

    def get_integration(self, integrationId: int, organization: str = None):
        params = {
            'integrationId': integrationId,
            'organization': organization
        }
        return self.conn.get("/management-rest/integrations/get-integration", params=params)

    def list_integrations(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get("/management-rest/integrations/list-integrations", params=params)

    def update_integration(self, integrationId: int, organization: str = None):
        params = {
            'integrationId': integrationId,
            'organization': organization
        }
        return self.conn.update("/management-rest/integrations/update-integration", params=params)
