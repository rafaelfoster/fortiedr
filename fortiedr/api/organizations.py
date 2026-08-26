from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class Organizations:
    def __init__(self, conn):
        self.conn = conn

    def add_organization(self, organizationName: str, organizationId: int = None):
        params = {
            'organizationName': organizationName,
            'organizationId': organizationId
        }
        return self.conn.send("/management-rest/organizations/add-organization", params=params)

    def delete_organization(self, organizationId: int):
        params = {
            'organizationId': organizationId
        }
        return self.conn.delete("/management-rest/organizations/delete-organization", params=params)

    def get_organization(self, organizationId: int):
        params = {
            'organizationId': organizationId
        }
        return self.conn.get("/management-rest/organizations/get-organization", params=params)

    def list_organizations(self):
        return self.conn.get("/management-rest/organizations/list-organizations")

    def update_organization(self, organizationId: int, organizationName: str = None):
        params = {
            'organizationId': organizationId,
            'organizationName': organizationName
        }
        return self.conn.update("/management-rest/organizations/update-organization", params=params)
