from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class Mobile:
    def __init__(self, conn):
        self.conn = conn

    def get_incident(self, incidentId: int, organization: str = None):
        params = {
            'incidentId': incidentId,
            'organization': organization
        }
        return self.conn.get("/management-rest/mobile/get-incident", params=params)

    def list_incidents(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get("/management-rest/mobile/list-incidents", params=params)
