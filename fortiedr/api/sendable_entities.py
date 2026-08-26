from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class SendableEntities:
    def __init__(self, conn):
        self.conn = conn

    def create(self, entity: dict, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.post("/management-rest/sendable-entities/create", json=entity, params=params)

    def test(self, entity: dict, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.post("/management-rest/sendable-entities/test", json=entity, params=params)
