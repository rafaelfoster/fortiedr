from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class SystemEvents:
    def __init__(self, conn):
        self.conn = conn

    def list(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get("/management-rest/system-events/list", params=params)
