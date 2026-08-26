from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class CollectorInventory:
    def __init__(self, conn):
        self.conn = conn

    def collectors(self, collectors: dict, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.post("/api/collector-inventory/collectors", json=collectors, params=params)
