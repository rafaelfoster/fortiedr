from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class MobileInventory:
    def __init__(self, conn):
        self.conn = conn

    def devices(self, devices: dict, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.post("/api/mobile-inventory/devices", json=devices, params=params)
