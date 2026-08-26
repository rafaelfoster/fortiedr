from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class Audit:
    def __init__(self, conn):
        self.conn = conn

    def get_system_audit(self, startDate: str, endDate: str, organization: str = None):
        params = {
            'startDate': startDate,
            'endDate': endDate,
            'organization': organization
        }
        return self.conn.get("/management-rest/audit/get-system-audit", params=params)
