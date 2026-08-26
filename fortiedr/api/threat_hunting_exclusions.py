from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class ThreatHuntingExclusions:
    def __init__(self, conn):
        self.conn = conn

    def add_exclusion(self, ruleName: str, organization: str = None):
        params = {
            'ruleName': ruleName,
            'organization': organization
        }
        return self.conn.send("/management-rest/threat-hunting-exclusions/add-exclusion", params=params)

    def delete_exclusion(self, ruleName: str, organization: str = None):
        params = {
            'ruleName': ruleName,
            'organization': organization
        }
        return self.conn.delete("/management-rest/threat-hunting-exclusions/delete-exclusion", params=params)

    def list_exclusions(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get("/management-rest/threat-hunting-exclusions/list-exclusions", params=params)
