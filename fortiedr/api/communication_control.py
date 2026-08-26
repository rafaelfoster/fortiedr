from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class CommunicationControl:
    def __init__(self, conn):
        self.conn = conn

    def add_exception(self, ruleName: str, organization: str = None):
        params = {
            'ruleName': ruleName,
            'organization': organization
        }
        return self.conn.send("/management-rest/communication-control/add-exception", params=params)

    def delete_exception(self, ruleName: str, organization: str = None):
        params = {
            'ruleName': ruleName,
            'organization': organization
        }
        return self.conn.delete("/management-rest/communication-control/delete-exception", params=params)

    def list_exceptions(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get("/management-rest/communication-control/list-exceptions", params=params)
