from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class Support:
    def __init__(self, conn):
        self.conn = conn

    def get_logs(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get("/management-rest/support/get-logs", params=params)
