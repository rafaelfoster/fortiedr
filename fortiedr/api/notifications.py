from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class Notifications:
    def __init__(self, conn):
        self.conn = conn

    def count(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get("/api/notifications/count", params=params)

    def mark_as_read(self, notificationIds: List[int], organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.post("/api/notifications/mark-as-read", json=notificationIds, params=params)
