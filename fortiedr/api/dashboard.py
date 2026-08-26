from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class Dashboard:
    def __init__(self, conn):
        self.conn = conn

    def events_and_incidents_by_os(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get("/api/dashboard/events-and-incidents-by-os", params=params)

    def events_and_incidents_progress(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get("/api/dashboard/events-and-incidents-progress", params=params)

    def events_severities(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get("/api/dashboard/events-severities", params=params)

    def incidents_severities(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get("/api/dashboard/incidents-severities", params=params)

    def top_ten_collectors_by_events(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get("/api/dashboard/top-ten-collectors-by-events", params=params)

    def top_ten_events(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get("/api/dashboard/top-ten-events", params=params)
