from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class ThreatHunting:
    def __init__(self, conn):
        self.conn = conn

    def add_comment_to_event(self, eventId: int, comment: str, organization: str = None):
        params = {
            'eventId': eventId,
            'comment': comment,
            'organization': organization
        }
        return self.conn.send("/management-rest/threat-hunting/add-comment-to-event", params=params)

    def get_event(self, eventId: int, organization: str = None):
        params = {
            'eventId': eventId,
            'organization': organization
        }
        return self.conn.get("/management-rest/threat-hunting/get-event", params=params)

    def list_events(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get("/management-rest/threat-hunting/list-events", params=params)

    def get_event_process_info(self, eventId: int, organization: str = None):
        params = {
            'eventId': eventId,
            'organization': organization
        }
        return self.conn.get("/management-rest/threat-hunting/get-event-process-info", params=params)

    def list_event_comments(self, eventId: int, organization: str = None):
        params = {
            'eventId': eventId,
            'organization': organization
        }
        return self.conn.get("/management-rest/threat-hunting/list-event-comments", params=params)
