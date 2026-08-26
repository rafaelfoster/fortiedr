from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class Events:
    def __init__(self, conn):
        self.conn = conn

    def acknowledge_event(self, eventId: int, organization: str = None):
        params = {
            'eventId': eventId,
            'organization': organization
        }
        return self.conn.send("/management-rest/events/acknowledge-event", params=params)

    def add_comment_to_event(self, eventId: int, comment: str, organization: str = None):
        params = {
            'eventId': eventId,
            'comment': comment,
            'organization': organization
        }
        return self.conn.send("/management-rest/events/add-comment-to-event", params=params)

    def get_event(self, eventId: int, organization: str = None):
        params = {
            'eventId': eventId,
            'organization': organization
        }
        return self.conn.get("/management-rest/events/get-event", params=params)

    def get_event_process_info(self, eventId: int, organization: str = None):
        params = {
            'eventId': eventId,
            'organization': organization
        }
        return self.conn.get("/management-rest/events/get-event-process-info", params=params)

    def list_event_comments(self, eventId: int, organization: str = None):
        params = {
            'eventId': eventId,
            'organization': organization
        }
        return self.conn.get("/management-rest/events/list-event-comments", params=params)

    def list_events(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get("/management-rest/events/list-events", params=params)

    def unacknowledge_event(self, eventId: int, organization: str = None):
        params = {
            'eventId': eventId,
            'organization': organization
        }
        return self.conn.send("/management-rest/events/unacknowledge-event", params=params)
