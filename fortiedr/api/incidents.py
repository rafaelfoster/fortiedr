from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class Incidents:
    def __init__(self, conn):
        self.conn = conn

    def add_comment_to_incident(self, incidentId: int, comment: str, organization: str = None):
        params = {
            'incidentId': incidentId,
            'comment': comment,
            'organization': organization
        }
        return self.conn.send("/management-rest/incidents/add-comment-to-incident", params=params)

    def get_incident(self, incidentId: int, organization: str = None):
        params = {
            'incidentId': incidentId,
            'organization': organization
        }
        return self.conn.get("/management-rest/incidents/get-incident", params=params)

    def list_incidents(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get("/management-rest/incidents/list-incidents", params=params)

    def update_incident(self, incidentId: int, organization: str = None):
        params = {
            'incidentId': incidentId,
            'organization': organization
        }
        return self.conn.update("/management-rest/incidents/update-incident", params=params)

    def list_incident_comments(self, incidentId: int, organization: str = None):
        params = {
            'incidentId': incidentId,
            'organization': organization
        }
        return self.conn.get("/management-rest/incidents/list-incident-comments", params=params)
