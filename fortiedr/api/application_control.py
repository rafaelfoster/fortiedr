from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class ApplicationControl:
    def __init__(self, conn):
        self.conn = conn

    def add_app_to_app_group(self, application: str, applicationGroup: str, organization: str = None):
        params = {
            'application': application,
            'applicationGroup': applicationGroup,
            'organization': organization
        }
        return self.conn.send("/management-rest/app-control/add-app-to-app-group", params=params)

    def add_app_group(self, applicationGroup: str, organization: str = None):
        params = {
            'applicationGroup': applicationGroup,
            'organization': organization
        }
        return self.conn.send("/management-rest/app-control/add-app-group", params=params)

    def delete_app_from_app_group(self, application: str, applicationGroup: str, organization: str = None):
        params = {
            'application': application,
            'applicationGroup': applicationGroup,
            'organization': organization
        }
        return self.conn.delete("/management-rest/app-control/delete-app-from-app-group", params=params)

    def delete_app_group(self, applicationGroup: str, organization: str = None):
        params = {
            'applicationGroup': applicationGroup,
            'organization': organization
        }
        return self.conn.delete("/management-rest/app-control/delete-app-group", params=params)

    def list_app_groups(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get("/management-rest/app-control/list-app-groups", params=params)

    def list_apps_in_app_group(self, applicationGroup: str, organization: str = None):
        params = {
            'applicationGroup': applicationGroup,
            'organization': organization
        }
        return self.conn.get("/management-rest/app-control/list-apps-in-app-group", params=params)

    def list_collectors_for_app(self, application: str, organization: str = None):
        params = {
            'application': application,
            'organization': organization
        }
        return self.conn.get("/management-rest/app-control/list-collectors-for-app", params=params)

    def list_installed_apps(self, collectorId: str, organization: str = None):
        params = {
            'collectorId': collectorId,
            'organization': organization
        }
        return self.conn.get("/management-rest/app-control/list-installed-apps", params=params)
