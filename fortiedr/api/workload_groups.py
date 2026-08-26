from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class WorkloadGroups:
    def __init__(self, conn):
        self.conn = conn

    def add_workload_group(self, groupName: str, organization: str = None):
        params = {
            'groupName': groupName,
            'organization': organization
        }
        return self.conn.send("/management-rest/workload-groups/add-workload-group", params=params)

    def delete_workload_group(self, groupName: str, organization: str = None):
        params = {
            'groupName': groupName,
            'organization': organization
        }
        return self.conn.delete("/management-rest/workload-groups/delete-workload-group", params=params)

    def get_workload_group(self, groupName: str, organization: str = None):
        params = {
            'groupName': groupName,
            'organization': organization
        }
        return self.conn.get("/management-rest/workload-groups/get-workload-group", params=params)

    def list_workload_groups(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get("/management-rest/workload-groups/list-workload-groups", params=params)

    def update_workload_group(self, groupName: str, newGroupName: str, organization: str = None):
        params = {
            'groupName': groupName,
            'newGroupName': newGroupName,
            'organization': organization
        }
        return self.conn.update("/management-rest/workload-groups/update-workload-group", params=params)
