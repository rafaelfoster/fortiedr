from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class Inventory:
    def __init__(self, conn):
        self.conn = conn

    def get_collector_details(self, collectorId: str, organization: str = None):
        params = {
            'collectorId': collectorId,
            'organization': organization
        }
        return self.conn.get("/management-rest/inventory/get-collector-details", params=params)

    def list_collectors(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get("/management-rest/inventory/list-collectors", params=params)

    def list_groups(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get("/management-rest/inventory/list-groups", params=params)

    def move_collectors_to_group(self, collectorIds: Union[int, List[int]], groupId: int, organization: str = None):
        if isinstance(collectorIds, int):
            collectorIds = [collectorIds]
        params = {
            'collectorIds': collectorIds,
            'groupId': groupId,
            'organization': organization
        }
        return self.conn.send("/management-rest/inventory/move-collectors-to-group", params=params)

    def uninstall_collector(self, collectorId: str, organization: str = None):
        params = {
            'collectorId': collectorId,
            'organization': organization
        }
        return self.conn.send("/management-rest/inventory/uninstall-collector", params=params)

    def create_group(self, groupName: str, organization: str = None):
        params = {
            'groupName': groupName,
            'organization': organization
        }
        return self.conn.send("/management-rest/inventory/create-group", params=params)

    def delete_group(self, groupName: str, organization: str = None):
        params = {
            'groupName': groupName,
            'organization': organization
        }
        return self.conn.delete("/management-rest/inventory/delete-group", params=params)

    def disable_collector(self, collectorId: str, organization: str = None):
        params = {
            'collectorId': collectorId,
            'organization': organization
        }
        return self.conn.send("/management-rest/inventory/disable-collector", params=params)

    def enable_collector(self, collectorId: str, organization: str = None):
        params = {
            'collectorId': collectorId,
            'organization': organization
        }
        return self.conn.send("/management-rest/inventory/enable-collector", params=params)

    def restart_collector(self, collectorId: str, organization: str = None):
        params = {
            'collectorId': collectorId,
            'organization': organization
        }
        return self.conn.send("/management-rest/inventory/restart-collector", params=params)

    def scan_collector(self, collectorId: str, organization: str = None):
        params = {
            'collectorId': collectorId,
            'organization': organization
        }
        return self.conn.send("/management-rest/inventory/scan-collector", params=params)

    def set_collector_policy(self, collectorId: str, policyName: str, organization: str = None):
        params = {
            'collectorId': collectorId,
            'policyName': policyName,
            'organization': organization
        }
        return self.conn.send("/management-rest/inventory/set-collector-policy", params=params)

    def assign_policy_to_group(self, groupId: int, policyName: str, organization: str = None):
        params = {
            'groupId': groupId,
            'policyName': policyName,
            'organization': organization
        }
        return self.conn.send("/management-rest/inventory/assign-policy-to-group", params=params)

    def get_collectors_by_group(self, groupName: str, organization: str = None):
        params = {
            'groupName': groupName,
            'organization': organization
        }
        return self.conn.get("/management-rest/inventory/get-collectors-by-group", params=params)

    def get_group_policy(self, groupName: str, organization: str = None):
        params = {
            'groupName': groupName,
            'organization': organization
        }
        return self.conn.get("/management-rest/inventory/get-group-policy", params=params)
