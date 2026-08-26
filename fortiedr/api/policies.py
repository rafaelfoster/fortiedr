from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class Policies:
    def __init__(self, conn):
        self.conn = conn

    def assign_policy_to_group(self, policyName: str, groupName: str, organization: str = None):
        params = {
            'policyName': policyName,
            'groupName': groupName,
            'organization': organization
        }
        return self.conn.send("/management-rest/policies/assign-policy-to-group", params=params)

    def clone(self, policyName: str, newPolicyName: str, organization: str = None):
        params = {
            'policyName': policyName,
            'newPolicyName': newPolicyName,
            'organization': organization
        }
        return self.conn.send("/management-rest/policies/clone", params=params)

    def create_policy(self, policyName: str, organization: str = None):
        params = {
            'policyName': policyName,
            'organization': organization
        }
        return self.conn.send("/management-rest/policies/create-policy", params=params)

    def delete_policy(self, policyName: str, organization: str = None):
        params = {
            'policyName': policyName,
            'organization': organization
        }
        return self.conn.delete("/management-rest/policies/delete-policy", params=params)

    def get_policy(self, policyName: str, organization: str = None):
        params = {
            'policyName': policyName,
            'organization': organization
        }
        return self.conn.get("/management-rest/policies/get-policy", params=params)

    def list_policies(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get("/management-rest/policies/list-policies", params=params)

    def update_policy(self, policyName: str, organization: str = None):
        params = {
            'policyName': policyName,
            'organization': organization
        }
        return self.conn.update("/management-rest/policies/update-policy", params=params)

    def unassign_policy_from_group(self, policyName: str, groupName: str, organization: str = None):
        params = {
            'policyName': policyName,
            'groupName': groupName,
            'organization': organization
        }
        return self.conn.send("/management-rest/policies/unassign-policy-from-group", params=params)
