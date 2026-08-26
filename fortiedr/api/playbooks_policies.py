from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class PlaybooksPolicies:
    def __init__(self, conn):
        self.conn = conn

    def add_playbook_policy(self, policyName: str, organization: str = None):
        params = {
            'policyName': policyName,
            'organization': organization
        }
        return self.conn.send("/management-rest/playbooks-policies/add-playbook-policy", params=params)

    def delete_playbook_policy(self, policyName: str, organization: str = None):
        params = {
            'policyName': policyName,
            'organization': organization
        }
        return self.conn.delete("/management-rest/playbooks-policies/delete-playbook-policy", params=params)

    def get_playbook_policy(self, policyName: str, organization: str = None):
        params = {
            'policyName': policyName,
            'organization': organization
        }
        return self.conn.get("/management-rest/playbooks-policies/get-playbook-policy", params=params)

    def list_playbook_policies(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get("/management-rest/playbooks-policies/list-playbook-policies", params=params)

    def update_playbook_policy(self, policyName: str, organization: str = None):
        params = {
            'policyName': policyName,
            'organization': organization
        }
        return self.conn.update("/management-rest/playbooks-policies/update-playbook-policy", params=params)
