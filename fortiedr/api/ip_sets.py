from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class IPSets:
    def __init__(self, conn):
        self.conn = conn

    def add_ip_set(self, name: str, description: str, ips: Union[str, List[str]], organization: str = None):
        if isinstance(ips, str):
            ips = [ips]
        params = {
            'name': name,
            'description': description,
            'ips': ips,
            'organization': organization
        }
        return self.conn.send("/management-rest/ip-sets/add-ip-set", params=params)

    def delete_ip_set(self, name: str, organization: str = None):
        params = {
            'name': name,
            'organization': organization
        }
        return self.conn.delete("/management-rest/ip-sets/delete-ip-set", params=params)

    def list_ip_sets(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get("/management-rest/ip-sets/list-ip-sets", params=params)

    def update_ip_set(self, name: str, new_name: str = None, description: str = None, ips: Union[str, List[str]] = None, organization: str = None):
        if isinstance(ips, str):
            ips = [ips]
        params = {
            'name': name,
            'new_name': new_name,
            'description': description,
            'ips': ips,
            'organization': organization
        }
        return self.conn.update("/management-rest/ip-sets/update-ip-set", params=params)
