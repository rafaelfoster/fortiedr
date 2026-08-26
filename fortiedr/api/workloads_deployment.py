from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class WorkloadsDeployment:
    def __init__(self, conn):
        self.conn = conn

    def connect_account(self, request: dict):
        return self.conn.post("/api/admin/deployment/workloads/connect-account", json=request)

    def delete_accounts(self, accountIds: List[str] = None, deleteAll: bool = None, organizationId: int = None, search: str = None):
        params = {
            'accountIds': accountIds,
            'deleteAll': deleteAll,
            'organizationId': organizationId,
            'search': search
        }
        return self.conn.delete("/api/admin/deployment/workloads/delete-accounts", params=params)

    def discover_clusters(self, request: dict):
        return self.conn.post("/api/admin/deployment/workloads/discover-clusters", json=request)

    def get_account(self, accountId: str = None, organizationId: int = None):
        params = {
            'accountId': accountId,
            'organizationId': organizationId
        }
        return self.conn.get("/api/admin/deployment/workloads/get-account", params=params)

    def install_agents(self, request: dict):
        return self.conn.post("/api/admin/deployment/workloads/install-agents", json=request)

    def installer_versions(self, organizationId: int):
        return self.conn.get("/api/admin/deployment/workloads/installer-versions", json=organizationId)

    def list_accounts(self, maxResult: int = None, organizationId: int = None, page: int = None, search: str = None, sorting: str = None):
        params = {
            'maxResult': maxResult,
            'organizationId': organizationId,
            'page': page,
            'search': search,
            'sorting': sorting
        }
        return self.conn.get("/api/admin/deployment/workloads/list-accounts", params=params)

    def list_clusters(self, accountNames: List[str] = None, cloudProviders: List[str] = None, maxResult: int = None, organizationId: int = None, page: int = None, search: str = None, sorting: str = None, statuses: List[str] = None):
        params = {
            'accountNames': accountNames,
            'cloudProviders': cloudProviders,
            'maxResult': maxResult,
            'organizationId': organizationId,
            'page': page,
            'search': search,
            'sorting': sorting,
            'statuses': statuses
        }
        return self.conn.get("/api/admin/deployment/workloads/list-clusters", params=params)

    def refresh_clusters(self, organizationId: int):
        return self.conn.get("/api/admin/deployment/workloads/refresh-clusters", json=organizationId)

    def uninstall_agents(self, accountNames: List[str] = None, cloudProviders: List[str] = None, clusterIds: List[str] = None, organizationId: int = None, search: str = None):
        params = {
            'accountNames': accountNames,
            'cloudProviders': cloudProviders,
            'clusterIds': clusterIds,
            'organizationId': organizationId,
            'search': search
        }
        return self.conn.delete("/api/admin/deployment/workloads/uninstall-agents", params=params)

    def upgrade_agents(self, request: dict):
        return self.conn.put("/api/admin/deployment/workloads/upgrade-agents", json=request)
