from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class SystemComponents:
    def __init__(self, conn):
        self.conn = conn

    def aggregator_logs(self, aggregatorId: int = None, organizationId: int = None):
        params = {
            'aggregatorId': aggregatorId,
            'organizationId': organizationId
        }
        return self.conn.get("/api/admin/deployment/system-components/aggregator-logs", params=params)

    def get_aggregators(self, aggregatorIds: List[int] = None, aggregators: List[str] = None, freeTextSearch: str = None, ip: str = None, offset: int = None, organizationId: int = None, pageSize: int = None, sorting: str = None, status: str = None, versions: List[str] = None):
        params = {
            'aggregatorIds': aggregatorIds,
            'aggregators': aggregators,
            'freeTextSearch': freeTextSearch,
            'ip': ip,
            'offset': offset,
            'organizationId': organizationId,
            'pageSize': pageSize,
            'sorting': sorting,
            'status': status,
            'versions': versions
        }
        return self.conn.get("/api/admin/deployment/system-components/aggregators", params=params)

    def delete_aggregators(self, aggregatorIds: List[int] = None, aggregators: List[str] = None, freeTextSearch: str = None, ip: str = None, organizationId: int = None, status: str = None, versions: List[str] = None):
        params = {
            'aggregatorIds': aggregatorIds,
            'aggregators': aggregators,
            'freeTextSearch': freeTextSearch,
            'ip': ip,
            'organizationId': organizationId,
            'status': status,
            'versions': versions
        }
        return self.conn.delete("/api/admin/deployment/system-components/aggregators", params=params)

    def core_logs(self, coreId: int = None, organizationId: int = None):
        params = {
            'coreId': coreId,
            'organizationId': organizationId
        }
        return self.conn.get("/api/admin/deployment/system-components/core-logs", params=params)

    def get_cores(self, coreIds: List[int] = None, cores: List[str] = None, deploymentModes: List[str] = None, freeTextSearch: str = None, hasCrashDumps: bool = None, ip: str = None, offset: int = None, organizationId: int = None, pageSize: int = None, sorting: str = None, status: str = None, versions: List[str] = None):
        params = {
            'coreIds': coreIds,
            'cores': cores,
            'deploymentModes': deploymentModes,
            'freeTextSearch': freeTextSearch,
            'hasCrashDumps': hasCrashDumps,
            'ip': ip,
            'offset': offset,
            'organizationId': organizationId,
            'pageSize': pageSize,
            'sorting': sorting,
            'status': status,
            'versions': versions
        }
        return self.conn.get("/api/admin/deployment/system-components/cores", params=params)

    def delete_cores(self, coreIds: List[int] = None, cores: List[str] = None, deploymentModes: List[str] = None, freeTextSearch: str = None, ip: str = None, organizationId: int = None, status: str = None, versions: List[str] = None):
        params = {
            'coreIds': coreIds,
            'cores': cores,
            'deploymentModes': deploymentModes,
            'freeTextSearch': freeTextSearch,
            'ip': ip,
            'organizationId': organizationId,
            'status': status,
            'versions': versions
        }
        return self.conn.delete("/api/admin/deployment/system-components/cores", params=params)

    def management_logs(self, organizationId: int):
        return self.conn.get("/api/admin/deployment/system-components/management-logs", json=organizationId)

    def get_repositories(self):
        return self.conn.get("/api/admin/deployment/system-components/repositories")

    def update_core_functionality(self, coreFunctionality: dict):
        return self.conn.put("/api/admin/deployment/system-components/update-core-functionality", json=coreFunctionality)
