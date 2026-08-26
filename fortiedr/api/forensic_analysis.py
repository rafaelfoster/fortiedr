from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class ForensicAnalysis:
    def __init__(self, conn):
        self.conn = conn

    def get_file_from_collector(self, collectorId: str, filePath: str, organization: str = None):
        params = {
            'collectorId': collectorId,
            'filePath': filePath,
            'organization': organization
        }
        return self.conn.get("/management-rest/forensic/get-file-from-collector", params=params)

    def get_process_info_from_collector(self, collectorId: str, processId: int, organization: str = None):
        params = {
            'collectorId': collectorId,
            'processId': processId,
            'organization': organization
        }
        return self.conn.get("/management-rest/forensic/get-process-info-from-collector", params=params)

    def list_running_processes_from_collector(self, collectorId: str, organization: str = None):
        params = {
            'collectorId': collectorId,
            'organization': organization
        }
        return self.conn.get("/management-rest/forensic/list-running-processes-from-collector", params=params)

    def abort_request(self, collectorId: str, requestId: str, organization: str = None):
        params = {
            'collectorId': collectorId,
            'requestId': requestId,
            'organization': organization
        }
        return self.conn.send("/management-rest/forensic/abort-request", params=params)

    def get_file_from_collector_ext(self, collectorId: str, filePath: str, organization: str = None):
        params = {
            'collectorId': collectorId,
            'filePath': filePath,
            'organization': organization
        }
        return self.conn.get("/management-rest/forensic/get-file-from-collector-ext", params=params)

    def get_process_info_from_collector_ext(self, collectorId: str, processId: int, organization: str = None):
        params = {
            'collectorId': collectorId,
            'processId': processId,
            'organization': organization
        }
        return self.conn.get("/management-rest/forensic/get-process-info-from-collector-ext", params=params)

    def list_running_processes_from_collector_ext(self, collectorId: str, organization: str = None):
        params = {
            'collectorId': collectorId,
            'organization': organization
        }
        return self.conn.get("/management-rest/forensic/list-running-processes-from-collector-ext", params=params)
