from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class Forensics:
    def __init__(self, conn):
        self.conn = conn

    def get_file(self, collectorId: str, filePath: str, organization: str = None):
        params = {
            'collectorId': collectorId,
            'filePath': filePath,
            'organization': organization
        }
        return self.conn.get("/management-rest/forensics/get-file", params=params)

    def get_process_details(self, collectorId: str, processId: int, organization: str = None):
        params = {
            'collectorId': collectorId,
            'processId': processId,
            'organization': organization
        }
        return self.conn.get("/management-rest/forensics/get-process-details", params=params)

    def list_processes(self, collectorId: str, organization: str = None):
        params = {
            'collectorId': collectorId,
            'organization': organization
        }
        return self.conn.get("/management-rest/forensics/list-processes", params=params)
