from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class AvScannerFileController:
    def __init__(self, conn):
        self.conn = conn

    def upload_file(self, file: bytes, organization: str = None):
        return self.conn.upload("/management-rest/av-scanner/upload-file", file=file, params={'organization': organization})
