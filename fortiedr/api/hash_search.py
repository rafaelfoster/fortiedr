from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class HashSearch:
    def __init__(self, conn):
        self.conn = conn

    def search(self, hash: str, organization: str = None):
        params = {
            'hash': hash,
            'organization': organization
        }
        return self.conn.get("/management-rest/hash-search/search", params=params)
