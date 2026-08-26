from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class Features:
    def __init__(self, conn):
        self.conn = conn

    def get_feature_parameters(self, featureName: str, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get(f"/api/features/{featureName}/parameters", params=params)
