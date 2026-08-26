from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class IoT:
    def __init__(self, conn):
        self.conn = conn

    def create_iot_group(self, groupName: str, organization: str = None):
        params = {
            'groupName': groupName,
            'organization': organization
        }
        return self.conn.send("/management-rest/iot/create-iot-group", params=params)

    def delete_iot_group(self, groupName: str, organization: str = None):
        params = {
            'groupName': groupName,
            'organization': organization
        }
        return self.conn.delete("/management-rest/iot/delete-iot-group", params=params)

    def list_iot_devices(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get("/management-rest/iot/list-iot-devices", params=params)

    def list_iot_groups(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get("/management-rest/iot/list-iot-groups", params=params)

    def move_iot_devices_to_group(self, deviceIds: Union[int, List[int]], groupId: int, organization: str = None):
        if isinstance(deviceIds, int):
            deviceIds = [deviceIds]
        params = {
            'deviceIds': deviceIds,
            'groupId': groupId,
            'organization': organization
        }
        return self.conn.send("/management-rest/iot/move-iot-devices-to-group", params=params)
