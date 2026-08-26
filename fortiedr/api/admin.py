from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class Admin:
    def __init__(self, conn):
        self.conn = conn

    def admin_tab_indication(self):
        return self.conn.get("/api/admin/admin-tab-indication")

    def set_enable_default_application_control_state(self, adminSetEnableDefaultApplicationControlRequest: dict):
        return self.conn.put("/api/admin/set-enable-default-application-control-state", json=adminSetEnableDefaultApplicationControlRequest)

    def set_tray_notification_settings(self, adminSetTrayNotificationSettingsRequest: dict):
        return self.conn.post("/api/admin/set-tray-notification-settings", json=adminSetTrayNotificationSettingsRequest)

    def av_scan(self, avScanDisplayItem: dict, accountId: int = None):
        params = {
            'accountId': accountId
        }
        return self.conn.put("/api/admin/settings/av-scan", json=avScanDisplayItem, params=params)

    def av_scan_collectors_and_groups_options(self, accountId: int = None, field: str = None, filterCollectorStatus: bool = None, search: str = None):
        params = {
            'accountId': accountId,
            'field': field,
            'filterCollectorStatus': filterCollectorStatus,
            'search': search
        }
        return self.conn.get("/api/admin/settings/av-scan-collectors-and-groups-options", params=params)

    def get_av_scan_mobile(self, json: str = None, organizationId: int = None):
        params = {
            'json': json,
            'organizationId': organizationId
        }
        return self.conn.get("/api/admin/settings/av-scan-mobile", params=params)

    def update_av_scan_mobile(self, mobileSaveScan: dict):
        return self.conn.put("/api/admin/settings/av-scan-mobile", json=mobileSaveScan)

    def av_scan_mobile_collectors_and_groups_options(self, organizationId: int = None, searchType: str = None, searchValue: str = None):
        params = {
            'organizationId': organizationId,
            'searchType': searchType,
            'searchValue': searchValue
        }
        return self.conn.get("/api/admin/settings/av-scan-mobile-collectors-and-groups-options", params=params)

    def trigger_scan(self, requestBody: dict, accountId: int = None):
        params = {
            'accountId': accountId
        }
        return self.conn.post("/api/admin/settings/av-scan-trigger", json=requestBody, params=params)

    def default_application_control_state(self, adminSetEnableDefaultApplicationControlRequest: dict):
        return self.conn.put("/api/admin/settings/default-application-control-state", json=adminSetEnableDefaultApplicationControlRequest)
