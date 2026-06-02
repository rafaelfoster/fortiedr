
import re
import os
import json
from typing import BinaryIO
from fortiedr.auth import Auth as fedrAuth
from fortiedr.connector import FortiEDR_API_GW

version = '3.9'

fortiedr_connection = None

class Admin:
	'''Admin Rest Api Controller'''

	def admin_tab_indication(self) -> tuple[bool, None]:
		'''
		Class Admin
		Description: admin tab indication.
        
		Args:

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("admin_tab_indication", locals())

		url = '/api/admin/admin-tab-indication'
		return fortiedr_connection.get(url)

	def upload_license(self, confirmInternalLicense: bool = None, licenseBlob: str = None) -> tuple[bool, None]:
		'''
		Class Admin
		Description: Upload license to the system.
        
		Args:
			license (Object): Check 'license' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("upload_license", locals())

		url = '/api/admin/license'

		license = {}
		if confirmInternalLicense:
			license["confirmInternalLicense"] = f"{confirmInternalLicense}"
		if licenseBlob:
			license["licenseBlob"] = f"{licenseBlob}"

		return fortiedr_connection.insert(url, license)

	def set_enable_default_application_control_state(self, isEnableDefaultApplicationControl: bool, organization: str) -> tuple[bool, None]:
		'''
		Class Admin
		Description: Update default application control state.
        
		Args:
			adminSetEnableDefaultApplicationControlRequest (Object): Check 'adminSetEnableDefaultApplicationControlRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("set_enable_default_application_control_state", locals())

		url = '/api/admin/set-enable-default-application-control-state'

		adminSetEnableDefaultApplicationControlRequest = {}
		if isEnableDefaultApplicationControl:
			adminSetEnableDefaultApplicationControlRequest["isEnableDefaultApplicationControl"] = f"{isEnableDefaultApplicationControl}"
		if organization:
			adminSetEnableDefaultApplicationControlRequest["organization"] = f"{organization}"

		return fortiedr_connection.insert(url, adminSetEnableDefaultApplicationControlRequest)

	def set_tray_notification_settings(self, enabledPopup: bool, enabledTrayNotification: bool, message: str, organization: str, enableFortiClientNotification: bool = None, showNotificationOnFileReadAttempt: bool = None) -> tuple[bool, None]:
		'''
		Class Admin
		Description: Update tray notification settings.
        
		Args:
			adminSetTrayNotificationSettingsRequest (Object): Check 'adminSetTrayNotificationSettingsRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("set_tray_notification_settings", locals())

		url = '/api/admin/set-tray-notification-settings'

		adminSetTrayNotificationSettingsRequest = {}
		if enableFortiClientNotification:
			adminSetTrayNotificationSettingsRequest["enableFortiClientNotification"] = f"{enableFortiClientNotification}"
		if enabledPopup:
			adminSetTrayNotificationSettingsRequest["enabledPopup"] = f"{enabledPopup}"
		if enabledTrayNotification:
			adminSetTrayNotificationSettingsRequest["enabledTrayNotification"] = f"{enabledTrayNotification}"
		if message:
			adminSetTrayNotificationSettingsRequest["message"] = f"{message}"
		if organization:
			adminSetTrayNotificationSettingsRequest["organization"] = f"{organization}"
		if showNotificationOnFileReadAttempt:
			adminSetTrayNotificationSettingsRequest["showNotificationOnFileReadAttempt"] = f"{showNotificationOnFileReadAttempt}"

		return fortiedr_connection.send(url, adminSetTrayNotificationSettingsRequest)

	def av_scan(self, accountId: int = None, allowedGuid: list = None, day: int = None, dayOptionsList: list = None, enabled: bool = None, executableOnly: bool = None, frequency: str = None, frequencyOptionsList: list = None, hour: int = None, hourOptionsList: list = None, interval: int = None, lastScan: str = None, scanBy: str = None, scanSelection: list = None) -> tuple[bool, None]:
		'''
		Class Admin
		Description: av-scan.
        
		Args:
			accountId (int): accountId
			avScanDisplayItem (Object): Check 'avScanDisplayItem' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("av_scan", locals())

		url = '/api/admin/settings/av-scan'

		avScanDisplayItem = {}
		if allowedGuid:
			avScanDisplayItem["allowedGuid"] = f"{allowedGuid}"
		if day != None:
			avScanDisplayItem["day"] = f"{day}"
		if dayOptionsList:
			avScanDisplayItem["dayOptionsList"] = f"{dayOptionsList}"
		if enabled:
			avScanDisplayItem["enabled"] = f"{enabled}"
		if executableOnly:
			avScanDisplayItem["executableOnly"] = f"{executableOnly}"
		if frequency:
			avScanDisplayItem["frequency"] = f"{frequency}"
		if frequencyOptionsList:
			avScanDisplayItem["frequencyOptionsList"] = f"{frequencyOptionsList}"
		if hour != None:
			avScanDisplayItem["hour"] = f"{hour}"
		if hourOptionsList:
			avScanDisplayItem["hourOptionsList"] = f"{hourOptionsList}"
		if interval != None:
			avScanDisplayItem["interval"] = f"{interval}"
		if lastScan:
			avScanDisplayItem["lastScan"] = f"{lastScan}"
		if scanBy:
			avScanDisplayItem["scanBy"] = f"{scanBy}"
		if scanSelection:
			avScanDisplayItem["scanSelection"] = f"{scanSelection}"

		return fortiedr_connection.insert(url, avScanDisplayItem)

	def av_scan_collectors_and_groups_options(self, accountId: int = None, field: str = None, filterCollectorStatus: bool = None, search: str = None) -> tuple[bool, list]:
		'''
		Class Admin
		Description: av-scan-collectors-and-groups-options.
        
		Args:
			accountId (int): accountId
			field (str): field
			filterCollectorStatus (bool): filterCollectorStatus
			search (str): search

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("av_scan_collectors_and_groups_options", locals())

		url = '/api/admin/settings/av-scan-collectors-and-groups-options'


		return fortiedr_connection.get(url, search)

	def get_av_scan_mobile(self, json: str = None, organizationId: int = None) -> tuple[bool, None]:
		'''
		Class Admin
		Description: av-scan-mobile.
        
		Args:
			json (str): json
			organizationId (int): organizationId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_av_scan_mobile", locals())

		url = '/api/admin/settings/av-scan-mobile'


		return fortiedr_connection.get(url, organizationId)

	def insert_av_scan_mobile(self, day: int = None, enabled: bool = None, frequency: str = None, hour: int = None, organizationId: int = None, scanBy: str = None, scanSelection: list = None) -> tuple[bool, None]:
		'''
		Class Admin
		Description: av-scan-mobile.
        
		Args:
			mobileSaveScan (Object): Check 'mobileSaveScan' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("insert_av_scan_mobile", locals())

		url = '/api/admin/settings/av-scan-mobile'

		mobileSaveScan = {}
		if day != None:
			mobileSaveScan["day"] = f"{day}"
		if enabled:
			mobileSaveScan["enabled"] = f"{enabled}"
		if frequency:
			mobileSaveScan["frequency"] = f"{frequency}"
		if hour != None:
			mobileSaveScan["hour"] = f"{hour}"
		if organizationId != None:
			mobileSaveScan["organizationId"] = f"{organizationId}"
		if scanBy:
			mobileSaveScan["scanBy"] = f"{scanBy}"
		if scanSelection:
			mobileSaveScan["scanSelection"] = f"{scanSelection}"

		return fortiedr_connection.insert(url, mobileSaveScan)

	def av_scan_mobile_collectors_and_groups_options(self, organizationId: int = None, searchType: str = None, searchValue: str = None) -> tuple[bool, None]:
		'''
		Class Admin
		Description: av-scan-mobile-collectors-and-groups-options.
        
		Args:
			organizationId (int): Specifies the organization id
			searchType (str): Specifies the search type (groups or collectors)
			searchValue (str): Specifies the search value

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("av_scan_mobile_collectors_and_groups_options", locals())

		url = '/api/admin/settings/av-scan-mobile-collectors-and-groups-options'
		url_params = []
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if searchType != None:
			url_params.append(f'searchType={searchType}')
		if searchValue != None:
			url_params.append(f'searchValue={searchValue}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def trigger_scan(self, accountId: int = None, applyRecursiveScan: bool = None, executableOnly: bool = None, filePaths: list = None, origin: str = None, scanBy: str = None, scanSelection: list = None) -> tuple[bool, None]:
		'''
		Class Admin
		Description: trigger-scan.
        
		Args:
			accountId (int): accountId
			requestBody (Object): Check 'requestBody' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("trigger_scan", locals())

		url = '/api/admin/settings/av-scan-trigger'

		requestBody = {}
		if applyRecursiveScan:
			requestBody["applyRecursiveScan"] = f"{applyRecursiveScan}"
		if executableOnly:
			requestBody["executableOnly"] = f"{executableOnly}"
		if filePaths:
			requestBody["filePaths"] = f"{filePaths}"
		if origin:
			requestBody["origin"] = f"{origin}"
		if scanBy:
			requestBody["scanBy"] = f"{scanBy}"
		if scanSelection:
			requestBody["scanSelection"] = f"{scanSelection}"

		return fortiedr_connection.send(url, requestBody)

	def default_application_control_state(self, isDefault: bool, accountId: int = None) -> tuple[bool, None]:
		'''
		Class Admin
		Description: default-application-control-state.
        
		Args:
			accountId (int): accountId
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("default_application_control_state", locals())

		url = '/api/admin/settings/default-application-control-state'

		request = {}
		if isDefault:
			request["isDefault"] = f"{isDefault}"

		return fortiedr_connection.insert(url, request)

	def get_get_gdpr_data(self, accountId: int = None, searchInput: str = None, type: str = None) -> tuple[bool, None]:
		'''
		Class Admin
		Description: get-gdpr-data.
        
		Args:
			accountId (int): accountId
			searchInput (str): searchInput
			type (str): type

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_get_gdpr_data", locals())

		url = '/api/admin/settings/gdpr-data'


		return fortiedr_connection.get(url, type)

	def delete_delete_gdpr_data(self, accountId: int = None, searchInput: str = None, type: str = None) -> tuple[bool, None]:
		'''
		Class Admin
		Description: delete-gdpr-data.
        
		Args:
			accountId (int): accountId
			searchInput (str): searchInput
			type (str): type

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_delete_gdpr_data", locals())

		url = '/api/admin/settings/gdpr-data'


		return fortiedr_connection.delete(url, type)

	def gdpr_data_report(self, accountId: int = None, searchInput: str = None, type: str = None) -> tuple[bool, None]:
		'''
		Class Admin
		Description: gdpr-data-report.
        
		Args:
			accountId (int): accountId
			searchInput (str): searchInput
			type (str): type

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("gdpr_data_report", locals())

		url = '/api/admin/settings/gdpr-data-report'


		return fortiedr_connection.get(url, type)

	def gdpr_types(self) -> tuple[bool, list]:
		'''
		Class Admin
		Description: gdpr-types.
        
		Args:

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("gdpr_types", locals())

		url = '/api/admin/settings/gdpr-types'
		return fortiedr_connection.get(url)

	def gdpr_users_report(self, accountId: int = None) -> tuple[bool, None]:
		'''
		Class Admin
		Description: gdpr-users-report.
        
		Args:
			accountId (int): accountId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("gdpr_users_report", locals())

		url = '/api/admin/settings/gdpr-users-report'


		return fortiedr_connection.get(url, accountId)

	def iot_discovery_collectors(self, accountId: int = None, searchValue: str = None) -> tuple[bool, None]:
		'''
		Class Admin
		Description: iot-discovery-collectors.
        
		Args:
			accountId (int): accountId
			searchValue (str): searchValue

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("iot_discovery_collectors", locals())

		url = '/api/admin/settings/iot-collectors'


		return fortiedr_connection.get(url, searchValue)

	def stop_last_discovery(self, accountId: int = None) -> tuple[bool, None]:
		'''
		Class Admin
		Description: stop-last-discovery.
        
		Args:
			accountId (int): accountId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("stop_last_discovery", locals())

		url = '/api/admin/settings/iot-last-discovery'


		return fortiedr_connection.get(url, accountId)

	def iot_settings(self, accountId: int = None, autoGroupingOption: str = None, compareExternalIpWhenMatchDeviceToCollectors: bool = None, excludeGroupsIds: list = None, iotEnable: bool = None, isExcludeGroupsChanged: bool = None) -> tuple[bool, None]:
		'''
		Class Admin
		Description: iot-settings.
        
		Args:
			accountId (int): accountId
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("iot_settings", locals())

		url = '/api/admin/settings/iot-settings'

		request = {}
		if autoGroupingOption:
			request["autoGroupingOption"] = f"{autoGroupingOption}"
		if compareExternalIpWhenMatchDeviceToCollectors:
			request["compareExternalIpWhenMatchDeviceToCollectors"] = f"{compareExternalIpWhenMatchDeviceToCollectors}"
		if excludeGroupsIds:
			request["excludeGroupsIds"] = f"{excludeGroupsIds}"
		if iotEnable:
			request["iotEnable"] = f"{iotEnable}"
		if isExcludeGroupsChanged:
			request["isExcludeGroupsChanged"] = f"{isExcludeGroupsChanged}"

		return fortiedr_connection.insert(url, request)

	def stop_test_scan(self, accountId: int = None) -> tuple[bool, None]:
		'''
		Class Admin
		Description: stop-test-scan.
        
		Args:
			accountId (int): accountId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("stop_test_scan", locals())

		url = '/api/admin/settings/iot-stop-test-scan'


		return fortiedr_connection.get(url, accountId)

	def iot_test_scan(self, accountId: int = None, collectorId: int = None, collectorName: str = None) -> tuple[bool, None]:
		'''
		Class Admin
		Description: iot-test-scan.
        
		Args:
			accountId (int): accountId
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("iot_test_scan", locals())

		url = '/api/admin/settings/iot-test-scan'

		request = {}
		if collectorId != None:
			request["collectorId"] = f"{collectorId}"
		if collectorName:
			request["collectorName"] = f"{collectorName}"

		return fortiedr_connection.send(url, request)

	def iot_scan_test_info(self, accountId: int = None) -> tuple[bool, None]:
		'''
		Class Admin
		Description: iot-scan-test-info.
        
		Args:
			accountId (int): accountId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("iot_scan_test_info", locals())

		url = '/api/admin/settings/iot-test-scan-info'


		return fortiedr_connection.get(url, accountId)

	def get_session_time_out(self) -> tuple[bool, None]:
		'''
		Class Admin
		Description: session-time-out.
        
		Args:

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_session_time_out", locals())

		url = '/api/admin/settings/session-time-out'
		return fortiedr_connection.get(url)

	def insert_session_time_out(self, sessionTimeoutInSeconds: int = None) -> tuple[bool, None]:
		'''
		Class Admin
		Description: session-time-out.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("insert_session_time_out", locals())

		url = '/api/admin/settings/session-time-out'

		request = {}
		if sessionTimeoutInSeconds != None:
			request["sessionTimeoutInSeconds"] = f"{sessionTimeoutInSeconds}"

		return fortiedr_connection.insert(url, request)

	def splunk(self, organizationId: int = None, confirmPassword: str = None, password: str = None, username: str = None) -> tuple[bool, None]:
		'''
		Class Admin
		Description: save splunk user.
        
		Args:
			organizationId (int): organizationId
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("splunk", locals())

		url = '/api/admin/splunk-user'

		request = {}
		if confirmPassword:
			request["confirmPassword"] = f"{confirmPassword}"
		if password:
			request["password"] = f"{password}"
		if username:
			request["username"] = f"{username}"

		return fortiedr_connection.send(url, request)

	def Get_available_timezone_options(self) -> tuple[bool, list]:
		'''
		Class Admin
		Description: Returns list of available timezone options with display labels.
        
		Args:

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("Get_available_timezone_options", locals())

		url = '/api/admin/timezones'
		return fortiedr_connection.get(url)

	def get_Get_organization_timezone_configuration(self, organizationId: int) -> tuple[bool, None]:
		'''
		Class Admin
		Description: Returns the timezone configuration for the specified organization.
        
		Args:
			organizationId (int): organizationId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_Get_organization_timezone_configuration", locals())

		url = f'/api/admin/{organizationId}/timezone'
		return fortiedr_connection.get(url)

	def insert_Update_organization_timezone_configuration(self, organizationId: int, enabled: bool, timezone: str, ignoreConverter: bool = None) -> tuple[bool, None]:
		'''
		Class Admin
		Description: Updates the timezone configuration for the specified organization.
        
		Args:
			organizationId (int): organizationId
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("insert_Update_organization_timezone_configuration", locals())

		url = f'/api/admin/{organizationId}/timezone'

		request = {}
		if enabled:
			request["enabled"] = f"{enabled}"
		if ignoreConverter:
			request["ignoreConverter"] = f"{ignoreConverter}"
		if timezone:
			request["timezone"] = f"{timezone}"

		return fortiedr_connection.insert(url, request)

class SystemComponents:
	'''System Component Rest Api Controller'''

	def aggregator_logs(self, aggregatorId: int = None, organizationId: int = None) -> tuple[bool, None]:
		'''
		Class SystemComponents
		Description: get aggregator logs.
        
		Args:
			aggregatorId (int): Specifies the aggregator IDs
			organizationId (int): Specifies the organization id

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("aggregator_logs", locals())

		url = '/api/admin/deployment/system-components/aggregator-logs'
		url_params = []
		if aggregatorId != None:
			url_params.append(f'aggregatorId={aggregatorId}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def get_get_aggregators(self, aggregatorIds: list = None, aggregators: list = None, freeTextSearch: str = None, ip: str = None, offset: int = None, organizationId: int = None, pageSize: int = None, sorting: str = None, status: str = None, versions: list = None) -> tuple[bool, None]:
		'''
		Class SystemComponents
		Description: Return aggregators.
        
		Args:
			aggregatorIds (list): Specifies the aggregator IDs
			aggregators (list): Specifies the aggregator names
			freeTextSearch (str): pattern of requested text
			ip (str): Specifies the aggregator IP
			offset (int): Specifies the page offset
			organizationId (int): Specifies the organization id
			pageSize (int): Specifies the page size
			sorting (str): list of sorting fields (each is a map of <fieldName>:<descending order flag>. false=ascending, true=descending)
			status (str): Specifies the aggregator status
			versions (list): Specifies the aggregator versions

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_get_aggregators", locals())

		url = '/api/admin/deployment/system-components/aggregators'
		url_params = []
		if aggregatorIds != None:
			aggregatorIds = ",".join(map(str, aggregatorIds)) if isinstance(aggregatorIds, list) else aggregatorIds
			url_params.append(f'aggregatorIds={aggregatorIds}')
		if aggregators != None:
			aggregators = ",".join(aggregators) if isinstance(aggregators, list) else aggregators
			url_params.append(f'aggregators={aggregators}')
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if ip != None:
			url_params.append(f'ip={ip}')
		if offset != None:
			url_params.append(f'offset={offset}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if pageSize != None:
			url_params.append(f'pageSize={pageSize}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if status != None:
			url_params.append(f'status={status}')
		if versions != None:
			versions = ",".join(versions) if isinstance(versions, list) else versions
			url_params.append(f'versions={versions}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def delete_Delete_aggregators(self, aggregatorIds: list = None, aggregators: list = None, freeTextSearch: str = None, ip: str = None, organizationId: int = None, status: str = None, versions: list = None) -> tuple[bool, None]:
		'''
		Class SystemComponents
		Description: Delete aggregators.
        
		Args:
			aggregatorIds (list): Specifies the aggregator IDs
			aggregators (list): Specifies the aggregator names
			freeTextSearch (str): pattern of requested text
			ip (str): Specifies the aggregator IP
			organizationId (int): Specifies the organization id
			status (str): Specifies the aggregator status
			versions (list): Specifies the aggregator versions

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_Delete_aggregators", locals())

		url = '/api/admin/deployment/system-components/aggregators'
		url_params = []
		if aggregatorIds != None:
			aggregatorIds = ",".join(map(str, aggregatorIds)) if isinstance(aggregatorIds, list) else aggregatorIds
			url_params.append(f'aggregatorIds={aggregatorIds}')
		if aggregators != None:
			aggregators = ",".join(aggregators) if isinstance(aggregators, list) else aggregators
			url_params.append(f'aggregators={aggregators}')
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if ip != None:
			url_params.append(f'ip={ip}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if status != None:
			url_params.append(f'status={status}')
		if versions != None:
			versions = ",".join(versions) if isinstance(versions, list) else versions
			url_params.append(f'versions={versions}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def core_logs(self, coreId: int = None, organizationId: int = None) -> tuple[bool, None]:
		'''
		Class SystemComponents
		Description: get core logs.
        
		Args:
			coreId (int): Specifies the aggregator IDs
			organizationId (int): Specifies the organization id

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("core_logs", locals())

		url = '/api/admin/deployment/system-components/core-logs'
		url_params = []
		if coreId != None:
			url_params.append(f'coreId={coreId}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def get_get_cores(self, coreIds: list = None, cores: list = None, deploymentModes: list = None, freeTextSearch: str = None, hasCrashDumps: bool = None, ip: str = None, offset: int = None, organizationId: int = None, pageSize: int = None, sorting: str = None, status: str = None, versions: list = None) -> tuple[bool, None]:
		'''
		Class SystemComponents
		Description: Return cores.
        
		Args:
			coreIds (list): Specifies the core IDs
			cores (list): Specifies the core names
			deploymentModes (list): List of cores deployments modes
			freeTextSearch (str): pattern of requested text
			hasCrashDumps (bool): Has crash dumps
			ip (str): Specifies the core IP
			offset (int): Specifies the page offset
			organizationId (int): Specifies the organization id
			pageSize (int): Specifies the page size
			sorting (str): list of sorting fields (each is a map of <fieldName>:<descending order flag>. false=ascending, true=descending)
			status (str): Specifies the device status
			versions (list): Specifies the core versions

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_get_cores", locals())

		url = '/api/admin/deployment/system-components/cores'
		url_params = []
		if coreIds != None:
			coreIds = ",".join(map(str, coreIds)) if isinstance(coreIds, list) else coreIds
			url_params.append(f'coreIds={coreIds}')
		if cores != None:
			cores = ",".join(cores) if isinstance(cores, list) else cores
			url_params.append(f'cores={cores}')
		if deploymentModes != None:
			deploymentModes = ",".join(deploymentModes) if isinstance(deploymentModes, list) else deploymentModes
			url_params.append(f'deploymentModes={deploymentModes}')
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if hasCrashDumps != None:
			url_params.append(f'hasCrashDumps={hasCrashDumps}')
		if ip != None:
			url_params.append(f'ip={ip}')
		if offset != None:
			url_params.append(f'offset={offset}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if pageSize != None:
			url_params.append(f'pageSize={pageSize}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if status != None:
			url_params.append(f'status={status}')
		if versions != None:
			versions = ",".join(versions) if isinstance(versions, list) else versions
			url_params.append(f'versions={versions}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def delete_Delete_cores(self, coreIds: list = None, cores: list = None, deploymentModes: list = None, freeTextSearch: str = None, ip: str = None, organizationId: int = None, status: str = None, versions: list = None) -> tuple[bool, None]:
		'''
		Class SystemComponents
		Description: Delete cores.
        
		Args:
			coreIds (list): Specifies the core IDs
			cores (list): Specifies the core names
			deploymentModes (list): List of cores deployments modes
			freeTextSearch (str): pattern of requested text
			ip (str): Specifies the core IP
			organizationId (int): Specifies the organization id
			status (str): Specifies the device status
			versions (list): Specifies the core versions

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_Delete_cores", locals())

		url = '/api/admin/deployment/system-components/cores'
		url_params = []
		if coreIds != None:
			coreIds = ",".join(map(str, coreIds)) if isinstance(coreIds, list) else coreIds
			url_params.append(f'coreIds={coreIds}')
		if cores != None:
			cores = ",".join(cores) if isinstance(cores, list) else cores
			url_params.append(f'cores={cores}')
		if deploymentModes != None:
			deploymentModes = ",".join(deploymentModes) if isinstance(deploymentModes, list) else deploymentModes
			url_params.append(f'deploymentModes={deploymentModes}')
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if ip != None:
			url_params.append(f'ip={ip}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if status != None:
			url_params.append(f'status={status}')
		if versions != None:
			versions = ",".join(versions) if isinstance(versions, list) else versions
			url_params.append(f'versions={versions}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def management_logs(self, organizationId: int) -> tuple[bool, None]:
		'''
		Class SystemComponents
		Description: get management logs.
        
		Args:
			organizationId (int): organizationId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("management_logs", locals())

		url = '/api/admin/deployment/system-components/management-logs'


		return fortiedr_connection.get(url, organizationId)

	def get_repositories(self) -> tuple[bool, list]:
		'''
		Class SystemComponents
		Description: Return repositories.
        
		Args:

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("get_repositories", locals())

		url = '/api/admin/deployment/system-components/repositories'
		return fortiedr_connection.get(url)

	def update_core_functionality(self, coreId: int = None, functionality: str = None, organizationId: int = None) -> tuple[bool, None]:
		'''
		Class SystemComponents
		Description: update-core-functionality.
        
		Args:
			coreFunctionality (Object): Check 'coreFunctionality' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("update_core_functionality", locals())

		url = '/api/admin/deployment/system-components/update-core-functionality'

		coreFunctionality = {}
		if coreId != None:
			coreFunctionality["coreId"] = f"{coreId}"
		if functionality:
			coreFunctionality["functionality"] = f"{functionality}"
		if organizationId != None:
			coreFunctionality["organizationId"] = f"{organizationId}"

		return fortiedr_connection.insert(url, coreFunctionality)

class workloadsdeploymentrestapicontroller:
	'''Workloads Deployment Rest Api Controller'''

	def connect_account(self, accountData: object = None, accountName: str = None, cloudProvider: str = None, organizationId: int = None) -> tuple[bool, None]:
		'''
		Class workloadsdeploymentrestapicontroller
		Description: connect account.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("connect_account", locals())

		url = '/api/admin/deployment/workloads/connect-account'

		request = {}
		if accountData:
			request["accountData"] = f"{accountData}"
		if accountName:
			request["accountName"] = f"{accountName}"
		if cloudProvider:
			request["cloudProvider"] = f"{cloudProvider}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"

		return fortiedr_connection.send(url, request)

	def delete_accounts(self, accountIds: list = None, deleteAll: bool = None, organizationId: int = None, search: str = None) -> tuple[bool, None]:
		'''
		Class workloadsdeploymentrestapicontroller
		Description: delete accounts.
        
		Args:
			accountIds (list): Specifies if delete all
			deleteAll (bool): Specifies if delete all
			organizationId (int): Specifies the organization ID
			search (str): pattern of requested text

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_accounts", locals())

		url = '/api/admin/deployment/workloads/delete-accounts'
		url_params = []
		if accountIds != None:
			accountIds = ",".join(accountIds) if isinstance(accountIds, list) else accountIds
			url_params.append(f'accountIds={accountIds}')
		if deleteAll != None:
			url_params.append(f'deleteAll={deleteAll}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if search != None:
			url_params.append(f'search={search}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def discover_clusters(self, accountId: str = None, organizationId: int = None) -> tuple[bool, None]:
		'''
		Class workloadsdeploymentrestapicontroller
		Description: discover clusters.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("discover_clusters", locals())

		url = '/api/admin/deployment/workloads/discover-clusters'

		request = {}
		if accountId:
			request["accountId"] = f"{accountId}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"

		return fortiedr_connection.send(url, request)

	def get_account(self, accountId: str = None, organizationId: int = None) -> tuple[bool, None]:
		'''
		Class workloadsdeploymentrestapicontroller
		Description: get account.
        
		Args:
			accountId (str): Specifies the account ID
			organizationId (int): Specifies the organization ID

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_account", locals())

		url = '/api/admin/deployment/workloads/get-account'
		url_params = []
		if accountId != None:
			url_params.append(f'accountId={accountId}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def install_Agents(self, accountNames: list = None, aggregatorIp: str = None, cloudProviders: list = None, clusterIds: list = None, group: str = None, organizationId: int = None, search: str = None, tag: str = None) -> tuple[bool, None]:
		'''
		Class workloadsdeploymentrestapicontroller
		Description: install Agents.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("install_Agents", locals())

		url = '/api/admin/deployment/workloads/install-agents'

		request = {}
		if accountNames:
			request["accountNames"] = f"{accountNames}"
		if aggregatorIp:
			request["aggregatorIp"] = f"{aggregatorIp}"
		if cloudProviders:
			request["cloudProviders"] = f"{cloudProviders}"
		if clusterIds:
			request["clusterIds"] = f"{clusterIds}"
		if group:
			request["group"] = f"{group}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"
		if search:
			request["search"] = f"{search}"
		if tag:
			request["tag"] = f"{tag}"

		return fortiedr_connection.send(url, request)

	def installer_versions(self, organizationId: int) -> tuple[bool, None]:
		'''
		Class workloadsdeploymentrestapicontroller
		Description: installer versions.
        
		Args:
			organizationId (int): organizationId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("installer_versions", locals())

		url = '/api/admin/deployment/workloads/installer-versions'


		return fortiedr_connection.get(url, organizationId)

	def list_accounts(self, maxResult: int = None, organizationId: int = None, page: int = None, search: str = None, sorting: str = None) -> tuple[bool, None]:
		'''
		Class workloadsdeploymentrestapicontroller
		Description: list accounts.
        
		Args:
			maxResult (int): Specifies the page size
			organizationId (int): Specifies the organization ID
			page (int): Specifies the page offset
			search (str): pattern of requested text
			sorting (str): list of sorting fields (each is a map of <fieldName>:<descending order flag>. false=ascending, true=descending)

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("list_accounts", locals())

		url = '/api/admin/deployment/workloads/list-accounts'
		url_params = []
		if maxResult != None:
			url_params.append(f'maxResult={maxResult}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if page != None:
			url_params.append(f'page={page}')
		if search != None:
			url_params.append(f'search={search}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def list_clusters(self, accountNames: list = None, cloudProviders: list = None, maxResult: int = None, organizationId: int = None, page: int = None, search: str = None, sorting: str = None, statuses: list = None) -> tuple[bool, None]:
		'''
		Class workloadsdeploymentrestapicontroller
		Description: list clusters.
        
		Args:
			accountNames (list): Search by account names
			cloudProviders (list): Search by cloud providers
			maxResult (int): Specifies the page size
			organizationId (int): Specifies the organization ID
			page (int): Specifies the page offset
			search (str): pattern of requested text
			sorting (str): list of sorting fields (each is a map of <fieldName>:<descending order flag>. false=ascending, true=descending)
			statuses (list): Search by statuses

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("list_clusters", locals())

		url = '/api/admin/deployment/workloads/list-clusters'
		url_params = []
		if accountNames != None:
			accountNames = ",".join(accountNames) if isinstance(accountNames, list) else accountNames
			url_params.append(f'accountNames={accountNames}')
		if cloudProviders != None:
			cloudProviders = ",".join(cloudProviders) if isinstance(cloudProviders, list) else cloudProviders
			url_params.append(f'cloudProviders={cloudProviders}')
		if maxResult != None:
			url_params.append(f'maxResult={maxResult}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if page != None:
			url_params.append(f'page={page}')
		if search != None:
			url_params.append(f'search={search}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if statuses != None:
			statuses = ",".join(statuses) if isinstance(statuses, list) else statuses
			url_params.append(f'statuses={statuses}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def refresh_clusters(self, organizationId: int) -> tuple[bool, None]:
		'''
		Class workloadsdeploymentrestapicontroller
		Description: refresh clusters.
        
		Args:
			organizationId (int): organizationId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("refresh_clusters", locals())

		url = '/api/admin/deployment/workloads/refresh-clusters'


		return fortiedr_connection.get(url, organizationId)

	def uninstall_agents(self, accountNames: list = None, cloudProviders: list = None, clusterIds: list = None, organizationId: int = None, search: str = None) -> tuple[bool, None]:
		'''
		Class workloadsdeploymentrestapicontroller
		Description: uninstall agents.
        
		Args:
			accountNames (list): Search by account names
			cloudProviders (list): Search by cloud providers
			clusterIds (list): Specifies the cluster Ids
			organizationId (int): Specifies the organization ID
			search (str): pattern of requested text

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("uninstall_agents", locals())

		url = '/api/admin/deployment/workloads/uninstall-agents'
		url_params = []
		if accountNames != None:
			accountNames = ",".join(accountNames) if isinstance(accountNames, list) else accountNames
			url_params.append(f'accountNames={accountNames}')
		if cloudProviders != None:
			cloudProviders = ",".join(cloudProviders) if isinstance(cloudProviders, list) else cloudProviders
			url_params.append(f'cloudProviders={cloudProviders}')
		if clusterIds != None:
			clusterIds = ",".join(clusterIds) if isinstance(clusterIds, list) else clusterIds
			url_params.append(f'clusterIds={clusterIds}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if search != None:
			url_params.append(f'search={search}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def upgrade_Agents(self, accountNames: list = None, cloudProviders: list = None, clusterIds: list = None, organizationId: int = None, search: str = None, tag: str = None) -> tuple[bool, None]:
		'''
		Class workloadsdeploymentrestapicontroller
		Description: upgrade Agents.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("upgrade_Agents", locals())

		url = '/api/admin/deployment/workloads/upgrade-agents'

		request = {}
		if accountNames:
			request["accountNames"] = f"{accountNames}"
		if cloudProviders:
			request["cloudProviders"] = f"{cloudProviders}"
		if clusterIds:
			request["clusterIds"] = f"{clusterIds}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"
		if search:
			request["search"] = f"{search}"
		if tag:
			request["tag"] = f"{tag}"

		return fortiedr_connection.insert(url, request)

class SystemEvents:
	'''System Events Rest Api Controller'''

	def get_get_system_events(self, freeTextSearch: str = None, maxResults: int = None, multipleSearchJSON: str = None, selectedEvents: list = None, start: int = None, viewFilterName: str = None) -> tuple[bool, None]:
		'''
		Class SystemEvents
		Description: get-system-events.
        
		Args:
			freeTextSearch (str): Free text search across audit records
			maxResults (int): Maximum number of results per page
			multipleSearchJSON (str): Advanced filtering in JSON string format
			selectedEvents (list): Array of specific event IDs to filter
			start (int): Start index for pagination
			viewFilterName (str): Name of the saved view filter

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_get_system_events", locals())

		url = '/api/admin/systemEvents'
		url_params = []
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if maxResults != None:
			url_params.append(f'maxResults={maxResults}')
		if multipleSearchJSON != None:
			url_params.append(f'multipleSearchJSON={multipleSearchJSON}')
		if selectedEvents != None:
			selectedEvents = ",".join(map(str, selectedEvents)) if isinstance(selectedEvents, list) else selectedEvents
			url_params.append(f'selectedEvents={selectedEvents}')
		if start != None:
			url_params.append(f'start={start}')
		if viewFilterName != None:
			url_params.append(f'viewFilterName={viewFilterName}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def delete_system_events_delete_system_events(self, itemIds: list, organizationId: int = None) -> tuple[bool, None]:
		'''
		Class SystemEvents
		Description: Deletes the given system events.
        
		Args:
			itemIds (list): itemIds
			organizationId (int): organizationId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_system_events_delete_system_events", locals())

		url = '/api/admin/systemEvents'
		url_params = []
		if itemIds != None:
			itemIds = ",".join(map(str, itemIds)) if isinstance(itemIds, list) else itemIds
			url_params.append(f'itemIds={itemIds}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def generate_report_system_events(self, multipleSearchJSON: str = None, organizationId: int = None, selectedEvents: list = None, sorting: object = None, viewFilterName: str = None) -> tuple[bool, None]:
		'''
		Class SystemEvents
		Description: Exports the given system events.
        
		Args:
			systemEventsExportRequest (Object): Check 'systemEventsExportRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("generate_report_system_events", locals())

		url = '/api/admin/systemEvents/generate-report'

		systemEventsExportRequest = {}
		if multipleSearchJSON:
			systemEventsExportRequest["multipleSearchJSON"] = f"{multipleSearchJSON}"
		if organizationId != None:
			systemEventsExportRequest["organizationId"] = f"{organizationId}"
		if selectedEvents:
			systemEventsExportRequest["selectedEvents"] = f"{selectedEvents}"
		if sorting:
			systemEventsExportRequest["sorting"] = f"{sorting}"
		if viewFilterName:
			systemEventsExportRequest["viewFilterName"] = f"{viewFilterName}"

		return fortiedr_connection.send(url, systemEventsExportRequest)

	def get_system_events_filter_options(self) -> tuple[bool, None]:
		'''
		Class SystemEvents
		Description: Retrieve available system event filter options like component types.
        
		Args:

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_system_events_filter_options", locals())

		url = '/api/admin/systemEvents/get-system-events-filter-options'
		return fortiedr_connection.get(url)

	def list_system_events(self, componentNames: list = None, componentTypes: list = None, fromDate: str = None, itemsPerPage: int = None, organization: str = None, pageNumber: int = None, sorting: str = None, strictMode: bool = None, toDate: str = None) -> tuple[bool, list]:
		'''
		Class SystemEvents
		Description: Retrieve system events.
        
		Args:
			componentNames (list):  Specifies one or more names. The name is the customer name for license-related system events and the device name for all others events
			componentTypes (list): Specifies one or more component type
			fromDate (str): Searches for system events that occurred after this date
			itemsPerPage (int): An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			pageNumber (int): An integer used for paging that indicates the required page number
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on
			strictMode (bool): A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False
			toDate (str): Searches for system events that occurred before this date

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_system_events", locals())

		url = '/management-rest/system-events/list-system-events'
		url_params = []
		if componentNames != None:
			componentNames = ",".join(componentNames) if isinstance(componentNames, list) else componentNames
			url_params.append(f'componentNames={componentNames}')
		if componentTypes != None:
			componentTypes = ",".join(componentTypes) if isinstance(componentTypes, list) else componentTypes
			url_params.append(f'componentTypes={componentTypes}')
		if fromDate != None:
			url_params.append(f'fromDate={fromDate}')
		if itemsPerPage != None:
			url_params.append(f'itemsPerPage={itemsPerPage}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if pageNumber != None:
			url_params.append(f'pageNumber={pageNumber}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if strictMode != None:
			url_params.append(f'strictMode={strictMode}')
		if toDate != None:
			url_params.append(f'toDate={toDate}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

class ApplicationControl:
	'''Application Control Rest Api Controller'''

	def get_applications(self, currentPage: int, organization: str, fileName: str = None, path: str = None, signer: str = None, enabled: bool = None, groupIds: list = None, hash: str = None, operatingSystem: str = None, policyIds: list = None, tag: str = None) -> tuple[bool, None]:
		'''
		Class ApplicationControl
		Description: Get application controls.
        
		Args:
			fileName (str): Specifies the file name, if contains special characters - encode to HTML URL Encoding
			path (str): Specifies the path, if contains special characters - encode to HTML URL Encoding
			signer (str): Specifies the value, if contains special characters - encode to HTML URL Encoding
			currentPage (int): Specifies the current page
			enabled (bool): Specifies the state of the application control
			groupIds (list): Specifies the IDs of the relevant groups for application control
			hash (str): Specifies the hash of the application control
			operatingSystem (str): Specifies the operating system of the application control
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			policyIds (list): Specifies the IDs of the relevant policies for application control
			tag (str): Specifies the tag related to application control

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_applications", locals())

		url = '/api/application-control/applications'
		url_params = []
		if fileName != None:
			url_params.append(f'attributes.fileName={fileName}')
		if path != None:
			url_params.append(f'attributes.path={path}')
		if signer != None:
			url_params.append(f'attributes.signer={signer}')
		if currentPage != None:
			url_params.append(f'currentPage={currentPage}')
		if enabled != None:
			url_params.append(f'enabled={enabled}')
		if groupIds != None:
			groupIds = ",".join(map(str, groupIds)) if isinstance(groupIds, list) else groupIds
			url_params.append(f'groupIds={groupIds}')
		if hash != None:
			url_params.append(f'hash={hash}')
		if operatingSystem != None:
			url_params.append(f'operatingSystem={operatingSystem}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if policyIds != None:
			policyIds = ",".join(map(str, policyIds)) if isinstance(policyIds, list) else policyIds
			url_params.append(f'policyIds={policyIds}')
		if tag != None:
			url_params.append(f'tag={tag}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def send_applications(self, applicationControls: list, organization: str) -> tuple[bool, None]:
		'''
		Class ApplicationControl
		Description: Saves new application controls and returns a list of them.
        
		Args:
			applicationControlSaveRequest (Object): Check 'applicationControlSaveRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("send_applications", locals())

		url = '/api/application-control/applications'

		applicationControlSaveRequest = {}
		if applicationControls:
			applicationControlSaveRequest["applicationControls"] = f"{applicationControls}"
		if organization:
			applicationControlSaveRequest["organization"] = f"{organization}"

		return fortiedr_connection.send(url, applicationControlSaveRequest)

	def insert_applications(self, appIds: list, groupIds: list, organization: str, enabled: bool = None, isOverridePolicies: bool = None, name: str = None, policyIds: list = None, tagId: int = None) -> tuple[bool, list]:
		'''
		Class ApplicationControl
		Description: Edits existing application control and returns the affected ones.
        
		Args:
			appIds (list): The relevant application IDs to edit
			modifiedFields (Object): Check 'modifiedFields' in the API documentation for further information.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("insert_applications", locals())

		url = '/api/application-control/applications'
		url_params = []
		if appIds != None:
			appIds = ",".join(map(str, appIds)) if isinstance(appIds, list) else appIds
			url_params.append(f'appIds={appIds}')
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)

		modifiedFields = {}
		if enabled:
			modifiedFields["enabled"] = f"{enabled}"
		if groupIds:
			modifiedFields["groupIds"] = f"{groupIds}"
		if isOverridePolicies:
			modifiedFields["isOverridePolicies"] = f"{isOverridePolicies}"
		if name:
			modifiedFields["name"] = f"{name}"
		if policyIds:
			modifiedFields["policyIds"] = f"{policyIds}"
		if tagId != None:
			modifiedFields["tagId"] = f"{tagId}"

		return fortiedr_connection.insert(url, modifiedFields)

	def delete_applications(self, organization: str, applicationIds: list = None) -> tuple[bool, None]:
		'''
		Class ApplicationControl
		Description: Deletes application controls.
        
		Args:
			applicationIds (list): The IDs of the applications to be deleted
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_applications", locals())

		url = '/api/application-control/applications'
		url_params = []
		if applicationIds != None:
			applicationIds = ",".join(map(str, applicationIds)) if isinstance(applicationIds, list) else applicationIds
			url_params.append(f'applicationIds={applicationIds}')
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def force_update_ootb_application_controls(self) -> tuple[bool, None]:
		'''
		Class ApplicationControl
		Description: Trigger OOTB application control update.
        
		Args:

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("force_update_ootb_application_controls", locals())

		url = '/api/application-control/force-update-ootb-application-controls'
		return fortiedr_connection.send(url)

	def tags(self, name: str, organization: str) -> tuple[bool, None]:
		'''
		Class ApplicationControl
		Description: Create an application control tags.
        
		Args:
			applicationControlTagCreateRequest (Object): Check 'applicationControlTagCreateRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("tags", locals())

		url = '/api/application-control/tags'

		applicationControlTagCreateRequest = {}
		if name:
			applicationControlTagCreateRequest["name"] = f"{name}"
		if organization:
			applicationControlTagCreateRequest["organization"] = f"{organization}"

		return fortiedr_connection.send(url, applicationControlTagCreateRequest)

class AvScannerFileController:
	'''Av Scanner File Rest Api Controller'''

	def Stream_AV_Scanner_File(self, version: str) -> tuple[bool, None]:
		'''
		Class AvScannerFileController
		Description: Streams a file from GCS directly to client.
        
		Args:
			version (str): version

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("Stream_AV_Scanner_File", locals())

		url = '/api/av-scanner-file-controller/download'
		url_params = []
		if version != None:
			url_params.append(f'version={version}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

class AvSignatureUpdate:
	'''Av Signature Policy Rest Api Controller'''

	def get_get_agent_groups_assignment(self, organization: str) -> tuple[bool, list]:
		'''
		Class AvSignatureUpdate
		Description: Return agent groups.
        
		Args:
			organization (str): organization

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("get_get_agent_groups_assignment", locals())

		url = '/api/av-signatures-update/assign-agent-groups'
		url_params = []
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def insert_assign_policy(self, forceGroupsAssign: bool = None, freeTextSearch: str = None, groupsIds: list = None, id: int = None, offset: int = None, organizationId: int = None, pageSize: int = None, sorting: str = None) -> tuple[bool, None]:
		'''
		Class AvSignatureUpdate
		Description: assign agent group to policy.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("insert_assign_policy", locals())

		url = '/api/av-signatures-update/assign-agent-groups'

		request = {}
		if forceGroupsAssign:
			request["forceGroupsAssign"] = f"{forceGroupsAssign}"
		if freeTextSearch:
			request["freeTextSearch"] = f"{freeTextSearch}"
		if groupsIds:
			request["groupsIds"] = f"{groupsIds}"
		if id != None:
			request["id"] = f"{id}"
		if offset != None:
			request["offset"] = f"{offset}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"
		if pageSize != None:
			request["pageSize"] = f"{pageSize}"
		if sorting:
			request["sorting"] = f"{sorting}"

		return fortiedr_connection.insert(url, request)

	def clone_policy(self, newPolicyName: str, organization: str, sourcePolicyName: str) -> tuple[bool, list]:
		'''
		Class AvSignatureUpdate
		Description: clone policy.
        
		Args:
			clonePolicyRequest (Object): Check 'clonePolicyRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("clone_policy", locals())

		url = '/api/av-signatures-update/clone-policy'

		clonePolicyRequest = {}
		if newPolicyName:
			clonePolicyRequest["newPolicyName"] = f"{newPolicyName}"
		if organization:
			clonePolicyRequest["organization"] = f"{organization}"
		if sourcePolicyName:
			clonePolicyRequest["sourcePolicyName"] = f"{sourcePolicyName}"

		return fortiedr_connection.send(url, clonePolicyRequest)

	def Retrieve_the_latest_AV_signature_file_version_by_type(self, organizationId: int) -> tuple[bool, None]:
		'''
		Class AvSignatureUpdate
		Description: Retrieve the latest AV signature file version by type.
        
		Args:
			organizationId (int): organizationId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("Retrieve_the_latest_AV_signature_file_version_by_type", locals())

		url = '/api/av-signatures-update/latest-files-version'
		url_params = []
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def get_get_policies(self, freeTextSearch: str = None, offset: int = None, organizationId: int = None, pageSize: int = None, sorting: str = None) -> tuple[bool, None]:
		'''
		Class AvSignatureUpdate
		Description: return av signature policies.
        
		Args:
			freeTextSearch (str): pattern of requested text
			offset (int): Specifies the page offset
			organizationId (int): Specifies the organization id
			pageSize (int): Specifies the page size
			sorting (str): list of sorting fields (each is a map of <fieldName>:<descending order flag>. false=ascending, true=descending)

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_get_policies", locals())

		url = '/api/av-signatures-update/policies'
		url_params = []
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if offset != None:
			url_params.append(f'offset={offset}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if pageSize != None:
			url_params.append(f'pageSize={pageSize}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def delete_policy(self, organization: str, deleteAll: bool = None, freeTextSearch: str = None, idToDelete: list = None, requirePolicyAssociation: bool = None) -> tuple[bool, None]:
		'''
		Class AvSignatureUpdate
		Description: Deletes an av signature policy.
        
		Args:
			deleteAll (bool): Indicate if should delete all matching results (rather than only the selected) 
			freeTextSearch (str): pattern of policies to delete
			idToDelete (list): Id's of entities to delete
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			requirePolicyAssociation (bool): require policy association

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_policy", locals())

		url = '/api/av-signatures-update/policies'
		url_params = []
		if deleteAll != None:
			url_params.append(f'deleteAll={deleteAll}')
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if idToDelete != None:
			idToDelete = ",".join(map(str, idToDelete)) if isinstance(idToDelete, list) else idToDelete
			url_params.append(f'idToDelete={idToDelete}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if requirePolicyAssociation != None:
			url_params.append(f'requirePolicyAssociation={requirePolicyAssociation}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def state(self, IsDefault: bool = None, description: str = None, enabled: bool = None, extraConfiguration: object = None, groupsIds: list = None, id: int = None, isActiveEnabled: bool = None, isExtendedEnabled: bool = None, isExtremeEnabled: bool = None, isUrlDBEnabled: bool = None, name: str = None, organizationId: int = None, organizationName: str = None, policiesIds: list = None, updateMethod: str = None) -> tuple[bool, list]:
		'''
		Class AvSignatureUpdate
		Description: set policy state.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("state", locals())

		url = '/api/av-signatures-update/policies/state'

		request = {}
		if IsDefault:
			request["IsDefault"] = f"{IsDefault}"
		if description:
			request["description"] = f"{description}"
		if enabled:
			request["enabled"] = f"{enabled}"
		if extraConfiguration:
			request["extraConfiguration"] = f"{extraConfiguration}"
		if groupsIds:
			request["groupsIds"] = f"{groupsIds}"
		if id != None:
			request["id"] = f"{id}"
		if isActiveEnabled:
			request["isActiveEnabled"] = f"{isActiveEnabled}"
		if isExtendedEnabled:
			request["isExtendedEnabled"] = f"{isExtendedEnabled}"
		if isExtremeEnabled:
			request["isExtremeEnabled"] = f"{isExtremeEnabled}"
		if isUrlDBEnabled:
			request["isUrlDBEnabled"] = f"{isUrlDBEnabled}"
		if name:
			request["name"] = f"{name}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"
		if organizationName:
			request["organizationName"] = f"{organizationName}"
		if policiesIds:
			request["policiesIds"] = f"{policiesIds}"
		if updateMethod:
			request["updateMethod"] = f"{updateMethod}"

		return fortiedr_connection.insert(url, request)

	def policy(self, name: str, IsDefault: bool = None, description: str = None, enabled: bool = None, extraConfiguration: object = None, groupsIds: list = None, id: int = None, isActiveEnabled: bool = None, isExtendedEnabled: bool = None, isExtremeEnabled: bool = None, isUrlDBEnabled: bool = None, organizationId: int = None, organizationName: str = None, updateMethod: str = None) -> tuple[bool, None]:
		'''
		Class AvSignatureUpdate
		Description: create an av signature policy.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("policy", locals())

		url = '/api/av-signatures-update/policy'

		request = {}
		if IsDefault:
			request["IsDefault"] = f"{IsDefault}"
		if description:
			request["description"] = f"{description}"
		if enabled:
			request["enabled"] = f"{enabled}"
		if extraConfiguration:
			request["extraConfiguration"] = f"{extraConfiguration}"
		if groupsIds:
			request["groupsIds"] = f"{groupsIds}"
		if id != None:
			request["id"] = f"{id}"
		if isActiveEnabled:
			request["isActiveEnabled"] = f"{isActiveEnabled}"
		if isExtendedEnabled:
			request["isExtendedEnabled"] = f"{isExtendedEnabled}"
		if isExtremeEnabled:
			request["isExtremeEnabled"] = f"{isExtremeEnabled}"
		if isUrlDBEnabled:
			request["isUrlDBEnabled"] = f"{isUrlDBEnabled}"
		if name:
			request["name"] = f"{name}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"
		if organizationName:
			request["organizationName"] = f"{organizationName}"
		if updateMethod:
			request["updateMethod"] = f"{updateMethod}"

		return fortiedr_connection.send(url, request)

	def policy(self, agentGroupsIds: list = None, excludePolicyId: int = None) -> tuple[bool, list]:
		'''
		Class AvSignatureUpdate
		Description: returns existing agent group assignments.
        
		Args:
			agentGroupsIds (list): agent groups id's
			excludePolicyId (int): exclude policy id

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("policy", locals())

		url = '/api/av-signatures-update/policy/existing-groups-assignment'
		url_params = []
		if agentGroupsIds != None:
			agentGroupsIds = ",".join(map(str, agentGroupsIds)) if isinstance(agentGroupsIds, list) else agentGroupsIds
			url_params.append(f'agentGroupsIds={agentGroupsIds}')
		if excludePolicyId != None:
			url_params.append(f'excludePolicyId={excludePolicyId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def update_policy(self, id: int, IsDefault: bool = None, description: str = None, enabled: bool = None, extraConfiguration: object = None, groupsIds: list = None, isActiveEnabled: bool = None, isExtendedEnabled: bool = None, isExtremeEnabled: bool = None, isUrlDBEnabled: bool = None, name: str = None, organizationId: int = None, organizationName: str = None, updateMethod: str = None) -> tuple[bool, None]:
		'''
		Class AvSignatureUpdate
		Description: update an av signature policy.
        
		Args:
			id (int): id
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("update_policy", locals())

		url = f'/api/av-signatures-update/policy/{id}'

		request = {}
		if IsDefault:
			request["IsDefault"] = f"{IsDefault}"
		if description:
			request["description"] = f"{description}"
		if enabled:
			request["enabled"] = f"{enabled}"
		if extraConfiguration:
			request["extraConfiguration"] = f"{extraConfiguration}"
		if groupsIds:
			request["groupsIds"] = f"{groupsIds}"
		if id != None:
			request["id"] = f"{id}"
		if isActiveEnabled:
			request["isActiveEnabled"] = f"{isActiveEnabled}"
		if isExtendedEnabled:
			request["isExtendedEnabled"] = f"{isExtendedEnabled}"
		if isExtremeEnabled:
			request["isExtremeEnabled"] = f"{isExtremeEnabled}"
		if isUrlDBEnabled:
			request["isUrlDBEnabled"] = f"{isUrlDBEnabled}"
		if name:
			request["name"] = f"{name}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"
		if organizationName:
			request["organizationName"] = f"{organizationName}"
		if updateMethod:
			request["updateMethod"] = f"{updateMethod}"

		return fortiedr_connection.insert(url, request)

	def get_signatures(self, freeTextSearch: str = None, offset: int = None, organizationId: int = None, pageSize: int = None, sorting: str = None) -> tuple[bool, None]:
		'''
		Class AvSignatureUpdate
		Description: return av signatures.
        
		Args:
			freeTextSearch (str): pattern of requested text
			offset (int): Specifies the page offset
			organizationId (int): Specifies the organization id
			pageSize (int): Specifies the page size
			sorting (str): list of sorting fields (each is a map of <fieldName>:<descending order flag>. false=ascending, true=descending)

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_signatures", locals())

		url = '/api/av-signatures-update/signatures'
		url_params = []
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if offset != None:
			url_params.append(f'offset={offset}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if pageSize != None:
			url_params.append(f'pageSize={pageSize}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def get_signatures_by_type(self, organizationId: int) -> tuple[bool, None]:
		'''
		Class AvSignatureUpdate
		Description: return av signatures by type.
        
		Args:
			organizationId (int): organizationId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_signatures_by_type", locals())

		url = '/api/av-signatures-update/signatures-by-type'
		url_params = []
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def toggle(self, enabled: bool = None, freeTextSearch: str = None, offset: int = None, organizationId: int = None, pageSize: int = None, sorting: str = None) -> tuple[bool, None]:
		'''
		Class AvSignatureUpdate
		Description: Enable / disable feature per organization.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("toggle", locals())

		url = '/api/av-signatures-update/toggle'

		request = {}
		if enabled:
			request["enabled"] = f"{enabled}"
		if freeTextSearch:
			request["freeTextSearch"] = f"{freeTextSearch}"
		if offset != None:
			request["offset"] = f"{offset}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"
		if pageSize != None:
			request["pageSize"] = f"{pageSize}"
		if sorting:
			request["sorting"] = f"{sorting}"

		return fortiedr_connection.insert(url, request)

class CollectorSettings:
	'''Collector Settings Policy Rest Api Controller'''

	def assign_policy(self, forceGroupsAssign: bool = None, freeTextSearch: str = None, groupsIds: list = None, id: int = None, offset: int = None, organizationId: int = None, pageSize: int = None, sorting: str = None) -> tuple[bool, None]:
		'''
		Class CollectorSettings
		Description: assign agent group to policy.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("assign_policy", locals())

		url = '/api/collector-settings/assign-agent-groups'

		request = {}
		if forceGroupsAssign:
			request["forceGroupsAssign"] = f"{forceGroupsAssign}"
		if freeTextSearch:
			request["freeTextSearch"] = f"{freeTextSearch}"
		if groupsIds:
			request["groupsIds"] = f"{groupsIds}"
		if id != None:
			request["id"] = f"{id}"
		if offset != None:
			request["offset"] = f"{offset}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"
		if pageSize != None:
			request["pageSize"] = f"{pageSize}"
		if sorting:
			request["sorting"] = f"{sorting}"

		return fortiedr_connection.insert(url, request)

	def clone_policy(self, newPolicyName: str, organization: str, sourcePolicyName: str) -> tuple[bool, list]:
		'''
		Class CollectorSettings
		Description: clone policy.
        
		Args:
			clonePolicyRequest (Object): Check 'clonePolicyRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("clone_policy", locals())

		url = '/api/collector-settings/clone-policy'

		clonePolicyRequest = {}
		if newPolicyName:
			clonePolicyRequest["newPolicyName"] = f"{newPolicyName}"
		if organization:
			clonePolicyRequest["organization"] = f"{organization}"
		if sourcePolicyName:
			clonePolicyRequest["sourcePolicyName"] = f"{sourcePolicyName}"

		return fortiedr_connection.send(url, clonePolicyRequest)

	def get_get_policies(self, freeTextSearch: str = None, offset: int = None, organizationId: int = None, pageSize: int = None, sorting: str = None) -> tuple[bool, None]:
		'''
		Class CollectorSettings
		Description: return collector settings policies.
        
		Args:
			freeTextSearch (str): pattern of requested text
			offset (int): Specifies the page offset
			organizationId (int): Specifies the organization id
			pageSize (int): Specifies the page size
			sorting (str): list of sorting fields (each is a map of <fieldName>:<descending order flag>. false=ascending, true=descending)

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_get_policies", locals())

		url = '/api/collector-settings/policies'
		url_params = []
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if offset != None:
			url_params.append(f'offset={offset}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if pageSize != None:
			url_params.append(f'pageSize={pageSize}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def delete_policy(self, organization: str, deleteAll: bool = None, freeTextSearch: str = None, idToDelete: list = None, requirePolicyAssociation: bool = None) -> tuple[bool, None]:
		'''
		Class CollectorSettings
		Description: Deletes a collector settings policy.
        
		Args:
			deleteAll (bool): Indicate if should delete all matching results (rather than only the selected) 
			freeTextSearch (str): pattern of policies to delete
			idToDelete (list): Id's of entities to delete
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			requirePolicyAssociation (bool): require policy association

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_policy", locals())

		url = '/api/collector-settings/policies'
		url_params = []
		if deleteAll != None:
			url_params.append(f'deleteAll={deleteAll}')
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if idToDelete != None:
			idToDelete = ",".join(map(str, idToDelete)) if isinstance(idToDelete, list) else idToDelete
			url_params.append(f'idToDelete={idToDelete}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if requirePolicyAssociation != None:
			url_params.append(f'requirePolicyAssociation={requirePolicyAssociation}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def state(self, IsDefault: bool = None, closeExistingConnections: bool = None, description: str = None, enabled: bool = None, groupsIds: list = None, id: int = None, name: str = None, organizationId: int = None, organizationName: str = None, policiesIds: list = None, timeConfig: list = None, updateMethod: str = None) -> tuple[bool, list]:
		'''
		Class CollectorSettings
		Description: set policy state.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("state", locals())

		url = '/api/collector-settings/policies/state'

		request = {}
		if IsDefault:
			request["IsDefault"] = f"{IsDefault}"
		if closeExistingConnections:
			request["closeExistingConnections"] = f"{closeExistingConnections}"
		if description:
			request["description"] = f"{description}"
		if enabled:
			request["enabled"] = f"{enabled}"
		if groupsIds:
			request["groupsIds"] = f"{groupsIds}"
		if id != None:
			request["id"] = f"{id}"
		if name:
			request["name"] = f"{name}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"
		if organizationName:
			request["organizationName"] = f"{organizationName}"
		if policiesIds:
			request["policiesIds"] = f"{policiesIds}"
		if timeConfig:
			request["timeConfig"] = f"{timeConfig}"
		if updateMethod:
			request["updateMethod"] = f"{updateMethod}"

		return fortiedr_connection.insert(url, request)

	def policy(self, name: str, IsDefault: bool = None, closeExistingConnections: bool = None, description: str = None, enabled: bool = None, groupsIds: list = None, id: int = None, organizationId: int = None, organizationName: str = None, timeConfig: list = None, updateMethod: str = None) -> tuple[bool, None]:
		'''
		Class CollectorSettings
		Description: create a collector settings policy.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("policy", locals())

		url = '/api/collector-settings/policy'

		request = {}
		if IsDefault:
			request["IsDefault"] = f"{IsDefault}"
		if closeExistingConnections:
			request["closeExistingConnections"] = f"{closeExistingConnections}"
		if description:
			request["description"] = f"{description}"
		if enabled:
			request["enabled"] = f"{enabled}"
		if groupsIds:
			request["groupsIds"] = f"{groupsIds}"
		if id != None:
			request["id"] = f"{id}"
		if name:
			request["name"] = f"{name}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"
		if organizationName:
			request["organizationName"] = f"{organizationName}"
		if timeConfig:
			request["timeConfig"] = f"{timeConfig}"
		if updateMethod:
			request["updateMethod"] = f"{updateMethod}"

		return fortiedr_connection.send(url, request)

	def policy(self, agentGroupsIds: list = None, excludePolicyId: int = None) -> tuple[bool, list]:
		'''
		Class CollectorSettings
		Description: returns existing agent group assignments.
        
		Args:
			agentGroupsIds (list): agent groups id's
			excludePolicyId (int): exclude policy id

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("policy", locals())

		url = '/api/collector-settings/policy/existing-groups-assignment'
		url_params = []
		if agentGroupsIds != None:
			agentGroupsIds = ",".join(map(str, agentGroupsIds)) if isinstance(agentGroupsIds, list) else agentGroupsIds
			url_params.append(f'agentGroupsIds={agentGroupsIds}')
		if excludePolicyId != None:
			url_params.append(f'excludePolicyId={excludePolicyId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def get_get_policy(self, id: int, organizationId: int) -> tuple[bool, None]:
		'''
		Class CollectorSettings
		Description: get a collector settings policy.
        
		Args:
			id (int): id
			organizationId (int): organizationId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_get_policy", locals())

		url = f'/api/collector-settings/policy/{id}'


		return fortiedr_connection.get(url, organizationId)

	def insert_update_policy(self, id: int, IsDefault: bool = None, closeExistingConnections: bool = None, description: str = None, enabled: bool = None, groupsIds: list = None, name: str = None, organizationId: int = None, organizationName: str = None, timeConfig: list = None, updateMethod: str = None) -> tuple[bool, None]:
		'''
		Class CollectorSettings
		Description: update a collector settings policy.
        
		Args:
			id (int): id
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("insert_update_policy", locals())

		url = f'/api/collector-settings/policy/{id}'

		request = {}
		if IsDefault:
			request["IsDefault"] = f"{IsDefault}"
		if closeExistingConnections:
			request["closeExistingConnections"] = f"{closeExistingConnections}"
		if description:
			request["description"] = f"{description}"
		if enabled:
			request["enabled"] = f"{enabled}"
		if groupsIds:
			request["groupsIds"] = f"{groupsIds}"
		if id != None:
			request["id"] = f"{id}"
		if name:
			request["name"] = f"{name}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"
		if organizationName:
			request["organizationName"] = f"{organizationName}"
		if timeConfig:
			request["timeConfig"] = f"{timeConfig}"
		if updateMethod:
			request["updateMethod"] = f"{updateMethod}"

		return fortiedr_connection.insert(url, request)

class dashboardrestapicontroller:
	'''Dashboard Rest Api Controller'''

	def collectors(self, organization: str, endDate: int = None, key: str = None, os: str = None, size: int = None, sortByField: str = None, sortDirection: str = None, startDate: int = None, timeFilter: str = None) -> tuple[bool, list]:
		'''
		Class dashboardrestapicontroller
		Description: Return collectors according to group by field.
        
		Args:
			endDate (int): Specifies the time filter end date
			key (str): Specifies the chart key
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			os (str): Specifies the OS of the return data
			size (int): Specifies the chart number axis items to display
			sortByField (str): Specifies the sort by field
			sortDirection (str): Specifies the sort direction
			startDate (int): Specifies the time filter start date
			timeFilter (str): Specifies the time filter

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("collectors", locals())

		url = '/api/dashboard/collectors'
		url_params = []
		if endDate != None:
			url_params.append(f'endDate={endDate}')
		if key != None:
			url_params.append(f'key={key}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if os != None:
			url_params.append(f'os={os}')
		if size != None:
			url_params.append(f'size={size}')
		if sortByField != None:
			url_params.append(f'sortByField={sortByField}')
		if sortDirection != None:
			url_params.append(f'sortDirection={sortDirection}')
		if startDate != None:
			url_params.append(f'startDate={startDate}')
		if timeFilter != None:
			url_params.append(f'timeFilter={timeFilter}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def collectors_by_os(self, organization: str, endDate: int = None, key: str = None, os: str = None, size: int = None, sortByField: str = None, sortDirection: str = None, startDate: int = None, timeFilter: str = None) -> tuple[bool, list]:
		'''
		Class dashboardrestapicontroller
		Description: Return collectors according to group by field.
        
		Args:
			endDate (int): Specifies the time filter end date
			key (str): Specifies the chart key
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			os (str): Specifies the OS of the return data
			size (int): Specifies the chart number axis items to display
			sortByField (str): Specifies the sort by field
			sortDirection (str): Specifies the sort direction
			startDate (int): Specifies the time filter start date
			timeFilter (str): Specifies the time filter

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("collectors_by_os", locals())

		url = '/api/dashboard/collectors-by-os'
		url_params = []
		if endDate != None:
			url_params.append(f'endDate={endDate}')
		if key != None:
			url_params.append(f'key={key}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if os != None:
			url_params.append(f'os={os}')
		if size != None:
			url_params.append(f'size={size}')
		if sortByField != None:
			url_params.append(f'sortByField={sortByField}')
		if sortDirection != None:
			url_params.append(f'sortDirection={sortDirection}')
		if startDate != None:
			url_params.append(f'startDate={startDate}')
		if timeFilter != None:
			url_params.append(f'timeFilter={timeFilter}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def collectors_by_policies(self, organization: str, endDate: int = None, key: str = None, os: str = None, size: int = None, sortByField: str = None, sortDirection: str = None, startDate: int = None, timeFilter: str = None) -> tuple[bool, list]:
		'''
		Class dashboardrestapicontroller
		Description: Return collectors by policies.
        
		Args:
			endDate (int): Specifies the time filter end date
			key (str): Specifies the chart key
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			os (str): Specifies the OS of the return data
			size (int): Specifies the chart number axis items to display
			sortByField (str): Specifies the sort by field
			sortDirection (str): Specifies the sort direction
			startDate (int): Specifies the time filter start date
			timeFilter (str): Specifies the time filter

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("collectors_by_policies", locals())

		url = '/api/dashboard/collectors-by-policies'
		url_params = []
		if endDate != None:
			url_params.append(f'endDate={endDate}')
		if key != None:
			url_params.append(f'key={key}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if os != None:
			url_params.append(f'os={os}')
		if size != None:
			url_params.append(f'size={size}')
		if sortByField != None:
			url_params.append(f'sortByField={sortByField}')
		if sortDirection != None:
			url_params.append(f'sortDirection={sortDirection}')
		if startDate != None:
			url_params.append(f'startDate={startDate}')
		if timeFilter != None:
			url_params.append(f'timeFilter={timeFilter}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def collectors_by_version(self, organization: str, endDate: int = None, key: str = None, os: str = None, size: int = None, sortByField: str = None, sortDirection: str = None, startDate: int = None, timeFilter: str = None) -> tuple[bool, list]:
		'''
		Class dashboardrestapicontroller
		Description: Return collectors according to group by field.
        
		Args:
			endDate (int): Specifies the time filter end date
			key (str): Specifies the chart key
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			os (str): Specifies the OS of the return data
			size (int): Specifies the chart number axis items to display
			sortByField (str): Specifies the sort by field
			sortDirection (str): Specifies the sort direction
			startDate (int): Specifies the time filter start date
			timeFilter (str): Specifies the time filter

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("collectors_by_version", locals())

		url = '/api/dashboard/collectors-by-version'
		url_params = []
		if endDate != None:
			url_params.append(f'endDate={endDate}')
		if key != None:
			url_params.append(f'key={key}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if os != None:
			url_params.append(f'os={os}')
		if size != None:
			url_params.append(f'size={size}')
		if sortByField != None:
			url_params.append(f'sortByField={sortByField}')
		if sortDirection != None:
			url_params.append(f'sortDirection={sortDirection}')
		if startDate != None:
			url_params.append(f'startDate={startDate}')
		if timeFilter != None:
			url_params.append(f'timeFilter={timeFilter}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def com_control_policies(self, organization: str, endDate: int = None, key: str = None, operationMode: str = None, size: int = None, sortByField: str = None, sortDirection: str = None, startDate: int = None, timeFilter: str = None) -> tuple[bool, list]:
		'''
		Class dashboardrestapicontroller
		Description: Return com control policies.
        
		Args:
			endDate (int): Specifies the time filter end date
			key (str): Specifies the chart key
			operationMode (str): Specifies the operation mode.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			size (int): Specifies the chart number axis items to display
			sortByField (str): Specifies the sort by field
			sortDirection (str): Specifies the sort direction
			startDate (int): Specifies the time filter start date
			timeFilter (str): Specifies the time filter

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("com_control_policies", locals())

		url = '/api/dashboard/com-control-policies'
		url_params = []
		if endDate != None:
			url_params.append(f'endDate={endDate}')
		if key != None:
			url_params.append(f'key={key}')
		if operationMode != None:
			url_params.append(f'operationMode={operationMode}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if size != None:
			url_params.append(f'size={size}')
		if sortByField != None:
			url_params.append(f'sortByField={sortByField}')
		if sortDirection != None:
			url_params.append(f'sortDirection={sortDirection}')
		if startDate != None:
			url_params.append(f'startDate={startDate}')
		if timeFilter != None:
			url_params.append(f'timeFilter={timeFilter}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def detection_activity(self, organization: str, classification: str = None, endDate: int = None, key: str = None, size: int = None, sortByField: str = None, sortDirection: str = None, startDate: int = None, timeFilter: str = None) -> tuple[bool, list]:
		'''
		Class dashboardrestapicontroller
		Description: Return detection activity.
        
		Args:
			classification (str): Specifies the event classification.
			endDate (int): Specifies the time filter end date
			key (str): Specifies the chart key
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			size (int): Specifies the chart number axis items to display
			sortByField (str): Specifies the sort by field
			sortDirection (str): Specifies the sort direction
			startDate (int): Specifies the time filter start date
			timeFilter (str): Specifies the time filter

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("detection_activity", locals())

		url = '/api/dashboard/detection-activity'
		url_params = []
		if classification != None:
			url_params.append(f'classification={classification}')
		if endDate != None:
			url_params.append(f'endDate={endDate}')
		if key != None:
			url_params.append(f'key={key}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if size != None:
			url_params.append(f'size={size}')
		if sortByField != None:
			url_params.append(f'sortByField={sortByField}')
		if sortDirection != None:
			url_params.append(f'sortDirection={sortDirection}')
		if startDate != None:
			url_params.append(f'startDate={startDate}')
		if timeFilter != None:
			url_params.append(f'timeFilter={timeFilter}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def event_classification_distribution(self, organization: str, endDate: int = None, key: str = None, size: int = None, sortByField: str = None, sortDirection: str = None, startDate: int = None, timeFilter: str = None) -> tuple[bool, list]:
		'''
		Class dashboardrestapicontroller
		Description: Return event classification distribution.
        
		Args:
			endDate (int): Specifies the time filter end date
			key (str): Specifies the chart key
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			size (int): Specifies the chart number axis items to display
			sortByField (str): Specifies the sort by field
			sortDirection (str): Specifies the sort direction
			startDate (int): Specifies the time filter start date
			timeFilter (str): Specifies the time filter

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("event_classification_distribution", locals())

		url = '/api/dashboard/event-classification-distribution'
		url_params = []
		if endDate != None:
			url_params.append(f'endDate={endDate}')
		if key != None:
			url_params.append(f'key={key}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if size != None:
			url_params.append(f'size={size}')
		if sortByField != None:
			url_params.append(f'sortByField={sortByField}')
		if sortDirection != None:
			url_params.append(f'sortDirection={sortDirection}')
		if startDate != None:
			url_params.append(f'startDate={startDate}')
		if timeFilter != None:
			url_params.append(f'timeFilter={timeFilter}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def generate_report(self, request: object) -> tuple[bool, None]:
		'''
		Class dashboardrestapicontroller
		Description: Export to excel.
        
		Args:
			request (object): request

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("generate_report", locals())

		url = '/api/dashboard/generate-report'


		return fortiedr_connection.send(url, request)

	def get_progress(self, progressBarId: int = None) -> tuple[bool, None]:
		'''
		Class dashboardrestapicontroller
		Description: Get progress.
        
		Args:
			progressBarId (int): progressBarId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_progress", locals())

		url = '/api/dashboard/get-progress'
		url_params = []
		if progressBarId != None:
			url_params.append(f'progressBarId={progressBarId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def layout_config(self) -> tuple[bool, None]:
		'''
		Class dashboardrestapicontroller
		Description: Return dashboard layout config.
        
		Args:

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("layout_config", locals())

		url = '/api/dashboard/layout-config'
		return fortiedr_connection.get(url)

	def license_capacity_per_organization(self, organization: str, endDate: int = None, key: str = None, selectedOrganization: str = None, size: int = None, sortByField: str = None, sortDirection: str = None, startDate: int = None, timeFilter: str = None) -> tuple[bool, list]:
		'''
		Class dashboardrestapicontroller
		Description: Return license capacity per organization.
        
		Args:
			endDate (int): Specifies the time filter end date
			key (str): Specifies the chart key
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			selectedOrganization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			size (int): Specifies the chart number axis items to display
			sortByField (str): Specifies the sort by field
			sortDirection (str): Specifies the sort direction
			startDate (int): Specifies the time filter start date
			timeFilter (str): Specifies the time filter

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("license_capacity_per_organization", locals())

		url = '/api/dashboard/license-capacity-per-organization'
		url_params = []
		if endDate != None:
			url_params.append(f'endDate={endDate}')
		if key != None:
			url_params.append(f'key={key}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if selectedOrganization != None:
			url_params.append(f'selectedOrganization={selectedOrganization}')
		if size != None:
			url_params.append(f'size={size}')
		if sortByField != None:
			url_params.append(f'sortByField={sortByField}')
		if sortDirection != None:
			url_params.append(f'sortDirection={sortDirection}')
		if startDate != None:
			url_params.append(f'startDate={startDate}')
		if timeFilter != None:
			url_params.append(f'timeFilter={timeFilter}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def license_status_per_organization(self, organization: str, endDate: int = None, key: str = None, selectedOrganization: str = None, size: int = None, sortByField: str = None, sortDirection: str = None, startDate: int = None, timeFilter: str = None) -> tuple[bool, None]:
		'''
		Class dashboardrestapicontroller
		Description: Return license status per organization.
        
		Args:
			endDate (int): Specifies the time filter end date
			key (str): Specifies the chart key
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			selectedOrganization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			size (int): Specifies the chart number axis items to display
			sortByField (str): Specifies the sort by field
			sortDirection (str): Specifies the sort direction
			startDate (int): Specifies the time filter start date
			timeFilter (str): Specifies the time filter

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("license_status_per_organization", locals())

		url = '/api/dashboard/license-status-per-organization'
		url_params = []
		if endDate != None:
			url_params.append(f'endDate={endDate}')
		if key != None:
			url_params.append(f'key={key}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if selectedOrganization != None:
			url_params.append(f'selectedOrganization={selectedOrganization}')
		if size != None:
			url_params.append(f'size={size}')
		if sortByField != None:
			url_params.append(f'sortByField={sortByField}')
		if sortDirection != None:
			url_params.append(f'sortDirection={sortDirection}')
		if startDate != None:
			url_params.append(f'startDate={startDate}')
		if timeFilter != None:
			url_params.append(f'timeFilter={timeFilter}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def most_targeted_items(self, organization: str, itemType: str = None, numOfColumns: int = None, numOfDays: int = None) -> tuple[bool, None]:
		'''
		Class dashboardrestapicontroller
		Description: Returns most targeted devices or most targeted processes, depending on the itemType parameter.
        
		Args:
			itemType (str): Specifies the type of items
			numOfColumns (int): Specifies the number of columns to present
			numOfDays (int): Specifies the number of days to present
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("most_targeted_items", locals())

		url = '/api/dashboard/most-targeted-items'
		url_params = []
		if itemType != None:
			url_params.append(f'itemType={itemType}')
		if numOfColumns != None:
			url_params.append(f'numOfColumns={numOfColumns}')
		if numOfDays != None:
			url_params.append(f'numOfDays={numOfDays}')
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def my_events(self, organization: str, endDate: int = None, key: str = None, size: int = None, sortByField: str = None, sortDirection: str = None, startDate: int = None, timeFilter: str = None) -> tuple[bool, list]:
		'''
		Class dashboardrestapicontroller
		Description: Return my events.
        
		Args:
			endDate (int): Specifies the time filter end date
			key (str): Specifies the chart key
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			size (int): Specifies the chart number axis items to display
			sortByField (str): Specifies the sort by field
			sortDirection (str): Specifies the sort direction
			startDate (int): Specifies the time filter start date
			timeFilter (str): Specifies the time filter

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("my_events", locals())

		url = '/api/dashboard/my-events'
		url_params = []
		if endDate != None:
			url_params.append(f'endDate={endDate}')
		if key != None:
			url_params.append(f'key={key}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if size != None:
			url_params.append(f'size={size}')
		if sortByField != None:
			url_params.append(f'sortByField={sortByField}')
		if sortDirection != None:
			url_params.append(f'sortDirection={sortDirection}')
		if startDate != None:
			url_params.append(f'startDate={startDate}')
		if timeFilter != None:
			url_params.append(f'timeFilter={timeFilter}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def new_detections(self, organization: str, classification: str = None, endDate: int = None, key: str = None, size: int = None, sortByField: str = None, sortDirection: str = None, startDate: int = None, timeFilter: str = None) -> tuple[bool, list]:
		'''
		Class dashboardrestapicontroller
		Description: Return new detections.
        
		Args:
			classification (str): Specifies the event classification.
			endDate (int): Specifies the time filter end date
			key (str): Specifies the chart key
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			size (int): Specifies the chart number axis items to display
			sortByField (str): Specifies the sort by field
			sortDirection (str): Specifies the sort direction
			startDate (int): Specifies the time filter start date
			timeFilter (str): Specifies the time filter

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("new_detections", locals())

		url = '/api/dashboard/new-detections'
		url_params = []
		if classification != None:
			url_params.append(f'classification={classification}')
		if endDate != None:
			url_params.append(f'endDate={endDate}')
		if key != None:
			url_params.append(f'key={key}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if size != None:
			url_params.append(f'size={size}')
		if sortByField != None:
			url_params.append(f'sortByField={sortByField}')
		if sortDirection != None:
			url_params.append(f'sortDirection={sortDirection}')
		if startDate != None:
			url_params.append(f'startDate={startDate}')
		if timeFilter != None:
			url_params.append(f'timeFilter={timeFilter}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def system_components(self, organization: str, endDate: int = None, key: str = None, size: int = None, sortByField: str = None, sortDirection: str = None, startDate: int = None, timeFilter: str = None) -> tuple[bool, list]:
		'''
		Class dashboardrestapicontroller
		Description: Return system components.
        
		Args:
			endDate (int): Specifies the time filter end date
			key (str): Specifies the chart key
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			size (int): Specifies the chart number axis items to display
			sortByField (str): Specifies the sort by field
			sortDirection (str): Specifies the sort direction
			startDate (int): Specifies the time filter start date
			timeFilter (str): Specifies the time filter

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("system_components", locals())

		url = '/api/dashboard/system-components'
		url_params = []
		if endDate != None:
			url_params.append(f'endDate={endDate}')
		if key != None:
			url_params.append(f'key={key}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if size != None:
			url_params.append(f'size={size}')
		if sortByField != None:
			url_params.append(f'sortByField={sortByField}')
		if sortDirection != None:
			url_params.append(f'sortDirection={sortDirection}')
		if startDate != None:
			url_params.append(f'startDate={startDate}')
		if timeFilter != None:
			url_params.append(f'timeFilter={timeFilter}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def team_workload_overview(self, organization: str, endDate: int = None, incidentHandlingState: str = None, key: str = None, size: int = None, sortByField: str = None, sortDirection: str = None, startDate: int = None, timeFilter: str = None) -> tuple[bool, list]:
		'''
		Class dashboardrestapicontroller
		Description: Return team workload overview.
        
		Args:
			endDate (int): Specifies the time filter end date
			incidentHandlingState (str): Specifies the incident handling state.
			key (str): Specifies the chart key
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			size (int): Specifies the chart number axis items to display
			sortByField (str): Specifies the sort by field
			sortDirection (str): Specifies the sort direction
			startDate (int): Specifies the time filter start date
			timeFilter (str): Specifies the time filter

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("team_workload_overview", locals())

		url = '/api/dashboard/team-workload-overview'
		url_params = []
		if endDate != None:
			url_params.append(f'endDate={endDate}')
		if incidentHandlingState != None:
			url_params.append(f'incidentHandlingState={incidentHandlingState}')
		if key != None:
			url_params.append(f'key={key}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if size != None:
			url_params.append(f'size={size}')
		if sortByField != None:
			url_params.append(f'sortByField={sortByField}')
		if sortDirection != None:
			url_params.append(f'sortDirection={sortDirection}')
		if startDate != None:
			url_params.append(f'startDate={startDate}')
		if timeFilter != None:
			url_params.append(f'timeFilter={timeFilter}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def top_affected_devices(self, organization: str, endDate: int = None, key: str = None, size: int = None, sortByField: str = None, sortDirection: str = None, startDate: int = None, timeFilter: str = None) -> tuple[bool, list]:
		'''
		Class dashboardrestapicontroller
		Description: Return top affected devices.
        
		Args:
			endDate (int): Specifies the time filter end date
			key (str): Specifies the chart key
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			size (int): Specifies the chart number axis items to display
			sortByField (str): Specifies the sort by field
			sortDirection (str): Specifies the sort direction
			startDate (int): Specifies the time filter start date
			timeFilter (str): Specifies the time filter

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("top_affected_devices", locals())

		url = '/api/dashboard/top-affected-devices'
		url_params = []
		if endDate != None:
			url_params.append(f'endDate={endDate}')
		if key != None:
			url_params.append(f'key={key}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if size != None:
			url_params.append(f'size={size}')
		if sortByField != None:
			url_params.append(f'sortByField={sortByField}')
		if sortDirection != None:
			url_params.append(f'sortDirection={sortDirection}')
		if startDate != None:
			url_params.append(f'startDate={startDate}')
		if timeFilter != None:
			url_params.append(f'timeFilter={timeFilter}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def top_detection_rule_by_occurrence(self, organization: str, endDate: int = None, key: str = None, numOfResultsToDisplay: int = None, size: int = None, sortByField: str = None, sortDirection: str = None, startDate: int = None, timeFilter: str = None) -> tuple[bool, list]:
		'''
		Class dashboardrestapicontroller
		Description: Return top detection rule by occurrence.
        
		Args:
			endDate (int): Specifies the time filter end date
			key (str): Specifies the chart key
			numOfResultsToDisplay (int): Specifies the num of results to display.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			size (int): Specifies the chart number axis items to display
			sortByField (str): Specifies the sort by field
			sortDirection (str): Specifies the sort direction
			startDate (int): Specifies the time filter start date
			timeFilter (str): Specifies the time filter

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("top_detection_rule_by_occurrence", locals())

		url = '/api/dashboard/top-detection-rule-by-occurrence'
		url_params = []
		if endDate != None:
			url_params.append(f'endDate={endDate}')
		if key != None:
			url_params.append(f'key={key}')
		if numOfResultsToDisplay != None:
			url_params.append(f'numOfResultsToDisplay={numOfResultsToDisplay}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if size != None:
			url_params.append(f'size={size}')
		if sortByField != None:
			url_params.append(f'sortByField={sortByField}')
		if sortDirection != None:
			url_params.append(f'sortDirection={sortDirection}')
		if startDate != None:
			url_params.append(f'startDate={startDate}')
		if timeFilter != None:
			url_params.append(f'timeFilter={timeFilter}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def top_response_action(self, organization: str, endDate: int = None, key: str = None, size: int = None, sortByField: str = None, sortDirection: str = None, startDate: int = None, timeFilter: str = None) -> tuple[bool, list]:
		'''
		Class dashboardrestapicontroller
		Description: Return top response action.
        
		Args:
			endDate (int): Specifies the time filter end date
			key (str): Specifies the chart key
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			size (int): Specifies the chart number axis items to display
			sortByField (str): Specifies the sort by field
			sortDirection (str): Specifies the sort direction
			startDate (int): Specifies the time filter start date
			timeFilter (str): Specifies the time filter

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("top_response_action", locals())

		url = '/api/dashboard/top-response-action'
		url_params = []
		if endDate != None:
			url_params.append(f'endDate={endDate}')
		if key != None:
			url_params.append(f'key={key}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if size != None:
			url_params.append(f'size={size}')
		if sortByField != None:
			url_params.append(f'sortByField={sortByField}')
		if sortDirection != None:
			url_params.append(f'sortDirection={sortDirection}')
		if startDate != None:
			url_params.append(f'startDate={startDate}')
		if timeFilter != None:
			url_params.append(f'timeFilter={timeFilter}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def unhandled_items(self, organization: str, itemType: str = None) -> tuple[bool, None]:
		'''
		Class dashboardrestapicontroller
		Description: Returns unhandled devices or unhandled processes, depending on the itemType parameter.
        
		Args:
			itemType (str): Specifies the type of items
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("unhandled_items", locals())

		url = '/api/dashboard/unhandled-items'
		url_params = []
		if itemType != None:
			url_params.append(f'itemType={itemType}')
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

class DistributionLists:
	'''Distribution Lists Rest Api Controller'''

	def distribution_lists(self, accountId: int = None, maxResults: int = None, start: int = None) -> tuple[bool, None]:
		'''
		Class DistributionLists
		Description: Return distribution lists.
        
		Args:
			accountId (int): Account Id
			maxResults (int): Maximum number of results per page
			start (int): Start index for pagination

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("distribution_lists", locals())

		url = '/api/distribution-lists'
		url_params = []
		if accountId != None:
			url_params.append(f'accountId={accountId}')
		if maxResults != None:
			url_params.append(f'maxResults={maxResults}')
		if start != None:
			url_params.append(f'start={start}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def distribution_lists_all(self, accountId: int) -> tuple[bool, list]:
		'''
		Class DistributionLists
		Description: Return distribution lists.
        
		Args:
			accountId (int): accountId

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("distribution_lists_all", locals())

		url = '/api/distribution-lists/all'
		url_params = []
		if accountId != None:
			url_params.append(f'accountId={accountId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def delete_lists(self, listIds: str) -> tuple[bool, None]:
		'''
		Class DistributionLists
		Description: Delete list.
        
		Args:
			listIds (str): listIds

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_lists", locals())

		url = f'/api/distribution-lists/delete-lists/{listIds}'
		return fortiedr_connection.delete(url)

	def delete_recipients(self, recipientsIds: str) -> tuple[bool, None]:
		'''
		Class DistributionLists
		Description: Delete recipients.
        
		Args:
			recipientsIds (str): recipientsIds

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_recipients", locals())

		url = f'/api/distribution-lists/delete-recipients/{recipientsIds}'
		return fortiedr_connection.delete(url)

	def distribution_list_info(self, groupId: int) -> tuple[bool, None]:
		'''
		Class DistributionLists
		Description: Return distribution list info by given list id.
        
		Args:
			groupId (int): groupId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("distribution_list_info", locals())

		url = f'/api/distribution-lists/info/{groupId}'
		return fortiedr_connection.get(url)

	def recipient_info(self, accountId: int, recipientId: int) -> tuple[bool, None]:
		'''
		Class DistributionLists
		Description: Return recipient info by given recipient id.
        
		Args:
			accountId (int): accountId
			recipientId (int): recipientId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("recipient_info", locals())

		url = f'/api/distribution-lists/recipient-info/{recipientId}'
		url_params = []
		if accountId != None:
			url_params.append(f'accountId={accountId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def recipients_assignment_info(self, recipientIds: list) -> tuple[bool, None]:
		'''
		Class DistributionLists
		Description: Return assignment info for recipients.
        
		Args:
			recipientIds (list): recipientIds

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("recipients_assignment_info", locals())

		url = '/api/distribution-lists/recipients/assignment-info'
		url_params = []
		if recipientIds != None:
			recipientIds = ",".join(map(str, recipientIds)) if isinstance(recipientIds, list) else recipientIds
			url_params.append(f'recipientIds={recipientIds}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def recipients_save_assignments(self, contactGroupDisplayItems: list = None, contactIDs: list = None) -> tuple[bool, None]:
		'''
		Class DistributionLists
		Description: Save recipients assignments.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("recipients_save_assignments", locals())

		url = '/api/distribution-lists/recipients/save-assignments'

		request = {}
		if contactGroupDisplayItems:
			request["contactGroupDisplayItems"] = f"{contactGroupDisplayItems}"
		if contactIDs:
			request["contactIDs"] = f"{contactIDs}"

		return fortiedr_connection.send(url, request)

	def save_list(self, accountId: int = None, accountName: str = None, allRecipientsGroup: bool = None, assigned: bool = None, attachJson: bool = None, contacts: list = None, id: int = None, name: str = None, securityEventsNotification: bool = None, systemEventsNotification: bool = None) -> tuple[bool, None]:
		'''
		Class DistributionLists
		Description: Save list.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("save_list", locals())

		url = '/api/distribution-lists/save-list'

		request = {}
		if accountId != None:
			request["accountId"] = f"{accountId}"
		if accountName:
			request["accountName"] = f"{accountName}"
		if allRecipientsGroup:
			request["allRecipientsGroup"] = f"{allRecipientsGroup}"
		if assigned:
			request["assigned"] = f"{assigned}"
		if attachJson:
			request["attachJson"] = f"{attachJson}"
		if contacts:
			request["contacts"] = f"{contacts}"
		if id != None:
			request["id"] = f"{id}"
		if name:
			request["name"] = f"{name}"
		if securityEventsNotification:
			request["securityEventsNotification"] = f"{securityEventsNotification}"
		if systemEventsNotification:
			request["systemEventsNotification"] = f"{systemEventsNotification}"

		return fortiedr_connection.send(url, request)

	def save_recipient(self, email: str, firstName: str, lastName: str, accountId: int = None, accountName: str = None, contactGroups: list = None, id: int = None, title: str = None) -> tuple[bool, None]:
		'''
		Class DistributionLists
		Description: Save recipient.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("save_recipient", locals())

		url = '/api/distribution-lists/save-recipient'

		request = {}
		if accountId != None:
			request["accountId"] = f"{accountId}"
		if accountName:
			request["accountName"] = f"{accountName}"
		if contactGroups:
			request["contactGroups"] = f"{contactGroups}"
		if email:
			request["email"] = f"{email}"
		if firstName:
			request["firstName"] = f"{firstName}"
		if id != None:
			request["id"] = f"{id}"
		if lastName:
			request["lastName"] = f"{lastName}"
		if title:
			request["title"] = f"{title}"

		return fortiedr_connection.send(url, request)

	def update_notification(self, listId: int, accountId: int = None, securityEventsNotification: bool = None, systemEventsNotification: bool = None) -> tuple[bool, None]:
		'''
		Class DistributionLists
		Description: Update notification.
        
		Args:
			listId (int): listId
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("update_notification", locals())

		url = f'/api/distribution-lists/update-notification/{listId}'

		request = {}
		if accountId != None:
			request["accountId"] = f"{accountId}"
		if securityEventsNotification:
			request["securityEventsNotification"] = f"{securityEventsNotification}"
		if systemEventsNotification:
			request["systemEventsNotification"] = f"{systemEventsNotification}"

		return fortiedr_connection.insert(url, request)

class exclusionsrestapicontroller:
	'''Exclusions Rest Api Controller'''

	def Save_exclusions(self, exclusions: list = None, exclusionsListId: int = None, organizationId: int = None) -> tuple[bool, None]:
		'''
		Class exclusionsrestapicontroller
		Description: Save security exclusions.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("Save_exclusions", locals())

		url = '/api/exclusions'

		request = {}
		if exclusions:
			request["exclusions"] = f"{exclusions}"
		if exclusionsListId != None:
			request["exclusionsListId"] = f"{exclusionsListId}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"

		return fortiedr_connection.send(url, request)

	def Create_exclusions_list(self, name: str = None, organizationId: int = None) -> tuple[bool, None]:
		'''
		Class exclusionsrestapicontroller
		Description: Creates a new security exclusions list.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("Create_exclusions_list", locals())

		url = '/api/exclusions/lists'

		request = {}
		if name:
			request["name"] = f"{name}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"

		return fortiedr_connection.send(url, request)

	def Get_exclusions_lists(self, organizationId: int) -> tuple[bool, list]:
		'''
		Class exclusionsrestapicontroller
		Description: Returns all security exclusion lists for the given organization.
        
		Args:
			organizationId (int): organizationId

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("Get_exclusions_lists", locals())

		url = f'/api/exclusions/lists/{organizationId}'
		return fortiedr_connection.get(url)

	def Delete_exclusions_list(self, organizationId: int, policyId: int) -> tuple[bool, None]:
		'''
		Class exclusionsrestapicontroller
		Description: Deletes the security exclusions list for the given policy ID.
        
		Args:
			organizationId (int): organizationId
			policyId (int): policyId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("Delete_exclusions_list", locals())

		url = f'/api/exclusions/lists/{organizationId}/{policyId}'
		return fortiedr_connection.delete(url)

	def Delete_exclusions(self, organizationId: int, ruleIds: str) -> tuple[bool, None]:
		'''
		Class exclusionsrestapicontroller
		Description: Deletes the specified security exclusions by their rule IDs.
        
		Args:
			organizationId (int): organizationId
			ruleIds (str): ruleIds

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("Delete_exclusions", locals())

		url = f'/api/exclusions/lists/{organizationId}/{ruleIds}'
		return fortiedr_connection.delete(url)

class Mobile:
	'''Mobile Exclusions Rest Api Controller'''

	def Save_exclusions_Mobile(self, exclusionGroupId: int = None, exclusions: list = None, organizationId: int = None) -> tuple[bool, None]:
		'''
		Class Mobile
		Description: Save security exclusions (mobile).
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("Save_exclusions_Mobile", locals())

		url = '/api/exclusions/mobile'

		request = {}
		if exclusionGroupId != None:
			request["exclusionGroupId"] = f"{exclusionGroupId}"
		if exclusions:
			request["exclusions"] = f"{exclusions}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"

		return fortiedr_connection.send(url, request)

	def Create_exclusions_list_Mobile(self, name: str = None, organizationId: int = None) -> tuple[bool, None]:
		'''
		Class Mobile
		Description: Creates a new security exclusions list (mobile).
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("Create_exclusions_list_Mobile", locals())

		url = '/api/exclusions/mobile/lists'

		request = {}
		if name:
			request["name"] = f"{name}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"

		return fortiedr_connection.send(url, request)

	def Get_exclusions_lists_Mobile(self, organizationId: int) -> tuple[bool, None]:
		'''
		Class Mobile
		Description: Returns all security exclusion lists for the given organization (mobile).
        
		Args:
			organizationId (int): organizationId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("Get_exclusions_lists_Mobile", locals())

		url = f'/api/exclusions/mobile/lists/{organizationId}'
		return fortiedr_connection.get(url)

	def Delete_exclusions_list_Mobile(self, organizationId: int, policyId: int) -> tuple[bool, None]:
		'''
		Class Mobile
		Description: Deletes the security exclusions list for the given policy ID (mobile).
        
		Args:
			organizationId (int): organizationId
			policyId (int): policyId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("Delete_exclusions_list_Mobile", locals())

		url = f'/api/exclusions/mobile/lists/{organizationId}/{policyId}'
		return fortiedr_connection.delete(url)

	def get_incidents(self, advancedFilters: str = None, endDate: int = None, freeTextFilters: list = None, freeTextSearch: str = None, incidentIds: list = None, isAllIncidents: bool = None, offset: int = None, organizationId: int = None, pageSize: int = None, sorting: str = None, startDate: int = None, statusFilter: str = None, tags: list = None, tagsIds: list = None, timeFilter: str = None, typeFilter: str = None) -> tuple[bool, None]:
		'''
		Class Mobile
		Description: Get incidents.
        
		Args:
			advancedFilters (str): Specifies advanced filters
			endDate (int): Specifies the time filter end date
			freeTextFilters (list): Specifies the free text search filter
			freeTextSearch (str): Specifies the free text search
			incidentIds (list): Specifies the id's of the incidents
			isAllIncidents (bool): Specifies the all incidents under the filters/search criteria are selected
			offset (int): Specifies the page offset
			organizationId (int): Specifies the organization id
			pageSize (int): Specifies the page size
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on
			startDate (int): Specifies the time filter start date
			statusFilter (str): Specifies the incidents status filter
			tags (list): Specifies the tags
			tagsIds (list): Specifies the tags ids
			timeFilter (str): Specifies the incidents time filter
			typeFilter (str): Specifies the incidents type filter

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_incidents", locals())

		url = '/api/incidents/mobile'
		url_params = []
		if advancedFilters != None:
			url_params.append(f'advancedFilters={advancedFilters}')
		if endDate != None:
			url_params.append(f'endDate={endDate}')
		if freeTextFilters != None:
			freeTextFilters = ",".join(freeTextFilters) if isinstance(freeTextFilters, list) else freeTextFilters
			url_params.append(f'freeTextFilters={freeTextFilters}')
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if incidentIds != None:
			incidentIds = ",".join(map(str, incidentIds)) if isinstance(incidentIds, list) else incidentIds
			url_params.append(f'incidentIds={incidentIds}')
		if isAllIncidents != None:
			url_params.append(f'isAllIncidents={isAllIncidents}')
		if offset != None:
			url_params.append(f'offset={offset}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if pageSize != None:
			url_params.append(f'pageSize={pageSize}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if startDate != None:
			url_params.append(f'startDate={startDate}')
		if statusFilter != None:
			url_params.append(f'statusFilter={statusFilter}')
		if tags != None:
			tags = ",".join(tags) if isinstance(tags, list) else tags
			url_params.append(f'tags={tags}')
		if tagsIds != None:
			tagsIds = ",".join(map(str, tagsIds)) if isinstance(tagsIds, list) else tagsIds
			url_params.append(f'tagsIds={tagsIds}')
		if timeFilter != None:
			url_params.append(f'timeFilter={timeFilter}')
		if typeFilter != None:
			url_params.append(f'typeFilter={typeFilter}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def delete_incidents(self, advancedFilters: str = None, allSelectedEventsParentIds: list = None, endDate: int = None, eventIds: list = None, freeTextFilters: list = None, freeTextSearch: str = None, incidentIds: list = None, isAllIncidents: bool = None, offset: int = None, organizationId: int = None, pageSize: int = None, sorting: str = None, startDate: int = None, statusFilter: str = None, tags: list = None, tagsIds: list = None, timeFilter: str = None, typeFilter: str = None) -> tuple[bool, None]:
		'''
		Class Mobile
		Description: Delete incidents.
        
		Args:
			advancedFilters (str): Specifies advanced filters
			allSelectedEventsParentIds (list): Meaning all those incidents' events under the filters/search criteria are selected. Specifies the events parent incidents ids
			endDate (int): Specifies the time filter end date
			eventIds (list): Specifies the IDs of the events
			freeTextFilters (list): Specifies the free text search filter
			freeTextSearch (str): Specifies the free text search
			incidentIds (list): Specifies the id's of the incidents
			isAllIncidents (bool): Specifies the all incidents under the filters/search criteria are selected
			offset (int): Specifies the page offset
			organizationId (int): Specifies the organization id
			pageSize (int): Specifies the page size
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on
			startDate (int): Specifies the time filter start date
			statusFilter (str): Specifies the incidents status filter
			tags (list): Specifies the tags
			tagsIds (list): Specifies the tags ids
			timeFilter (str): Specifies the incidents time filter
			typeFilter (str): Specifies the incidents type filter

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_incidents", locals())

		url = '/api/incidents/mobile'
		url_params = []
		if advancedFilters != None:
			url_params.append(f'advancedFilters={advancedFilters}')
		if allSelectedEventsParentIds != None:
			allSelectedEventsParentIds = ",".join(map(str, allSelectedEventsParentIds)) if isinstance(allSelectedEventsParentIds, list) else allSelectedEventsParentIds
			url_params.append(f'allSelectedEventsParentIds={allSelectedEventsParentIds}')
		if endDate != None:
			url_params.append(f'endDate={endDate}')
		if eventIds != None:
			eventIds = ",".join(map(str, eventIds)) if isinstance(eventIds, list) else eventIds
			url_params.append(f'eventIds={eventIds}')
		if freeTextFilters != None:
			freeTextFilters = ",".join(freeTextFilters) if isinstance(freeTextFilters, list) else freeTextFilters
			url_params.append(f'freeTextFilters={freeTextFilters}')
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if incidentIds != None:
			incidentIds = ",".join(map(str, incidentIds)) if isinstance(incidentIds, list) else incidentIds
			url_params.append(f'incidentIds={incidentIds}')
		if isAllIncidents != None:
			url_params.append(f'isAllIncidents={isAllIncidents}')
		if offset != None:
			url_params.append(f'offset={offset}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if pageSize != None:
			url_params.append(f'pageSize={pageSize}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if startDate != None:
			url_params.append(f'startDate={startDate}')
		if statusFilter != None:
			url_params.append(f'statusFilter={statusFilter}')
		if tags != None:
			tags = ",".join(tags) if isinstance(tags, list) else tags
			url_params.append(f'tags={tags}')
		if tagsIds != None:
			tagsIds = ",".join(map(str, tagsIds)) if isinstance(tagsIds, list) else tagsIds
			url_params.append(f'tagsIds={tagsIds}')
		if timeFilter != None:
			url_params.append(f'timeFilter={timeFilter}')
		if typeFilter != None:
			url_params.append(f'typeFilter={typeFilter}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def update_modification_status(self, advancedFilters: str = None, endDate: int = None, freeTextFilters: list = None, freeTextSearch: str = None, incidentIds: list = None, isAllIncidents: bool = None, offset: int = None, organizationId: int = None, pageSize: int = None, sorting: str = None, startDate: int = None, statusFilter: str = None, timeFilter: str = None, typeFilter: str = None, userId: int = None, userName: str = None) -> tuple[bool, None]:
		'''
		Class Mobile
		Description: update modification status.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("update_modification_status", locals())

		url = '/api/incidents/mobile/assign-user'

		request = {}
		if advancedFilters:
			request["advancedFilters"] = f"{advancedFilters}"
		if endDate != None:
			request["endDate"] = f"{endDate}"
		if freeTextFilters:
			request["freeTextFilters"] = f"{freeTextFilters}"
		if freeTextSearch:
			request["freeTextSearch"] = f"{freeTextSearch}"
		if incidentIds:
			request["incidentIds"] = f"{incidentIds}"
		if isAllIncidents:
			request["isAllIncidents"] = f"{isAllIncidents}"
		if offset != None:
			request["offset"] = f"{offset}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"
		if pageSize != None:
			request["pageSize"] = f"{pageSize}"
		if sorting:
			request["sorting"] = f"{sorting}"
		if startDate != None:
			request["startDate"] = f"{startDate}"
		if statusFilter:
			request["statusFilter"] = f"{statusFilter}"
		if timeFilter:
			request["timeFilter"] = f"{timeFilter}"
		if typeFilter:
			request["typeFilter"] = f"{typeFilter}"
		if userId != None:
			request["userId"] = f"{userId}"
		if userName:
			request["userName"] = f"{userName}"

		return fortiedr_connection.send(url, request)

	def events_handle(self, eventIds: list, classification: str = None, comment: str = None, handlingState: str = None, muteDurationTime: str = None, muteEnabled: bool = None) -> tuple[bool, None]:
		'''
		Class Mobile
		Description: Handle events.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("events_handle", locals())

		url = '/api/incidents/mobile/events/handle'

		request = {}
		if classification:
			request["classification"] = f"{classification}"
		if comment:
			request["comment"] = f"{comment}"
		if eventIds:
			request["eventIds"] = f"{eventIds}"
		if handlingState:
			request["handlingState"] = f"{handlingState}"
		if muteDurationTime:
			request["muteDurationTime"] = f"{muteDurationTime}"
		if muteEnabled:
			request["muteEnabled"] = f"{muteEnabled}"

		return fortiedr_connection.insert(url, request)

	def generate_report(self, advancedFilters: str = None, allSelectedEventsParentIds: list = None, endDate: int = None, eventIds: list = None, freeTextFilters: list = None, freeTextSearch: str = None, incidentIds: list = None, isAllIncidents: bool = None, offset: int = None, organizationId: int = None, pageSize: int = None, sorting: str = None, startDate: int = None, statusFilter: str = None, tags: list = None, tagsIds: list = None, timeFilter: str = None, typeFilter: str = None) -> tuple[bool, None]:
		'''
		Class Mobile
		Description: Generate mobile incidents report.
        
		Args:
			reportRequest (Object): Check 'reportRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("generate_report", locals())

		url = '/api/incidents/mobile/generate-report'

		reportRequest = {}
		if advancedFilters:
			reportRequest["advancedFilters"] = f"{advancedFilters}"
		if allSelectedEventsParentIds:
			reportRequest["allSelectedEventsParentIds"] = f"{allSelectedEventsParentIds}"
		if endDate != None:
			reportRequest["endDate"] = f"{endDate}"
		if eventIds:
			reportRequest["eventIds"] = f"{eventIds}"
		if freeTextFilters:
			reportRequest["freeTextFilters"] = f"{freeTextFilters}"
		if freeTextSearch:
			reportRequest["freeTextSearch"] = f"{freeTextSearch}"
		if incidentIds:
			reportRequest["incidentIds"] = f"{incidentIds}"
		if isAllIncidents:
			reportRequest["isAllIncidents"] = f"{isAllIncidents}"
		if offset != None:
			reportRequest["offset"] = f"{offset}"
		if organizationId != None:
			reportRequest["organizationId"] = f"{organizationId}"
		if pageSize != None:
			reportRequest["pageSize"] = f"{pageSize}"
		if sorting:
			reportRequest["sorting"] = f"{sorting}"
		if startDate != None:
			reportRequest["startDate"] = f"{startDate}"
		if statusFilter:
			reportRequest["statusFilter"] = f"{statusFilter}"
		if tags:
			reportRequest["tags"] = f"{tags}"
		if tagsIds:
			reportRequest["tagsIds"] = f"{tagsIds}"
		if timeFilter:
			reportRequest["timeFilter"] = f"{timeFilter}"
		if typeFilter:
			reportRequest["typeFilter"] = f"{typeFilter}"

		return fortiedr_connection.send(url, reportRequest)

	def incident_handle(self, classification: str = None, comment: str = None, eventIds: list = None, handlingState: str = None, incidentId: int = None, userId: int = None, userName: str = None) -> tuple[bool, None]:
		'''
		Class Mobile
		Description: Handle incidents.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("incident_handle", locals())

		url = '/api/incidents/mobile/incident-handle'

		request = {}
		if classification:
			request["classification"] = f"{classification}"
		if comment:
			request["comment"] = f"{comment}"
		if eventIds:
			request["eventIds"] = f"{eventIds}"
		if handlingState:
			request["handlingState"] = f"{handlingState}"
		if incidentId != None:
			request["incidentId"] = f"{incidentId}"
		if userId != None:
			request["userId"] = f"{userId}"
		if userName:
			request["userName"] = f"{userName}"

		return fortiedr_connection.insert(url, request)

	def get_incident_by_id(self, incidentId: int) -> tuple[bool, None]:
		'''
		Class Mobile
		Description: Get incident by id.
        
		Args:
			incidentId (int): incidentId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_incident_by_id", locals())

		url = f'/api/incidents/mobile/incident/{incidentId}'
		return fortiedr_connection.get(url)

	def update_modification_status(self, incidentId: int, modificationStatus: str) -> tuple[bool, None]:
		'''
		Class Mobile
		Description: update modification status.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("update_modification_status", locals())

		url = '/api/incidents/mobile/modification-status'

		request = {}
		if incidentId != None:
			request["incidentId"] = f"{incidentId}"
		if modificationStatus:
			request["modificationStatus"] = f"{modificationStatus}"

		return fortiedr_connection.send(url, request)

	def get_incident_audit_history(self, incidentId: int, events: list = None) -> tuple[bool, None]:
		'''
		Class Mobile
		Description: get incident audit history.
        
		Args:
			events (list): events
			incidentId (int): incidentId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_incident_audit_history", locals())

		url = f'/api/incidents/mobile/{incidentId}/audit-history'
		url_params = []
		if events != None:
			events = ",".join(map(str, events)) if isinstance(events, list) else events
			url_params.append(f'events={events}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def events(self, advancedFilters: str = None, endDate: int = None, freeTextFilters: list = None, freeTextSearch: str = None, incidentIds: list = None, isAllIncidents: bool = None, offset: int = None, organizationId: int = None, pageSize: int = None, sorting: str = None, startDate: int = None, statusFilter: str = None, timeFilter: str = None, typeFilter: str = None) -> tuple[bool, None]:
		'''
		Class Mobile
		Description: Get events.
        
		Args:
			advancedFilters (str): Specifies advanced filters
			endDate (int): Specifies the time filter end date
			freeTextFilters (list): Specifies the free text search filter
			freeTextSearch (str): Specifies the free text search
			incidentIds (list): Specifies the id's of the incidents
			isAllIncidents (bool): Specifies the all incidents under the filters/search criteria are selected
			offset (int): Specifies the page offset
			organizationId (int): Specifies the organization id
			pageSize (int): Specifies the page size
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on
			startDate (int): Specifies the time filter start date
			statusFilter (str): Specifies the incidents status filter
			timeFilter (str): Specifies the incidents time filter
			typeFilter (str): Specifies the incidents type filter

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("events", locals())

		url = f'/api/incidents/mobile/{incidentId}/events'
		url_params = []
		if advancedFilters != None:
			url_params.append(f'advancedFilters={advancedFilters}')
		if endDate != None:
			url_params.append(f'endDate={endDate}')
		if freeTextFilters != None:
			freeTextFilters = ",".join(freeTextFilters) if isinstance(freeTextFilters, list) else freeTextFilters
			url_params.append(f'freeTextFilters={freeTextFilters}')
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if incidentIds != None:
			incidentIds = ",".join(map(str, incidentIds)) if isinstance(incidentIds, list) else incidentIds
			url_params.append(f'incidentIds={incidentIds}')
		if isAllIncidents != None:
			url_params.append(f'isAllIncidents={isAllIncidents}')
		if offset != None:
			url_params.append(f'offset={offset}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if pageSize != None:
			url_params.append(f'pageSize={pageSize}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if startDate != None:
			url_params.append(f'startDate={startDate}')
		if statusFilter != None:
			url_params.append(f'statusFilter={statusFilter}')
		if timeFilter != None:
			url_params.append(f'timeFilter={timeFilter}')
		if typeFilter != None:
			url_params.append(f'typeFilter={typeFilter}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

class featuresrestapicontroller:
	'''Features Rest Api Controller'''

	def get_list_features(self) -> tuple[bool, list]:
		'''
		Class featuresrestapicontroller
		Description: This API call outputs a list of the features in the system..
        
		Args:

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("get_list_features", locals())

		url = '/api/features'
		return fortiedr_connection.get(url)

	def send_create_feature(self, enabled: bool, name: str, description: str = None, strategy: object = None) -> tuple[bool, None]:
		'''
		Class featuresrestapicontroller
		Description: This API create feature in the system..
        
		Args:
			item (Object): Check 'item' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("send_create_feature", locals())

		url = '/api/features'

		item = {}
		if description:
			item["description"] = f"{description}"
		if enabled:
			item["enabled"] = f"{enabled}"
		if name:
			item["name"] = f"{name}"
		if strategy:
			item["strategy"] = f"{strategy}"

		return fortiedr_connection.send(url, item)

	def features_state(self, organizationId: int, featureName: str = None) -> tuple[bool, None]:
		'''
		Class featuresrestapicontroller
		Description: This API retrieve feature state by account..
        
		Args:
			featureName (str): featureName
			organizationId (int): organizationId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("features_state", locals())

		url = '/api/features/features-state'
		url_params = []
		if featureName != None:
			url_params.append(f'featureName={featureName}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def features_url(self) -> tuple[bool, None]:
		'''
		Class featuresrestapicontroller
		Description: This API retrieve urls associated with feature..
        
		Args:

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("features_url", locals())

		url = '/api/features/features-url'
		return fortiedr_connection.get(url)

	def strategy_types(self) -> tuple[bool, None]:
		'''
		Class featuresrestapicontroller
		Description: Retrieves all strategy types that exist in this instance, along with their descriptions..
        
		Args:

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("strategy_types", locals())

		url = '/api/features/strategy-types'
		return fortiedr_connection.get(url)

	def get_get_feature(self, featureName: str) -> tuple[bool, None]:
		'''
		Class featuresrestapicontroller
		Description: This API call outputs a feature by feature name.
        
		Args:
			featureName (str): featureName

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_get_feature", locals())

		url = f'/api/features/{featureName}'
		return fortiedr_connection.get(url)

	def insert_update_feature(self, featureName: str, enabled: bool, name: str, description: str = None, strategy: object = None) -> tuple[bool, None]:
		'''
		Class featuresrestapicontroller
		Description: This API update feature in the system..
        
		Args:
			featureName (str): featureName
			item (Object): Check 'item' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("insert_update_feature", locals())

		url = f'/api/features/{featureName}'

		item = {}
		if description:
			item["description"] = f"{description}"
		if enabled:
			item["enabled"] = f"{enabled}"
		if name:
			item["name"] = f"{name}"
		if strategy:
			item["strategy"] = f"{strategy}"

		return fortiedr_connection.insert(url, item)

	def delete_delete_feature(self, featureName: str) -> tuple[bool, None]:
		'''
		Class featuresrestapicontroller
		Description: This API delete feature in the system..
        
		Args:
			featureName (str): featureName

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_delete_feature", locals())

		url = f'/api/features/{featureName}'
		return fortiedr_connection.delete(url)

	def insert_add_accounts(self, accountIds: list, featureName: str) -> tuple[bool, None]:
		'''
		Class featuresrestapicontroller
		Description: This API add accounts to feature.
        
		Args:
			accountIds (list): accountIds
			featureName (str): featureName

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("insert_add_accounts", locals())

		url = f'/api/features/{featureName}/accounts'


		return fortiedr_connection.insert(url, accountIds)

	def delete_remove_accounts(self, accountIds: list, featureName: str) -> tuple[bool, None]:
		'''
		Class featuresrestapicontroller
		Description: This API remove accounts to feature.
        
		Args:
			accountIds (list): accountIds
			featureName (str): featureName

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_remove_accounts", locals())

		url = f'/api/features/{featureName}/accounts'


		return fortiedr_connection.delete(url, accountIds)

	def disable_feature(self, featureName: str) -> tuple[bool, None]:
		'''
		Class featuresrestapicontroller
		Description: This API disable a feature flag..
        
		Args:
			featureName (str): featureName

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("disable_feature", locals())

		url = f'/api/features/{featureName}/off'
		return fortiedr_connection.insert(url)

	def enable_feature(self, featureName: str) -> tuple[bool, None]:
		'''
		Class featuresrestapicontroller
		Description: This API enable a feature flag..
        
		Args:
			featureName (str): featureName

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("enable_feature", locals())

		url = f'/api/features/{featureName}/on'
		return fortiedr_connection.insert(url)

	def insert_add_feature_parameters(self, featureName: str, parameters: list = None) -> tuple[bool, None]:
		'''
		Class featuresrestapicontroller
		Description: This API update feature with an additional parameters..
        
		Args:
			featureName (str): featureName
			item (Object): Check 'item' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("insert_add_feature_parameters", locals())

		url = f'/api/features/{featureName}/parameters'

		item = {}
		if parameters:
			item["parameters"] = f"{parameters}"

		return fortiedr_connection.insert(url, item)

	def delete_remove_feature_parameters(self, featureName: str, parameters: list = None) -> tuple[bool, None]:
		'''
		Class featuresrestapicontroller
		Description: This API removes parameters from feature..
        
		Args:
			featureName (str): featureName
			item (Object): Check 'item' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_remove_feature_parameters", locals())

		url = f'/api/features/{featureName}/parameters'

		item = {}
		if parameters:
			item["parameters"] = f"{parameters}"

		return fortiedr_connection.delete(url, item)

class forensicsrestapicontroller:
	'''Forensics Rest Api Controller'''

	def get_events(self, advancedFilters: str = None, endDate: int = None, eventIds: list = None, freeTextFilters: list = None, freeTextSearch: str = None, incidentIds: list = None, offset: int = None, organizationId: int = None, pageSize: int = None, selectedEventIds: list = None, sorting: str = None, startDate: int = None, statusFilter: str = None, timeFilter: str = None, typeFilter: str = None) -> tuple[bool, None]:
		'''
		Class forensicsrestapicontroller
		Description: Returns forensic events filtered according to the given request parameters.
        
		Args:
			forensicsEventsRequest (Object): Check 'forensicsEventsRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_events", locals())

		url = '/api/forensics/get-events'

		forensicsEventsRequest = {}
		if advancedFilters:
			forensicsEventsRequest["advancedFilters"] = f"{advancedFilters}"
		if endDate != None:
			forensicsEventsRequest["endDate"] = f"{endDate}"
		if eventIds:
			forensicsEventsRequest["eventIds"] = f"{eventIds}"
		if freeTextFilters:
			forensicsEventsRequest["freeTextFilters"] = f"{freeTextFilters}"
		if freeTextSearch:
			forensicsEventsRequest["freeTextSearch"] = f"{freeTextSearch}"
		if incidentIds:
			forensicsEventsRequest["incidentIds"] = f"{incidentIds}"
		if offset != None:
			forensicsEventsRequest["offset"] = f"{offset}"
		if organizationId != None:
			forensicsEventsRequest["organizationId"] = f"{organizationId}"
		if pageSize != None:
			forensicsEventsRequest["pageSize"] = f"{pageSize}"
		if selectedEventIds:
			forensicsEventsRequest["selectedEventIds"] = f"{selectedEventIds}"
		if sorting:
			forensicsEventsRequest["sorting"] = f"{sorting}"
		if startDate != None:
			forensicsEventsRequest["startDate"] = f"{startDate}"
		if statusFilter:
			forensicsEventsRequest["statusFilter"] = f"{statusFilter}"
		if timeFilter:
			forensicsEventsRequest["timeFilter"] = f"{timeFilter}"
		if typeFilter:
			forensicsEventsRequest["typeFilter"] = f"{typeFilter}"

		return fortiedr_connection.send(url, forensicsEventsRequest)

class Incidents:
	'''Incidents Rest Api Controller'''

	def get_incidents(self, advancedFilters: str = None, endDate: int = None, freeTextFilters: list = None, freeTextSearch: str = None, incidentIds: list = None, isAllIncidents: bool = None, offset: int = None, organizationId: int = None, pageSize: int = None, sorting: str = None, startDate: int = None, statusFilter: str = None, tags: list = None, tagsIds: list = None, timeFilter: str = None, typeFilter: str = None) -> tuple[bool, None]:
		'''
		Class Incidents
		Description: Get incidents.
        
		Args:
			advancedFilters (str): Specifies advanced filters
			endDate (int): Specifies the time filter end date
			freeTextFilters (list): Specifies the free text search filter
			freeTextSearch (str): Specifies the free text search
			incidentIds (list): Specifies the id's of the incidents
			isAllIncidents (bool): Specifies the all incidents under the filters/search criteria are selected
			offset (int): Specifies the page offset
			organizationId (int): Specifies the organization id
			pageSize (int): Specifies the page size
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on
			startDate (int): Specifies the time filter start date
			statusFilter (str): Specifies the incidents status filter
			tags (list): Specifies the tags
			tagsIds (list): Specifies the tags ids
			timeFilter (str): Specifies the incidents time filter
			typeFilter (str): Specifies the incidents type filter

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_incidents", locals())

		url = '/api/incidents'
		url_params = []
		if advancedFilters != None:
			url_params.append(f'advancedFilters={advancedFilters}')
		if endDate != None:
			url_params.append(f'endDate={endDate}')
		if freeTextFilters != None:
			freeTextFilters = ",".join(freeTextFilters) if isinstance(freeTextFilters, list) else freeTextFilters
			url_params.append(f'freeTextFilters={freeTextFilters}')
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if incidentIds != None:
			incidentIds = ",".join(map(str, incidentIds)) if isinstance(incidentIds, list) else incidentIds
			url_params.append(f'incidentIds={incidentIds}')
		if isAllIncidents != None:
			url_params.append(f'isAllIncidents={isAllIncidents}')
		if offset != None:
			url_params.append(f'offset={offset}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if pageSize != None:
			url_params.append(f'pageSize={pageSize}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if startDate != None:
			url_params.append(f'startDate={startDate}')
		if statusFilter != None:
			url_params.append(f'statusFilter={statusFilter}')
		if tags != None:
			tags = ",".join(tags) if isinstance(tags, list) else tags
			url_params.append(f'tags={tags}')
		if tagsIds != None:
			tagsIds = ",".join(map(str, tagsIds)) if isinstance(tagsIds, list) else tagsIds
			url_params.append(f'tagsIds={tagsIds}')
		if timeFilter != None:
			url_params.append(f'timeFilter={timeFilter}')
		if typeFilter != None:
			url_params.append(f'typeFilter={typeFilter}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def delete_incidents(self, advancedFilters: str = None, allSelectedEventsParentIds: list = None, endDate: int = None, eventIds: list = None, freeTextFilters: list = None, freeTextSearch: str = None, incidentIds: list = None, isAllIncidents: bool = None, offset: int = None, organizationId: int = None, pageSize: int = None, sorting: str = None, startDate: int = None, statusFilter: str = None, tags: list = None, tagsIds: list = None, timeFilter: str = None, typeFilter: str = None) -> tuple[bool, None]:
		'''
		Class Incidents
		Description: Delete incidents.
        
		Args:
			advancedFilters (str): Specifies advanced filters
			allSelectedEventsParentIds (list): Meaning all those incidents' events under the filters/search criteria are selected. Specifies the events parent incidents ids
			endDate (int): Specifies the time filter end date
			eventIds (list): Specifies the IDs of the events
			freeTextFilters (list): Specifies the free text search filter
			freeTextSearch (str): Specifies the free text search
			incidentIds (list): Specifies the id's of the incidents
			isAllIncidents (bool): Specifies the all incidents under the filters/search criteria are selected
			offset (int): Specifies the page offset
			organizationId (int): Specifies the organization id
			pageSize (int): Specifies the page size
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on
			startDate (int): Specifies the time filter start date
			statusFilter (str): Specifies the incidents status filter
			tags (list): Specifies the tags
			tagsIds (list): Specifies the tags ids
			timeFilter (str): Specifies the incidents time filter
			typeFilter (str): Specifies the incidents type filter

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_incidents", locals())

		url = '/api/incidents'
		url_params = []
		if advancedFilters != None:
			url_params.append(f'advancedFilters={advancedFilters}')
		if allSelectedEventsParentIds != None:
			allSelectedEventsParentIds = ",".join(map(str, allSelectedEventsParentIds)) if isinstance(allSelectedEventsParentIds, list) else allSelectedEventsParentIds
			url_params.append(f'allSelectedEventsParentIds={allSelectedEventsParentIds}')
		if endDate != None:
			url_params.append(f'endDate={endDate}')
		if eventIds != None:
			eventIds = ",".join(map(str, eventIds)) if isinstance(eventIds, list) else eventIds
			url_params.append(f'eventIds={eventIds}')
		if freeTextFilters != None:
			freeTextFilters = ",".join(freeTextFilters) if isinstance(freeTextFilters, list) else freeTextFilters
			url_params.append(f'freeTextFilters={freeTextFilters}')
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if incidentIds != None:
			incidentIds = ",".join(map(str, incidentIds)) if isinstance(incidentIds, list) else incidentIds
			url_params.append(f'incidentIds={incidentIds}')
		if isAllIncidents != None:
			url_params.append(f'isAllIncidents={isAllIncidents}')
		if offset != None:
			url_params.append(f'offset={offset}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if pageSize != None:
			url_params.append(f'pageSize={pageSize}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if startDate != None:
			url_params.append(f'startDate={startDate}')
		if statusFilter != None:
			url_params.append(f'statusFilter={statusFilter}')
		if tags != None:
			tags = ",".join(tags) if isinstance(tags, list) else tags
			url_params.append(f'tags={tags}')
		if tagsIds != None:
			tagsIds = ",".join(map(str, tagsIds)) if isinstance(tagsIds, list) else tagsIds
			url_params.append(f'tagsIds={tagsIds}')
		if timeFilter != None:
			url_params.append(f'timeFilter={timeFilter}')
		if typeFilter != None:
			url_params.append(f'typeFilter={typeFilter}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def update_user_assignment(self, advancedFilters: str = None, endDate: int = None, freeTextFilters: list = None, freeTextSearch: str = None, incidentIds: list = None, isAllIncidents: bool = None, offset: int = None, organizationId: int = None, pageSize: int = None, sorting: str = None, startDate: int = None, statusFilter: str = None, timeFilter: str = None, typeFilter: str = None, userId: int = None, userName: str = None) -> tuple[bool, None]:
		'''
		Class Incidents
		Description: update user assignment.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("update_user_assignment", locals())

		url = '/api/incidents/assign-user'

		request = {}
		if advancedFilters:
			request["advancedFilters"] = f"{advancedFilters}"
		if endDate != None:
			request["endDate"] = f"{endDate}"
		if freeTextFilters:
			request["freeTextFilters"] = f"{freeTextFilters}"
		if freeTextSearch:
			request["freeTextSearch"] = f"{freeTextSearch}"
		if incidentIds:
			request["incidentIds"] = f"{incidentIds}"
		if isAllIncidents:
			request["isAllIncidents"] = f"{isAllIncidents}"
		if offset != None:
			request["offset"] = f"{offset}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"
		if pageSize != None:
			request["pageSize"] = f"{pageSize}"
		if sorting:
			request["sorting"] = f"{sorting}"
		if startDate != None:
			request["startDate"] = f"{startDate}"
		if statusFilter:
			request["statusFilter"] = f"{statusFilter}"
		if timeFilter:
			request["timeFilter"] = f"{timeFilter}"
		if typeFilter:
			request["typeFilter"] = f"{typeFilter}"
		if userId != None:
			request["userId"] = f"{userId}"
		if userName:
			request["userName"] = f"{userName}"

		return fortiedr_connection.send(url, request)

	def events_handle(self, eventIds: list, classification: str = None, comment: str = None, handlingState: str = None, muteDurationTime: str = None, muteEnabled: bool = None) -> tuple[bool, None]:
		'''
		Class Incidents
		Description: Handle events.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("events_handle", locals())

		url = '/api/incidents/events/handle'

		request = {}
		if classification:
			request["classification"] = f"{classification}"
		if comment:
			request["comment"] = f"{comment}"
		if eventIds:
			request["eventIds"] = f"{eventIds}"
		if handlingState:
			request["handlingState"] = f"{handlingState}"
		if muteDurationTime:
			request["muteDurationTime"] = f"{muteDurationTime}"
		if muteEnabled:
			request["muteEnabled"] = f"{muteEnabled}"

		return fortiedr_connection.insert(url, request)

	def get_event_by_id(self, eventId: int) -> tuple[bool, None]:
		'''
		Class Incidents
		Description: Get event by id.
        
		Args:
			eventId (int): eventId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_event_by_id", locals())

		url = f'/api/incidents/events/{eventId}'
		return fortiedr_connection.get(url)

	def raw_events(self, eventId: int, advancedFilters: str = None, endDate: int = None, freeTextFilters: list = None, freeTextSearch: str = None, offset: int = None, organizationId: int = None, pageSize: int = None, sorting: str = None, startDate: int = None, statusFilter: str = None, timeFilter: str = None, typeFilter: str = None) -> tuple[bool, None]:
		'''
		Class Incidents
		Description: Get raw events.
        
		Args:
			advancedFilters (str): Specifies advanced filters
			endDate (int): Specifies the time filter end date
			eventId (int): eventId
			freeTextFilters (list): Specifies the free text search filter
			freeTextSearch (str): Specifies the free text search
			offset (int): Specifies the page offset
			organizationId (int): Specifies the organization id
			pageSize (int): Specifies the page size
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on
			startDate (int): Specifies the time filter start date
			statusFilter (str): Specifies the incidents status filter
			timeFilter (str): Specifies the incidents time filter
			typeFilter (str): Specifies the incidents type filter

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("raw_events", locals())

		url = f'/api/incidents/events/{eventId}/raw-events'
		url_params = []
		if advancedFilters != None:
			url_params.append(f'advancedFilters={advancedFilters}')
		if endDate != None:
			url_params.append(f'endDate={endDate}')
		if freeTextFilters != None:
			freeTextFilters = ",".join(freeTextFilters) if isinstance(freeTextFilters, list) else freeTextFilters
			url_params.append(f'freeTextFilters={freeTextFilters}')
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if offset != None:
			url_params.append(f'offset={offset}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if pageSize != None:
			url_params.append(f'pageSize={pageSize}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if startDate != None:
			url_params.append(f'startDate={startDate}')
		if statusFilter != None:
			url_params.append(f'statusFilter={statusFilter}')
		if timeFilter != None:
			url_params.append(f'timeFilter={timeFilter}')
		if typeFilter != None:
			url_params.append(f'typeFilter={typeFilter}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def incidents(self, advancedFilters: str = None, allSelectedEventsParentIds: list = None, endDate: int = None, eventIds: list = None, freeTextFilters: list = None, freeTextSearch: str = None, incidentIds: list = None, isAllIncidents: bool = None, offset: int = None, organizationId: int = None, pageSize: int = None, sorting: str = None, startDate: int = None, statusFilter: str = None, tags: list = None, tagsIds: list = None, timeFilter: str = None, typeFilter: str = None) -> tuple[bool, None]:
		'''
		Class Incidents
		Description: exports incidents.
        
		Args:
			reportRequest (Object): Check 'reportRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("incidents", locals())

		url = '/api/incidents/generate-report'

		reportRequest = {}
		if advancedFilters:
			reportRequest["advancedFilters"] = f"{advancedFilters}"
		if allSelectedEventsParentIds:
			reportRequest["allSelectedEventsParentIds"] = f"{allSelectedEventsParentIds}"
		if endDate != None:
			reportRequest["endDate"] = f"{endDate}"
		if eventIds:
			reportRequest["eventIds"] = f"{eventIds}"
		if freeTextFilters:
			reportRequest["freeTextFilters"] = f"{freeTextFilters}"
		if freeTextSearch:
			reportRequest["freeTextSearch"] = f"{freeTextSearch}"
		if incidentIds:
			reportRequest["incidentIds"] = f"{incidentIds}"
		if isAllIncidents:
			reportRequest["isAllIncidents"] = f"{isAllIncidents}"
		if offset != None:
			reportRequest["offset"] = f"{offset}"
		if organizationId != None:
			reportRequest["organizationId"] = f"{organizationId}"
		if pageSize != None:
			reportRequest["pageSize"] = f"{pageSize}"
		if sorting:
			reportRequest["sorting"] = f"{sorting}"
		if startDate != None:
			reportRequest["startDate"] = f"{startDate}"
		if statusFilter:
			reportRequest["statusFilter"] = f"{statusFilter}"
		if tags:
			reportRequest["tags"] = f"{tags}"
		if tagsIds:
			reportRequest["tagsIds"] = f"{tagsIds}"
		if timeFilter:
			reportRequest["timeFilter"] = f"{timeFilter}"
		if typeFilter:
			reportRequest["typeFilter"] = f"{typeFilter}"

		return fortiedr_connection.send(url, reportRequest)

	def incident_handle(self, classification: str = None, comment: str = None, eventIds: list = None, handlingState: str = None, incidentId: int = None, userId: int = None, userName: str = None) -> tuple[bool, None]:
		'''
		Class Incidents
		Description: Handle incidents.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("incident_handle", locals())

		url = '/api/incidents/incident-handle'

		request = {}
		if classification:
			request["classification"] = f"{classification}"
		if comment:
			request["comment"] = f"{comment}"
		if eventIds:
			request["eventIds"] = f"{eventIds}"
		if handlingState:
			request["handlingState"] = f"{handlingState}"
		if incidentId != None:
			request["incidentId"] = f"{incidentId}"
		if userId != None:
			request["userId"] = f"{userId}"
		if userName:
			request["userName"] = f"{userName}"

		return fortiedr_connection.insert(url, request)

	def update_modification_status(self, incidentId: int, modificationStatus: str) -> tuple[bool, None]:
		'''
		Class Incidents
		Description: update modification status.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("update_modification_status", locals())

		url = '/api/incidents/modification-status'

		request = {}
		if incidentId != None:
			request["incidentId"] = f"{incidentId}"
		if modificationStatus:
			request["modificationStatus"] = f"{modificationStatus}"

		return fortiedr_connection.send(url, request)

	def search_info(self, organizationId: int) -> tuple[bool, None]:
		'''
		Class Incidents
		Description: Get incidents search info.
        
		Args:
			organizationId (int): organizationId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("search_info", locals())

		url = '/api/incidents/search-info'


		return fortiedr_connection.get(url, organizationId)

	def get_get_tags(self, organizationId: int) -> tuple[bool, list]:
		'''
		Class Incidents
		Description: Return incident tags by organization.
        
		Args:
			organizationId (int): organizationId

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("get_get_tags", locals())

		url = '/api/incidents/tags'


		return fortiedr_connection.get(url, organizationId)

	def send_tag(self, tagName: str, organizationId: int = None, tagId: int = None) -> tuple[bool, None]:
		'''
		Class Incidents
		Description: Create incidents tag.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("send_tag", locals())

		url = '/api/incidents/tags'

		request = {}
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"
		if tagId != None:
			request["tagId"] = f"{tagId}"
		if tagName:
			request["tagName"] = f"{tagName}"

		return fortiedr_connection.send(url, request)

	def insert_tag(self, tagName: str, organizationId: int = None, tagId: int = None) -> tuple[bool, None]:
		'''
		Class Incidents
		Description: Update incidents tag name.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("insert_tag", locals())

		url = '/api/incidents/tags'

		request = {}
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"
		if tagId != None:
			request["tagId"] = f"{tagId}"
		if tagName:
			request["tagName"] = f"{tagName}"

		return fortiedr_connection.insert(url, request)

	def delete_tags(self, tagId: int) -> tuple[bool, None]:
		'''
		Class Incidents
		Description: Deletes incident tags.
        
		Args:
			tagId (int): tagId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_tags", locals())

		url = '/api/incidents/tags'


		return fortiedr_connection.delete(url, tagId)

	def get_incident_by_id(self, incidentId: int) -> tuple[bool, None]:
		'''
		Class Incidents
		Description: Get incident by id.
        
		Args:
			incidentId (int): incidentId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_incident_by_id", locals())

		url = f'/api/incidents/{incidentId}'
		return fortiedr_connection.get(url)

	def get_incident_audit_history(self, incidentId: int, eventIds: list = None) -> tuple[bool, list]:
		'''
		Class Incidents
		Description: get incident audit history.
        
		Args:
			eventIds (list): Specifies the IDs of the events
			incidentId (int): incidentId

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("get_incident_audit_history", locals())

		url = f'/api/incidents/{incidentId}/audit-history'
		url_params = []
		if eventIds != None:
			eventIds = ",".join(map(str, eventIds)) if isinstance(eventIds, list) else eventIds
			url_params.append(f'eventIds={eventIds}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def events(self, incidentId: int, advancedFilters: str = None, endDate: int = None, freeTextFilters: list = None, freeTextSearch: str = None, offset: int = None, organizationId: int = None, pageSize: int = None, sorting: str = None, startDate: int = None, statusFilter: str = None, timeFilter: str = None, typeFilter: str = None) -> tuple[bool, None]:
		'''
		Class Incidents
		Description: Get events.
        
		Args:
			advancedFilters (str): Specifies advanced filters
			endDate (int): Specifies the time filter end date
			freeTextFilters (list): Specifies the free text search filter
			freeTextSearch (str): Specifies the free text search
			incidentId (int): incidentId
			offset (int): Specifies the page offset
			organizationId (int): Specifies the organization id
			pageSize (int): Specifies the page size
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on
			startDate (int): Specifies the time filter start date
			statusFilter (str): Specifies the incidents status filter
			timeFilter (str): Specifies the incidents time filter
			typeFilter (str): Specifies the incidents type filter

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("events", locals())

		url = f'/api/incidents/{incidentId}/events'
		url_params = []
		if advancedFilters != None:
			url_params.append(f'advancedFilters={advancedFilters}')
		if endDate != None:
			url_params.append(f'endDate={endDate}')
		if freeTextFilters != None:
			freeTextFilters = ",".join(freeTextFilters) if isinstance(freeTextFilters, list) else freeTextFilters
			url_params.append(f'freeTextFilters={freeTextFilters}')
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if offset != None:
			url_params.append(f'offset={offset}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if pageSize != None:
			url_params.append(f'pageSize={pageSize}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if startDate != None:
			url_params.append(f'startDate={startDate}')
		if statusFilter != None:
			url_params.append(f'statusFilter={statusFilter}')
		if timeFilter != None:
			url_params.append(f'timeFilter={timeFilter}')
		if typeFilter != None:
			url_params.append(f'typeFilter={typeFilter}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def get_incident_related_policies(self, incidentId: int) -> tuple[bool, list]:
		'''
		Class Incidents
		Description: get incident related policies.
        
		Args:
			incidentId (int): incidentId

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("get_incident_related_policies", locals())

		url = f'/api/incidents/{incidentId}/policies'
		return fortiedr_connection.get(url)

	def get_incident_related_processes(self, incidentId: int) -> tuple[bool, list]:
		'''
		Class Incidents
		Description: get incident related processes.
        
		Args:
			incidentId (int): incidentId

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("get_incident_related_processes", locals())

		url = f'/api/incidents/{incidentId}/processes'
		return fortiedr_connection.get(url)

	def get_get_tags(self, incidentId: int) -> tuple[bool, list]:
		'''
		Class Incidents
		Description: Return incident's tags.
        
		Args:
			incidentId (int): incidentId

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("get_get_tags", locals())

		url = f'/api/incidents/{incidentId}/tags'
		return fortiedr_connection.get(url)

	def send_get_tags(self, incidentId: int, tagsIds: list) -> tuple[bool, None]:
		'''
		Class Incidents
		Description: Return incident's tags.
        
		Args:
			incidentId (int): incidentId
			tagsIds (list): Specifies the id's of the incidents

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("send_get_tags", locals())

		url = f'/api/incidents/{incidentId}/tags'
		url_params = []
		if tagsIds != None:
			tagsIds = ",".join(map(str, tagsIds)) if isinstance(tagsIds, list) else tagsIds
			url_params.append(f'tagsIds={tagsIds}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.send(url)

class collectorinventoryrestapicontroller:
	'''Collector Inventory Rest Api Controller'''

	def collectors(self, collectorGroups: list = None, collectorIds: list = None, collectorType: str = None, devices: list = None, freeTextSearch: str = None, groupIds: list = None, ips: list = None, lastSeenEnd: str = None, macAddresses: list = None, organizationId: int = None, os: list = None, osFamily: list = None, showExpired: bool = None, status: str = None, user: str = None, versions: list = None) -> tuple[bool, None]:
		'''
		Class collectorinventoryrestapicontroller
		Description: Delete collectors.
        
		Args:
			collectorGroups (list): Specifies the collector names
			collectorIds (list): Specifies the Collector IDs
			collectorType (str): The collector Type
			devices (list): Specifies the collector names
			freeTextSearch (str): pattern of requested collectors
			groupIds (list): Specifies the Collector group IDs
			ips (list): Specifies the collector IPs
			lastSeenEnd (str): Retrieves collectors that were last seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss
			macAddresses (list): Specifies the collector mac Addresses
			organizationId (int): Specifies the organization ID
			os (list): Specifies the list of specific operating systems. For example, Windows 7 Pro
			osFamily (list): Specifies the list of operating system families: Windows, Windows Server or OS X
			showExpired (bool): Specifies whether to include collectors which have been disconnected for more than 30 days (sequentially) and are marked as Expired
			status (str): Specifies the Collector status
			user (str): Specifies the user that was logged
			versions (list): Specifies the collector versions

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("collectors", locals())

		url = '/api/inventory/collectors'
		url_params = []
		if collectorGroups != None:
			collectorGroups = ",".join(collectorGroups) if isinstance(collectorGroups, list) else collectorGroups
			url_params.append(f'collectorGroups={collectorGroups}')
		if collectorIds != None:
			collectorIds = ",".join(map(str, collectorIds)) if isinstance(collectorIds, list) else collectorIds
			url_params.append(f'collectorIds={collectorIds}')
		if collectorType != None:
			url_params.append(f'collectorType={collectorType}')
		if devices != None:
			devices = ",".join(devices) if isinstance(devices, list) else devices
			url_params.append(f'devices={devices}')
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if groupIds != None:
			groupIds = ",".join(map(str, groupIds)) if isinstance(groupIds, list) else groupIds
			url_params.append(f'groupIds={groupIds}')
		if ips != None:
			ips = ",".join(ips) if isinstance(ips, list) else ips
			url_params.append(f'ips={ips}')
		if lastSeenEnd != None:
			url_params.append(f'lastSeenEnd={lastSeenEnd}')
		if macAddresses != None:
			macAddresses = ",".join(macAddresses) if isinstance(macAddresses, list) else macAddresses
			url_params.append(f'macAddresses={macAddresses}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if os != None:
			os = ",".join(os) if isinstance(os, list) else os
			url_params.append(f'os={os}')
		if osFamily != None:
			osFamily = ",".join(osFamily) if isinstance(osFamily, list) else osFamily
			url_params.append(f'osFamily={osFamily}')
		if showExpired != None:
			url_params.append(f'showExpired={showExpired}')
		if status != None:
			url_params.append(f'status={status}')
		if user != None:
			url_params.append(f'user={user}')
		if versions != None:
			versions = ",".join(versions) if isinstance(versions, list) else versions
			url_params.append(f'versions={versions}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def get_collectors_notification_info(self, organizationId: int) -> tuple[bool, None]:
		'''
		Class collectorinventoryrestapicontroller
		Description: get collectors notification info.
        
		Args:
			organizationId (int): organizationId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_collectors_notification_info", locals())

		url = '/api/inventory/collectors/advanced-search-info'
		url_params = []
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def get_collectors(self, collectorGroups: list = None, collectorIds: list = None, devices: list = None, freeTextSearch: str = None, groupIds: list = None, ips: list = None, lastSeenEnd: str = None, macAddresses: list = None, organizationId: int = None, os: list = None, osFamily: list = None, showExpired: bool = None, status: str = None, user: str = None, versions: list = None) -> tuple[bool, int]:
		'''
		Class collectorinventoryrestapicontroller
		Description: Return collectors.
        
		Args:
			collectorGroups (list): Specifies the collector names
			collectorIds (list): Specifies the Collector IDs
			devices (list): Specifies the collector names
			freeTextSearch (str): pattern of requested collectors
			groupIds (list): Specifies the Collector group IDs
			ips (list): Specifies the collector IPs
			lastSeenEnd (str): Retrieves collectors that were last seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss
			macAddresses (list): Specifies the collector mac Addresses
			organizationId (int): Specifies the organization ID
			os (list): Specifies the list of specific operating systems. For example, Windows 7 Pro
			osFamily (list): Specifies the list of operating system families: Windows, Windows Server or OS X
			showExpired (bool): Specifies whether to include collectors which have been disconnected for more than 30 days (sequentially) and are marked as Expired
			status (str): Specifies the Collector status
			user (str): Specifies the user that was logged
			versions (list): Specifies the collector versions

		Returns:
			bool: Status of the request (True or False). 
			int
		'''
		validate_params("get_collectors", locals())

		url = '/api/inventory/collectors/agent-count'
		url_params = []
		if collectorGroups != None:
			collectorGroups = ",".join(collectorGroups) if isinstance(collectorGroups, list) else collectorGroups
			url_params.append(f'collectorGroups={collectorGroups}')
		if collectorIds != None:
			collectorIds = ",".join(map(str, collectorIds)) if isinstance(collectorIds, list) else collectorIds
			url_params.append(f'collectorIds={collectorIds}')
		if devices != None:
			devices = ",".join(devices) if isinstance(devices, list) else devices
			url_params.append(f'devices={devices}')
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if groupIds != None:
			groupIds = ",".join(map(str, groupIds)) if isinstance(groupIds, list) else groupIds
			url_params.append(f'groupIds={groupIds}')
		if ips != None:
			ips = ",".join(ips) if isinstance(ips, list) else ips
			url_params.append(f'ips={ips}')
		if lastSeenEnd != None:
			url_params.append(f'lastSeenEnd={lastSeenEnd}')
		if macAddresses != None:
			macAddresses = ",".join(macAddresses) if isinstance(macAddresses, list) else macAddresses
			url_params.append(f'macAddresses={macAddresses}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if os != None:
			os = ",".join(os) if isinstance(os, list) else os
			url_params.append(f'os={os}')
		if osFamily != None:
			osFamily = ",".join(osFamily) if isinstance(osFamily, list) else osFamily
			url_params.append(f'osFamily={osFamily}')
		if showExpired != None:
			url_params.append(f'showExpired={showExpired}')
		if status != None:
			url_params.append(f'status={status}')
		if user != None:
			url_params.append(f'user={user}')
		if versions != None:
			versions = ",".join(versions) if isinstance(versions, list) else versions
			url_params.append(f'versions={versions}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def assign_agent_group(self, collectorGroups: list = None, collectorIds: list = None, collectorType: str = None, devices: list = None, freeTextSearch: str = None, ips: list = None, lastSeenEnd: str = None, macAddresses: list = None, organizationId: int = None, os: list = None, osFamily: list = None, showExpired: bool = None, sourceGroupIds: list = None, status: str = None, targetGroupId: int = None, user: str = None, versions: list = None) -> tuple[bool, None]:
		'''
		Class collectorinventoryrestapicontroller
		Description: assign agent group.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("assign_agent_group", locals())

		url = '/api/inventory/collectors/assign-agent-group'

		request = {}
		if collectorGroups:
			request["collectorGroups"] = f"{collectorGroups}"
		if collectorIds:
			request["collectorIds"] = f"{collectorIds}"
		if collectorType:
			request["collectorType"] = f"{collectorType}"
		if devices:
			request["devices"] = f"{devices}"
		if freeTextSearch:
			request["freeTextSearch"] = f"{freeTextSearch}"
		if ips:
			request["ips"] = f"{ips}"
		if lastSeenEnd:
			request["lastSeenEnd"] = f"{lastSeenEnd}"
		if macAddresses:
			request["macAddresses"] = f"{macAddresses}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"
		if os:
			request["os"] = f"{os}"
		if osFamily:
			request["osFamily"] = f"{osFamily}"
		if showExpired:
			request["showExpired"] = f"{showExpired}"
		if sourceGroupIds:
			request["sourceGroupIds"] = f"{sourceGroupIds}"
		if status:
			request["status"] = f"{status}"
		if targetGroupId != None:
			request["targetGroupId"] = f"{targetGroupId}"
		if user:
			request["user"] = f"{user}"
		if versions:
			request["versions"] = f"{versions}"

		return fortiedr_connection.insert(url, request)

	def create_group(self, name: str = None, organizationId: int = None) -> tuple[bool, None]:
		'''
		Class collectorinventoryrestapicontroller
		Description: Create a Collector group.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("create_group", locals())

		url = '/api/inventory/collectors/create-group'

		request = {}
		if name:
			request["name"] = f"{name}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"

		return fortiedr_connection.send(url, request)

	def generate_logs(self, collectorGroups: list = None, collectorIds: list = None, collectorType: str = None, devices: list = None, freeTextSearch: str = None, groupIds: list = None, ips: list = None, lastSeenEnd: str = None, macAddresses: list = None, organizationId: int = None, os: list = None, osFamily: list = None, showExpired: bool = None, sorting: str = None, status: str = None, type: str = None, user: str = None, versions: list = None) -> tuple[bool, None]:
		'''
		Class collectorinventoryrestapicontroller
		Description: generate logs.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("generate_logs", locals())

		url = '/api/inventory/collectors/generate-logs'

		request = {}
		if collectorGroups:
			request["collectorGroups"] = f"{collectorGroups}"
		if collectorIds:
			request["collectorIds"] = f"{collectorIds}"
		if collectorType:
			request["collectorType"] = f"{collectorType}"
		if devices:
			request["devices"] = f"{devices}"
		if freeTextSearch:
			request["freeTextSearch"] = f"{freeTextSearch}"
		if groupIds:
			request["groupIds"] = f"{groupIds}"
		if ips:
			request["ips"] = f"{ips}"
		if lastSeenEnd:
			request["lastSeenEnd"] = f"{lastSeenEnd}"
		if macAddresses:
			request["macAddresses"] = f"{macAddresses}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"
		if os:
			request["os"] = f"{os}"
		if osFamily:
			request["osFamily"] = f"{osFamily}"
		if showExpired:
			request["showExpired"] = f"{showExpired}"
		if sorting:
			request["sorting"] = f"{sorting}"
		if status:
			request["status"] = f"{status}"
		if type:
			request["type"] = f"{type}"
		if user:
			request["user"] = f"{user}"
		if versions:
			request["versions"] = f"{versions}"

		return fortiedr_connection.send(url, request)

	def generate_report(self, collectorGroups: list = None, collectorIds: list = None, collectorType: str = None, devices: list = None, freeTextSearch: str = None, groupIds: list = None, ips: list = None, lastSeenEnd: str = None, macAddresses: list = None, organizationId: int = None, os: list = None, osFamily: list = None, showExpired: bool = None, sorting: str = None, status: str = None, type: str = None, user: str = None, versions: list = None) -> tuple[bool, None]:
		'''
		Class collectorinventoryrestapicontroller
		Description: generate report.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("generate_report", locals())

		url = '/api/inventory/collectors/generate-report'

		request = {}
		if collectorGroups:
			request["collectorGroups"] = f"{collectorGroups}"
		if collectorIds:
			request["collectorIds"] = f"{collectorIds}"
		if collectorType:
			request["collectorType"] = f"{collectorType}"
		if devices:
			request["devices"] = f"{devices}"
		if freeTextSearch:
			request["freeTextSearch"] = f"{freeTextSearch}"
		if groupIds:
			request["groupIds"] = f"{groupIds}"
		if ips:
			request["ips"] = f"{ips}"
		if lastSeenEnd:
			request["lastSeenEnd"] = f"{lastSeenEnd}"
		if macAddresses:
			request["macAddresses"] = f"{macAddresses}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"
		if os:
			request["os"] = f"{os}"
		if osFamily:
			request["osFamily"] = f"{osFamily}"
		if showExpired:
			request["showExpired"] = f"{showExpired}"
		if sorting:
			request["sorting"] = f"{sorting}"
		if status:
			request["status"] = f"{status}"
		if type:
			request["type"] = f"{type}"
		if user:
			request["user"] = f"{user}"
		if versions:
			request["versions"] = f"{versions}"

		return fortiedr_connection.send(url, request)

	def get_get_groups(self, organization: str, collectorGroups: list = None, collectorType: str = None, devices: list = None, freeTextSearch: str = None, groupIds: list = None, ips: list = None, lastSeenEnd: str = None, macAddresses: list = None, offset: int = None, organizationId: int = None, os: list = None, osFamily: list = None, pageSize: int = None, showExpired: bool = None, sorting: str = None, status: str = None, user: str = None, versions: list = None) -> tuple[bool, None]:
		'''
		Class collectorinventoryrestapicontroller
		Description: Return collector groups.
        
		Args:
			collectorGroups (list): Specifies the collector group names
			collectorType (str): The collector Type
			devices (list): Specifies the collector names
			freeTextSearch (str): pattern of requested policies
			groupIds (list): Specifies the collector group IDs
			ips (list): Specifies the collector IPs
			lastSeenEnd (str): Retrieves collectors that were last seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss
			macAddresses (list): Specifies the collector mac Addresses
			offset (int): Specifies the page offset
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			organizationId (int): Specifies the organization ID
			os (list): Specifies the list of specific operating systems. For example, Windows 7 Pro
			osFamily (list): Specifies the list of operating system families: Windows, Windows Server or OS X
			pageSize (int): Specifies the page size
			showExpired (bool): Specifies whether to include collectors which have been disconnected for more than 30 days (sequentially) and are marked as Expired
			sorting (str): list of sorting fields (each is a map of <fieldName>:<descending order flag>. false=ascending, true=descending)
			status (str): Specifies the device status
			user (str): Specifies the user that was logged
			versions (list): Specifies the collector versions

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_get_groups", locals())

		url = '/api/inventory/collectors/groups'
		url_params = []
		if collectorGroups != None:
			collectorGroups = ",".join(collectorGroups) if isinstance(collectorGroups, list) else collectorGroups
			url_params.append(f'collectorGroups={collectorGroups}')
		if collectorType != None:
			url_params.append(f'collectorType={collectorType}')
		if devices != None:
			devices = ",".join(devices) if isinstance(devices, list) else devices
			url_params.append(f'devices={devices}')
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if groupIds != None:
			groupIds = ",".join(map(str, groupIds)) if isinstance(groupIds, list) else groupIds
			url_params.append(f'groupIds={groupIds}')
		if ips != None:
			ips = ",".join(ips) if isinstance(ips, list) else ips
			url_params.append(f'ips={ips}')
		if lastSeenEnd != None:
			url_params.append(f'lastSeenEnd={lastSeenEnd}')
		if macAddresses != None:
			macAddresses = ",".join(macAddresses) if isinstance(macAddresses, list) else macAddresses
			url_params.append(f'macAddresses={macAddresses}')
		if offset != None:
			url_params.append(f'offset={offset}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if os != None:
			os = ",".join(os) if isinstance(os, list) else os
			url_params.append(f'os={os}')
		if osFamily != None:
			osFamily = ",".join(osFamily) if isinstance(osFamily, list) else osFamily
			url_params.append(f'osFamily={osFamily}')
		if pageSize != None:
			url_params.append(f'pageSize={pageSize}')
		if showExpired != None:
			url_params.append(f'showExpired={showExpired}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if status != None:
			url_params.append(f'status={status}')
		if user != None:
			url_params.append(f'user={user}')
		if versions != None:
			versions = ",".join(versions) if isinstance(versions, list) else versions
			url_params.append(f'versions={versions}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def delete_collectors(self, collectorType: str = None, groupIds: list = None, organizationId: int = None) -> tuple[bool, None]:
		'''
		Class collectorinventoryrestapicontroller
		Description: Delete collector groups.
        
		Args:
			collectorType (str): The collector Type
			groupIds (list): Specifies the Collector group IDs
			organizationId (int): Specifies the organization ID

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_collectors", locals())

		url = '/api/inventory/collectors/groups'
		url_params = []
		if collectorType != None:
			url_params.append(f'collectorType={collectorType}')
		if groupIds != None:
			groupIds = ",".join(map(str, groupIds)) if isinstance(groupIds, list) else groupIds
			url_params.append(f'groupIds={groupIds}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def set_as_default_group(self, collectorGroupId: int = None, organizationId: int = None) -> tuple[bool, None]:
		'''
		Class collectorinventoryrestapicontroller
		Description: set as default group.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("set_as_default_group", locals())

		url = '/api/inventory/collectors/groups/set-default'

		request = {}
		if collectorGroupId != None:
			request["collectorGroupId"] = f"{collectorGroupId}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"

		return fortiedr_connection.send(url, request)

	def Isolate_collectors(self, applyAllGroups: bool = None, collectorGroups: list = None, collectorIds: list = None, devices: list = None, freeTextSearch: str = None, groupIds: list = None, ips: list = None, lastSeenEnd: str = None, macAddresses: list = None, organizationId: int = None, os: list = None, osFamily: list = None, showExpired: bool = None, status: str = None, user: str = None, versions: list = None) -> tuple[bool, None]:
		'''
		Class collectorinventoryrestapicontroller
		Description: Isolate collectors.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("Isolate_collectors", locals())

		url = '/api/inventory/collectors/isolate'

		request = {}
		if applyAllGroups:
			request["applyAllGroups"] = f"{applyAllGroups}"
		if collectorGroups:
			request["collectorGroups"] = f"{collectorGroups}"
		if collectorIds:
			request["collectorIds"] = f"{collectorIds}"
		if devices:
			request["devices"] = f"{devices}"
		if freeTextSearch:
			request["freeTextSearch"] = f"{freeTextSearch}"
		if groupIds:
			request["groupIds"] = f"{groupIds}"
		if ips:
			request["ips"] = f"{ips}"
		if lastSeenEnd:
			request["lastSeenEnd"] = f"{lastSeenEnd}"
		if macAddresses:
			request["macAddresses"] = f"{macAddresses}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"
		if os:
			request["os"] = f"{os}"
		if osFamily:
			request["osFamily"] = f"{osFamily}"
		if showExpired:
			request["showExpired"] = f"{showExpired}"
		if status:
			request["status"] = f"{status}"
		if user:
			request["user"] = f"{user}"
		if versions:
			request["versions"] = f"{versions}"

		return fortiedr_connection.insert(url, request)

	def get_collectors(self, organization: str, collectorType: str = None, devices: list = None, freeTextSearch: str = None, groupId: int = None, ips: list = None, lastSeenEnd: str = None, macAddresses: list = None, offset: int = None, organizationId: int = None, os: list = None, osFamily: list = None, pageSize: int = None, showExpired: bool = None, sorting: str = None, status: str = None, user: str = None, versions: list = None) -> tuple[bool, None]:
		'''
		Class collectorinventoryrestapicontroller
		Description: Return collectors.
        
		Args:
			collectorType (str): The collector Type
			devices (list): Specifies the collector names
			freeTextSearch (str): pattern of requested policies
			groupId (int): The group ID of the collector device
			ips (list): Specifies the collector IPs
			lastSeenEnd (str): Retrieves collectors that were last seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss
			macAddresses (list): Specifies the collector mac Addresses
			offset (int): Specifies the page offset
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			organizationId (int): Specifies the organization ID
			os (list): Specifies the list of specific operating systems. For example, Windows 7 Pro
			osFamily (list): Specifies the list of operating system families: Windows, Windows Server or OS X
			pageSize (int): Specifies the page size
			showExpired (bool): Specifies whether to include collectors which have been disconnected for more than 30 days (sequentially) and are marked as Expired
			sorting (str): list of sorting fields (each is a map of <fieldName>:<descending order flag>. false=ascending, true=descending)
			status (str): The status of the collector device
			user (str): Specifies the user that was logged
			versions (list): Specifies the collector versions

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_collectors", locals())

		url = '/api/inventory/collectors/list'
		url_params = []
		if collectorType != None:
			url_params.append(f'collectorType={collectorType}')
		if devices != None:
			devices = ",".join(devices) if isinstance(devices, list) else devices
			url_params.append(f'devices={devices}')
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if groupId != None:
			url_params.append(f'groupId={groupId}')
		if ips != None:
			ips = ",".join(ips) if isinstance(ips, list) else ips
			url_params.append(f'ips={ips}')
		if lastSeenEnd != None:
			url_params.append(f'lastSeenEnd={lastSeenEnd}')
		if macAddresses != None:
			macAddresses = ",".join(macAddresses) if isinstance(macAddresses, list) else macAddresses
			url_params.append(f'macAddresses={macAddresses}')
		if offset != None:
			url_params.append(f'offset={offset}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if os != None:
			os = ",".join(os) if isinstance(os, list) else os
			url_params.append(f'os={os}')
		if osFamily != None:
			osFamily = ",".join(osFamily) if isinstance(osFamily, list) else osFamily
			url_params.append(f'osFamily={osFamily}')
		if pageSize != None:
			url_params.append(f'pageSize={pageSize}')
		if showExpired != None:
			url_params.append(f'showExpired={showExpired}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if status != None:
			url_params.append(f'status={status}')
		if user != None:
			url_params.append(f'user={user}')
		if versions != None:
			versions = ",".join(versions) if isinstance(versions, list) else versions
			url_params.append(f'versions={versions}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def get_collectors(self, collectorIds: list = None, groupIds: list = None, organizationId: int = None) -> tuple[bool, None]:
		'''
		Class collectorinventoryrestapicontroller
		Description: Return collectors.
        
		Args:
			collectorIds (list): Specifies the Collector IDs
			groupIds (list): Specifies the Collector group IDs
			organizationId (int): Specifies the organization ID

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_collectors", locals())

		url = '/api/inventory/collectors/move-collector-info'
		url_params = []
		if collectorIds != None:
			collectorIds = ",".join(map(str, collectorIds)) if isinstance(collectorIds, list) else collectorIds
			url_params.append(f'collectorIds={collectorIds}')
		if groupIds != None:
			groupIds = ",".join(map(str, groupIds)) if isinstance(groupIds, list) else groupIds
			url_params.append(f'groupIds={groupIds}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def get_collectors_notification_info(self, organizationId: int) -> tuple[bool, None]:
		'''
		Class collectorinventoryrestapicontroller
		Description: get collectors notification info.
        
		Args:
			organizationId (int): organizationId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_collectors_notification_info", locals())

		url = '/api/inventory/collectors/notification-info'
		url_params = []
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def Collectors_Search_options_auto_complete(self, accountId: int = None, allAccounts: bool = None, field: str = None, search: str = None) -> tuple[bool, list]:
		'''
		Class collectorinventoryrestapicontroller
		Description: Collectors Search options auto complete.
        
		Args:
			accountId (int): Specifies the account id
			allAccounts (bool): Specifies if need to check on all accounts
			field (str): Specifies the field to which need to search
			search (str): Specifies the text to search

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("Collectors_Search_options_auto_complete", locals())

		url = '/api/inventory/collectors/search-options-auto-complete'
		url_params = []
		if accountId != None:
			url_params.append(f'accountId={accountId}')
		if allAccounts != None:
			url_params.append(f'allAccounts={allAccounts}')
		if field != None:
			url_params.append(f'field={field}')
		if search != None:
			url_params.append(f'search={search}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def State(self, applyAllGroups: bool = None, collectorGroups: list = None, collectorIds: list = None, collectorType: str = None, devices: list = None, enabled: bool = None, freeTextSearch: str = None, groupIds: list = None, ips: list = None, lastSeenEnd: str = None, macAddresses: list = None, organizationId: int = None, os: list = None, osFamily: list = None, showExpired: bool = None, status: str = None, user: str = None, versions: list = None) -> tuple[bool, None]:
		'''
		Class collectorinventoryrestapicontroller
		Description: Update Collectors state.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("State", locals())

		url = '/api/inventory/collectors/state'

		request = {}
		if applyAllGroups:
			request["applyAllGroups"] = f"{applyAllGroups}"
		if collectorGroups:
			request["collectorGroups"] = f"{collectorGroups}"
		if collectorIds:
			request["collectorIds"] = f"{collectorIds}"
		if collectorType:
			request["collectorType"] = f"{collectorType}"
		if devices:
			request["devices"] = f"{devices}"
		if enabled:
			request["enabled"] = f"{enabled}"
		if freeTextSearch:
			request["freeTextSearch"] = f"{freeTextSearch}"
		if groupIds:
			request["groupIds"] = f"{groupIds}"
		if ips:
			request["ips"] = f"{ips}"
		if lastSeenEnd:
			request["lastSeenEnd"] = f"{lastSeenEnd}"
		if macAddresses:
			request["macAddresses"] = f"{macAddresses}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"
		if os:
			request["os"] = f"{os}"
		if osFamily:
			request["osFamily"] = f"{osFamily}"
		if showExpired:
			request["showExpired"] = f"{showExpired}"
		if status:
			request["status"] = f"{status}"
		if user:
			request["user"] = f"{user}"
		if versions:
			request["versions"] = f"{versions}"

		return fortiedr_connection.insert(url, request)

	def Uninstall(self, applyAllGroups: bool = None, collectorGroups: list = None, collectorIds: list = None, devices: list = None, freeTextSearch: str = None, groupIds: list = None, ips: list = None, lastSeenEnd: str = None, macAddresses: list = None, organizationId: int = None, os: list = None, osFamily: list = None, showExpired: bool = None, status: str = None, user: str = None, versions: list = None) -> tuple[bool, None]:
		'''
		Class collectorinventoryrestapicontroller
		Description: Uninstall collectors.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("Uninstall", locals())

		url = '/api/inventory/collectors/uninstall'

		request = {}
		if applyAllGroups:
			request["applyAllGroups"] = f"{applyAllGroups}"
		if collectorGroups:
			request["collectorGroups"] = f"{collectorGroups}"
		if collectorIds:
			request["collectorIds"] = f"{collectorIds}"
		if devices:
			request["devices"] = f"{devices}"
		if freeTextSearch:
			request["freeTextSearch"] = f"{freeTextSearch}"
		if groupIds:
			request["groupIds"] = f"{groupIds}"
		if ips:
			request["ips"] = f"{ips}"
		if lastSeenEnd:
			request["lastSeenEnd"] = f"{lastSeenEnd}"
		if macAddresses:
			request["macAddresses"] = f"{macAddresses}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"
		if os:
			request["os"] = f"{os}"
		if osFamily:
			request["osFamily"] = f"{osFamily}"
		if showExpired:
			request["showExpired"] = f"{showExpired}"
		if status:
			request["status"] = f"{status}"
		if user:
			request["user"] = f"{user}"
		if versions:
			request["versions"] = f"{versions}"

		return fortiedr_connection.send(url, request)

	def Unisolate_collectors(self, applyAllGroups: bool = None, collectorGroups: list = None, collectorIds: list = None, devices: list = None, freeTextSearch: str = None, groupIds: list = None, ips: list = None, lastSeenEnd: str = None, macAddresses: list = None, organizationId: int = None, os: list = None, osFamily: list = None, showExpired: bool = None, status: str = None, user: str = None, versions: list = None) -> tuple[bool, None]:
		'''
		Class collectorinventoryrestapicontroller
		Description: Unisolate collectors.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("Unisolate_collectors", locals())

		url = '/api/inventory/collectors/unisolate'

		request = {}
		if applyAllGroups:
			request["applyAllGroups"] = f"{applyAllGroups}"
		if collectorGroups:
			request["collectorGroups"] = f"{collectorGroups}"
		if collectorIds:
			request["collectorIds"] = f"{collectorIds}"
		if devices:
			request["devices"] = f"{devices}"
		if freeTextSearch:
			request["freeTextSearch"] = f"{freeTextSearch}"
		if groupIds:
			request["groupIds"] = f"{groupIds}"
		if ips:
			request["ips"] = f"{ips}"
		if lastSeenEnd:
			request["lastSeenEnd"] = f"{lastSeenEnd}"
		if macAddresses:
			request["macAddresses"] = f"{macAddresses}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"
		if os:
			request["os"] = f"{os}"
		if osFamily:
			request["osFamily"] = f"{osFamily}"
		if showExpired:
			request["showExpired"] = f"{showExpired}"
		if status:
			request["status"] = f"{status}"
		if user:
			request["user"] = f"{user}"
		if versions:
			request["versions"] = f"{versions}"

		return fortiedr_connection.insert(url, request)

	def unmanaged_devices(self, deviceIds: list = None, freeTextSearch: str = None, organizationId: int = None) -> tuple[bool, None]:
		'''
		Class collectorinventoryrestapicontroller
		Description: unmanaged devices.
        
		Args:
			deviceIds (list): Specifies the Collector IDs
			freeTextSearch (str): pattern of requested collectors
			organizationId (int): Specifies the organization ID

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("unmanaged_devices", locals())

		url = '/api/inventory/collectors/unmanaged-devices'
		url_params = []
		if deviceIds != None:
			deviceIds = ",".join(map(str, deviceIds)) if isinstance(deviceIds, list) else deviceIds
			url_params.append(f'deviceIds={deviceIds}')
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

class mobileinventoryrestapicontroller:
	'''Mobile Inventory Rest Api Controller'''

	def create_group(self, name: str = None, organizationId: int = None) -> tuple[bool, None]:
		'''
		Class mobileinventoryrestapicontroller
		Description: Create a Mobile group.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("create_group", locals())

		url = '/api/inventory/mobile/create-group'

		request = {}
		if name:
			request["name"] = f"{name}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"

		return fortiedr_connection.send(url, request)

	def Delete(self, allDevicesUnderGroupIds: list = None, deleteAll: bool = None, deviceIds: list = None, freeTextSearch: str = None, groupIds: list = None, organizationId: int = None, status: str = None) -> tuple[bool, None]:
		'''
		Class mobileinventoryrestapicontroller
		Description: Delete.
        
		Args:
			allDevicesUnderGroupIds (list): Delete all the devices under the group ids
			deleteAll (bool): Specifies delete all groups and devices
			deviceIds (list): Specifies the device ids
			freeTextSearch (str): pattern of requested text
			groupIds (list): Specifies the group ids
			organizationId (int): Specifies the organization id
			status (str): Specifies the device status

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("Delete", locals())

		url = '/api/inventory/mobile/delete'
		url_params = []
		if allDevicesUnderGroupIds != None:
			allDevicesUnderGroupIds = ",".join(map(str, allDevicesUnderGroupIds)) if isinstance(allDevicesUnderGroupIds, list) else allDevicesUnderGroupIds
			url_params.append(f'allDevicesUnderGroupIds={allDevicesUnderGroupIds}')
		if deleteAll != None:
			url_params.append(f'deleteAll={deleteAll}')
		if deviceIds != None:
			deviceIds = ",".join(map(str, deviceIds)) if isinstance(deviceIds, list) else deviceIds
			url_params.append(f'deviceIds={deviceIds}')
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if groupIds != None:
			groupIds = ",".join(map(str, groupIds)) if isinstance(groupIds, list) else groupIds
			url_params.append(f'groupIds={groupIds}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if status != None:
			url_params.append(f'status={status}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def devices_count_per_group(self, groupIds: list = None, organizationId: int = None) -> tuple[bool, None]:
		'''
		Class mobileinventoryrestapicontroller
		Description: devices count per group.
        
		Args:
			groupIds (list): Specifies the group ids
			organizationId (int): Specifies the organization id

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("devices_count_per_group", locals())

		url = '/api/inventory/mobile/devices-count-per-group'
		url_params = []
		if groupIds != None:
			groupIds = ",".join(map(str, groupIds)) if isinstance(groupIds, list) else groupIds
			url_params.append(f'groupIds={groupIds}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def get_groups(self, freeTextSearch: str = None, offset: int = None, organizationId: int = None, pageSize: int = None, sorting: str = None, status: str = None) -> tuple[bool, None]:
		'''
		Class mobileinventoryrestapicontroller
		Description: Return mobile groups.
        
		Args:
			freeTextSearch (str): pattern of requested text
			offset (int): Specifies the page offset
			organizationId (int): Specifies the organization id
			pageSize (int): Specifies the page size
			sorting (str): list of sorting fields (each is a map of <fieldName>:<descending order flag>. false=ascending, true=descending)
			status (str): Specifies the device status

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_groups", locals())

		url = '/api/inventory/mobile/groups'
		url_params = []
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if offset != None:
			url_params.append(f'offset={offset}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if pageSize != None:
			url_params.append(f'pageSize={pageSize}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if status != None:
			url_params.append(f'status={status}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def get_devices(self, freeTextSearch: str = None, groupId: int = None, offset: int = None, organizationId: int = None, pageSize: int = None, sorting: str = None, status: str = None) -> tuple[bool, None]:
		'''
		Class mobileinventoryrestapicontroller
		Description: Return mobile devices.
        
		Args:
			freeTextSearch (str): pattern of requested text
			groupId (int): Specifies the device group id
			offset (int): Specifies the page offset
			organizationId (int): Specifies the organization id
			pageSize (int): Specifies the page size
			sorting (str): list of sorting fields (each is a map of <fieldName>:<descending order flag>. false=ascending, true=descending)
			status (str): Specifies device status

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_devices", locals())

		url = '/api/inventory/mobile/list'
		url_params = []
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if groupId != None:
			url_params.append(f'groupId={groupId}')
		if offset != None:
			url_params.append(f'offset={offset}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if pageSize != None:
			url_params.append(f'pageSize={pageSize}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if status != None:
			url_params.append(f'status={status}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def move_group(self, deviceIds: list = None, organizationId: int = None, srcGroupIds: list = None, targetGroupId: int = None) -> tuple[bool, None]:
		'''
		Class mobileinventoryrestapicontroller
		Description: Move a Mobile group.
        
		Args:
			mobileMoveGroupRequest (Object): Check 'mobileMoveGroupRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("move_group", locals())

		url = '/api/inventory/mobile/move-group'

		mobileMoveGroupRequest = {}
		if deviceIds:
			mobileMoveGroupRequest["deviceIds"] = f"{deviceIds}"
		if organizationId != None:
			mobileMoveGroupRequest["organizationId"] = f"{organizationId}"
		if srcGroupIds:
			mobileMoveGroupRequest["srcGroupIds"] = f"{srcGroupIds}"
		if targetGroupId != None:
			mobileMoveGroupRequest["targetGroupId"] = f"{targetGroupId}"

		return fortiedr_connection.insert(url, mobileMoveGroupRequest)

class workloadslistrestapicontroller:
	'''Workloads List Rest Api Controller'''

	def workloads_filters(self, organizationId: int) -> tuple[bool, None]:
		'''
		Class workloadslistrestapicontroller
		Description: workloads filters.
        
		Args:
			organizationId (int): organizationId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("workloads_filters", locals())

		url = '/api/inventory/workloads/filters'


		return fortiedr_connection.get(url, organizationId)

	def workloads_list(self, accounts: list = None, cloudProviders: list = None, clusters: list = None, forceUpdate: bool = None, maxResult: int = None, namespaces: list = None, organizationId: int = None, page: int = None, search: str = None) -> tuple[bool, None]:
		'''
		Class workloadslistrestapicontroller
		Description: workloads list.
        
		Args:
			accounts (list): Specifies the account list
			cloudProviders (list): Specifies the cloud providers list
			clusters (list): Specifies the clusters list
			forceUpdate (bool): Specifies if force update
			maxResult (int): Specifies the page size
			namespaces (list): Specifies the namespaces list
			organizationId (int): Specifies the organization ID
			page (int): Specifies the page offset
			search (str): pattern of requested text

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("workloads_list", locals())

		url = '/api/inventory/workloads/list'
		url_params = []
		if accounts != None:
			accounts = ",".join(map(str, accounts)) if isinstance(accounts, list) else accounts
			url_params.append(f'accounts={accounts}')
		if cloudProviders != None:
			cloudProviders = ",".join(map(str, cloudProviders)) if isinstance(cloudProviders, list) else cloudProviders
			url_params.append(f'cloudProviders={cloudProviders}')
		if clusters != None:
			clusters = ",".join(map(str, clusters)) if isinstance(clusters, list) else clusters
			url_params.append(f'clusters={clusters}')
		if forceUpdate != None:
			url_params.append(f'forceUpdate={forceUpdate}')
		if maxResult != None:
			url_params.append(f'maxResult={maxResult}')
		if namespaces != None:
			namespaces = ",".join(map(str, namespaces)) if isinstance(namespaces, list) else namespaces
			url_params.append(f'namespaces={namespaces}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if page != None:
			url_params.append(f'page={page}')
		if search != None:
			url_params.append(f'search={search}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

class notifications:
	'''Notification Controller'''

	def handle(self, createdBy: str = None, createdTime: int = None, id: str = None, status: str = None, title: str = None, type: str = None) -> tuple[bool, None]:
		'''
		Class notifications
		Description: This API handles notifications created by the notification service.
        
		Args:
			notification (Object): Check 'notification' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("handle", locals())

		url = '/api/notifications/handle'

		notification = {}
		if createdBy:
			notification["createdBy"] = f"{createdBy}"
		if createdTime != None:
			notification["createdTime"] = f"{createdTime}"
		if id:
			notification["id"] = f"{id}"
		if status:
			notification["status"] = f"{status}"
		if title:
			notification["title"] = f"{title}"
		if type:
			notification["type"] = f"{type}"

		return fortiedr_connection.send(url, notification)

	def notifications(self, isSeen: bool, userId: str) -> tuple[bool, str]:
		'''
		Class notifications
		Description: This API get notifications from notification service.
        
		Args:
			isSeen (bool): isSeen
			userId (str): userId

		Returns:
			bool: Status of the request (True or False). 
			str
		'''
		validate_params("notifications", locals())

		url = '/api/notifications/notifications'
		url_params = []
		if isSeen != None:
			url_params.append(f'isSeen={isSeen}')
		if userId != None:
			url_params.append(f'userId={userId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def notifications(self, message: object = None, topic: str = None) -> tuple[bool, None]:
		'''
		Class notifications
		Description: health method to emulate of action-->manager-->notification service-->db-->manager-->ui.
        
		Args:
			notificationServiceHealthRequest (Object): Check 'notificationServiceHealthRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("notifications", locals())

		url = '/api/notifications/push'

		notificationServiceHealthRequest = {}
		if message:
			notificationServiceHealthRequest["message"] = f"{message}"
		if topic:
			notificationServiceHealthRequest["topic"] = f"{topic}"

		return fortiedr_connection.send(url, notificationServiceHealthRequest)

class policiesrestapicontroller:
	'''Policies Rest Api Controller'''

	def Search_options_auto_complete(self, accountId: int = None, allAccounts: bool = None, field: str = None, search: str = None) -> tuple[bool, list]:
		'''
		Class policiesrestapicontroller
		Description: Search options auto complete.
        
		Args:
			accountId (int): Specifies the account id
			allAccounts (bool): Specifies if need to check on all accounts
			field (str): Specifies the field to which need to search
			search (str): Specifies the text to search

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("Search_options_auto_complete", locals())

		url = '/api/policies/search-options-auto-complete'
		url_params = []
		if accountId != None:
			url_params.append(f'accountId={accountId}')
		if allAccounts != None:
			url_params.append(f'allAccounts={allAccounts}')
		if field != None:
			url_params.append(f'field={field}')
		if search != None:
			url_params.append(f'search={search}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

class Reputation:
	'''Reputation Rest Api Controller'''

	def get_regions(self, organizationId: int) -> tuple[bool, None]:
		'''
		Class Reputation
		Description: retrieves reputation region entity.
        
		Args:
			organizationId (int): organizationId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_regions", locals())

		url = '/api/reputation/regions'
		url_params = []
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def insert_regions(self, organizationId: int, regionIds: list) -> tuple[bool, None]:
		'''
		Class Reputation
		Description: select regions for specific organization.
        
		Args:
			organizationId (int): organizationId
			regionIds (list): regionIds

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("insert_regions", locals())

		url = '/api/reputation/regions'
		url_params = []
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		url += '?' + '&'.join(url_params)


		return fortiedr_connection.insert(url, regionIds)

	def reputationdb(self, organizationId: int) -> tuple[bool, None]:
		'''
		Class Reputation
		Description: retrieves reputation db entity.
        
		Args:
			organizationId (int): organizationId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("reputationdb", locals())

		url = '/api/reputation/reputationdb'
		url_params = []
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

class securebrowserservicerestapicontroller:
	'''Secure Browser Service Rest Api Controller'''

	def delete_policies(self, organization: str, deleteAll: bool = None, freeTextSearch: str = None, idToDelete: list = None, requirePolicyAssociation: bool = None) -> tuple[bool, None]:
		'''
		Class securebrowserservicerestapicontroller
		Description: Delete secure browser policies.
        
		Args:
			deleteAll (bool): Indicate if should delete all matching results (rather than only the selected) 
			freeTextSearch (str): pattern of policies to delete
			idToDelete (list): Id's of entities to delete
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			requirePolicyAssociation (bool): require policy association

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_policies", locals())

		url = '/api/secure-browser-service/policies'
		url_params = []
		if deleteAll != None:
			url_params.append(f'deleteAll={deleteAll}')
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if idToDelete != None:
			idToDelete = ",".join(map(str, idToDelete)) if isinstance(idToDelete, list) else idToDelete
			url_params.append(f'idToDelete={idToDelete}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if requirePolicyAssociation != None:
			url_params.append(f'requirePolicyAssociation={requirePolicyAssociation}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def send_policy(self, mode: bool, name: str, organization: str, forceGroupsAssign: bool = None, groupsIds: list = None, id: int = None, updatedBy: str = None) -> tuple[bool, None]:
		'''
		Class securebrowserservicerestapicontroller
		Description: Create a secure browser policy.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("send_policy", locals())

		url = '/api/secure-browser-service/policy'

		request = {}
		if forceGroupsAssign:
			request["forceGroupsAssign"] = f"{forceGroupsAssign}"
		if groupsIds:
			request["groupsIds"] = f"{groupsIds}"
		if id != None:
			request["id"] = f"{id}"
		if mode:
			request["mode"] = f"{mode}"
		if name:
			request["name"] = f"{name}"
		if organization:
			request["organization"] = f"{organization}"
		if updatedBy:
			request["updatedBy"] = f"{updatedBy}"

		return fortiedr_connection.send(url, request)

	def insert_policy(self, id: int, organization: str, forceGroupsAssign: bool = None, groupsIds: list = None, mode: bool = None, name: str = None, updatedBy: str = None) -> tuple[bool, None]:
		'''
		Class securebrowserservicerestapicontroller
		Description: edit a secure browser policy.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("insert_policy", locals())

		url = '/api/secure-browser-service/policy'

		request = {}
		if forceGroupsAssign:
			request["forceGroupsAssign"] = f"{forceGroupsAssign}"
		if groupsIds:
			request["groupsIds"] = f"{groupsIds}"
		if id != None:
			request["id"] = f"{id}"
		if mode:
			request["mode"] = f"{mode}"
		if name:
			request["name"] = f"{name}"
		if organization:
			request["organization"] = f"{organization}"
		if updatedBy:
			request["updatedBy"] = f"{updatedBy}"

		return fortiedr_connection.insert(url, request)

class securebrowserrestapicontroller:
	'''Secure Browser Rest Api Controller'''

	def clone_policy(self, name: str, organizationId: int, sourcePolicyId: int) -> tuple[bool, None]:
		'''
		Class securebrowserrestapicontroller
		Description: clone secure browser policy.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("clone_policy", locals())

		url = '/api/secure-browser/clone-policy'

		request = {}
		if name:
			request["name"] = f"{name}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"
		if sourcePolicyId != None:
			request["sourcePolicyId"] = f"{sourcePolicyId}"

		return fortiedr_connection.send(url, request)

	def get_get_domain_groups(self, freeTextSearch: str = None, offset: int = None, organizationId: int = None, pageSize: int = None, sorting: str = None) -> tuple[bool, None]:
		'''
		Class securebrowserrestapicontroller
		Description: Return all secure browser domain groups.
        
		Args:
			freeTextSearch (str): pattern of requested text
			offset (int): Specifies the page offset
			organizationId (int): Specifies the organization id
			pageSize (int): Specifies the page size
			sorting (str): list of sorting fields (each is a map of <fieldName>:<descending order flag>. false=ascending, true=descending)

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_get_domain_groups", locals())

		url = '/api/secure-browser/domain-groups'
		url_params = []
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if offset != None:
			url_params.append(f'offset={offset}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if pageSize != None:
			url_params.append(f'pageSize={pageSize}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def send_create_domain_groups(self, description: str = None, domains: list = None, id: int = None, name: str = None, organizationId: int = None, updatedBy: str = None) -> tuple[bool, None]:
		'''
		Class securebrowserrestapicontroller
		Description: create domain groups.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("send_create_domain_groups", locals())

		url = '/api/secure-browser/domain-groups'

		request = {}
		if description:
			request["description"] = f"{description}"
		if domains:
			request["domains"] = f"{domains}"
		if id != None:
			request["id"] = f"{id}"
		if name:
			request["name"] = f"{name}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"
		if updatedBy:
			request["updatedBy"] = f"{updatedBy}"

		return fortiedr_connection.send(url, request)

	def delete_delete_domain_groups(self, deleteAll: bool = None, freeTextSearch: str = None, idsToDelete: list = None, offset: int = None, organizationId: int = None, pageSize: int = None, sorting: str = None, updatedBy: str = None) -> tuple[bool, None]:
		'''
		Class securebrowserrestapicontroller
		Description: Delete domain groups.
        
		Args:
			deleteAll (bool): Indicate if should delete all matching results (rather than only the selected) 
			freeTextSearch (str): pattern of policies to delete
			idsToDelete (list): Id's of entities to delete
			offset (int): Specifies the page offset
			organizationId (int): organization id
			pageSize (int): Specifies the page size
			sorting (str): list of sorting fields (each is a map of <fieldName>:<descending order flag>. false=ascending, true=descending)
			updatedBy (str): specifies the user who updated the policy

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_delete_domain_groups", locals())

		url = '/api/secure-browser/domain-groups'
		url_params = []
		if deleteAll != None:
			url_params.append(f'deleteAll={deleteAll}')
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if idsToDelete != None:
			idsToDelete = ",".join(map(str, idsToDelete)) if isinstance(idsToDelete, list) else idsToDelete
			url_params.append(f'idsToDelete={idsToDelete}')
		if offset != None:
			url_params.append(f'offset={offset}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if pageSize != None:
			url_params.append(f'pageSize={pageSize}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if updatedBy != None:
			url_params.append(f'updatedBy={updatedBy}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def update_domain_group(self, id: int, description: str = None, domains: list = None, name: str = None, organizationId: int = None, updatedBy: str = None) -> tuple[bool, None]:
		'''
		Class securebrowserrestapicontroller
		Description: update domain group.
        
		Args:
			id (int): id
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("update_domain_group", locals())

		url = f'/api/secure-browser/domain-groups/{id}'

		request = {}
		if description:
			request["description"] = f"{description}"
		if domains:
			request["domains"] = f"{domains}"
		if id != None:
			request["id"] = f"{id}"
		if name:
			request["name"] = f"{name}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"
		if updatedBy:
			request["updatedBy"] = f"{updatedBy}"

		return fortiedr_connection.insert(url, request)

	def get_get_events(self, advancedFilters: str = None, endDate: int = None, freeTextSearch: str = None, offset: int = None, organizationId: int = None, pageSize: int = None, sorting: str = None, startDate: int = None, timeFilter: str = None) -> tuple[bool, None]:
		'''
		Class securebrowserrestapicontroller
		Description: Return all secure browser events.
        
		Args:
			advancedFilters (str): Specifies advanced filters
			endDate (int): Specifies the time filter end date
			freeTextSearch (str): pattern of requested text
			offset (int): Specifies the page offset
			organizationId (int): Specifies the organization id
			pageSize (int): Specifies the page size
			sorting (str): list of sorting fields (each is a map of <fieldName>:<descending order flag>. false=ascending, true=descending)
			startDate (int): Specifies the time filter start date
			timeFilter (str): Specifies the incidents time filter

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_get_events", locals())

		url = '/api/secure-browser/events'
		url_params = []
		if advancedFilters != None:
			url_params.append(f'advancedFilters={advancedFilters}')
		if endDate != None:
			url_params.append(f'endDate={endDate}')
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if offset != None:
			url_params.append(f'offset={offset}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if pageSize != None:
			url_params.append(f'pageSize={pageSize}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if startDate != None:
			url_params.append(f'startDate={startDate}')
		if timeFilter != None:
			url_params.append(f'timeFilter={timeFilter}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def delete_delete_event(self, advancedFilters: str = None, deleteAll: bool = None, endDate: int = None, freeTextSearch: str = None, idsToDelete: list = None, offset: int = None, organizationId: int = None, pageSize: int = None, sorting: str = None, startDate: int = None, timeFilter: str = None) -> tuple[bool, None]:
		'''
		Class securebrowserrestapicontroller
		Description: Delete secure browser events.
        
		Args:
			advancedFilters (str): Specifies advanced filters
			deleteAll (bool): Indicate if should delete all matching results (rather than only the selected) 
			endDate (int): Specifies the time filter end date
			freeTextSearch (str): pattern of requested text
			idsToDelete (list): Id's of entities to delete
			offset (int): Specifies the page offset
			organizationId (int): Specifies the organization id
			pageSize (int): Specifies the page size
			sorting (str): list of sorting fields (each is a map of <fieldName>:<descending order flag>. false=ascending, true=descending)
			startDate (int): Specifies the time filter start date
			timeFilter (str): Specifies the incidents time filter

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_delete_event", locals())

		url = '/api/secure-browser/events'
		url_params = []
		if advancedFilters != None:
			url_params.append(f'advancedFilters={advancedFilters}')
		if deleteAll != None:
			url_params.append(f'deleteAll={deleteAll}')
		if endDate != None:
			url_params.append(f'endDate={endDate}')
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if idsToDelete != None:
			idsToDelete = ",".join(map(str, idsToDelete)) if isinstance(idsToDelete, list) else idsToDelete
			url_params.append(f'idsToDelete={idsToDelete}')
		if offset != None:
			url_params.append(f'offset={offset}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if pageSize != None:
			url_params.append(f'pageSize={pageSize}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if startDate != None:
			url_params.append(f'startDate={startDate}')
		if timeFilter != None:
			url_params.append(f'timeFilter={timeFilter}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def get_get_policies(self, freeTextSearch: str = None, offset: int = None, organizationId: int = None, pageSize: int = None, sorting: str = None) -> tuple[bool, None]:
		'''
		Class securebrowserrestapicontroller
		Description: Return all secure browser policies.
        
		Args:
			freeTextSearch (str): pattern of requested text
			offset (int): Specifies the page offset
			organizationId (int): Specifies the organization id
			pageSize (int): Specifies the page size
			sorting (str): list of sorting fields (each is a map of <fieldName>:<descending order flag>. false=ascending, true=descending)

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_get_policies", locals())

		url = '/api/secure-browser/policies'
		url_params = []
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if offset != None:
			url_params.append(f'offset={offset}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if pageSize != None:
			url_params.append(f'pageSize={pageSize}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def send_create_policy(self, collectorGroups: list = None, description: str = None, enabled: bool = None, id: int = None, name: str = None, organizationId: int = None, updatedBy: str = None) -> tuple[bool, None]:
		'''
		Class securebrowserrestapicontroller
		Description: Create secure browser policy.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("send_create_policy", locals())

		url = '/api/secure-browser/policies'

		request = {}
		if collectorGroups:
			request["collectorGroups"] = f"{collectorGroups}"
		if description:
			request["description"] = f"{description}"
		if enabled:
			request["enabled"] = f"{enabled}"
		if id != None:
			request["id"] = f"{id}"
		if name:
			request["name"] = f"{name}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"
		if updatedBy:
			request["updatedBy"] = f"{updatedBy}"

		return fortiedr_connection.send(url, request)

	def delete_delete_policy(self, deleteAll: bool = None, freeTextSearch: str = None, idsToDelete: list = None, offset: int = None, organizationId: int = None, pageSize: int = None, sorting: str = None, updatedBy: str = None) -> tuple[bool, None]:
		'''
		Class securebrowserrestapicontroller
		Description: Delete secure browser policies.
        
		Args:
			deleteAll (bool): Indicate if should delete all matching results (rather than only the selected) 
			freeTextSearch (str): pattern of policies to delete
			idsToDelete (list): Id's of entities to delete
			offset (int): Specifies the page offset
			organizationId (int): organization id
			pageSize (int): Specifies the page size
			sorting (str): list of sorting fields (each is a map of <fieldName>:<descending order flag>. false=ascending, true=descending)
			updatedBy (str): specifies the user who updated the policy

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_delete_policy", locals())

		url = '/api/secure-browser/policies'
		url_params = []
		if deleteAll != None:
			url_params.append(f'deleteAll={deleteAll}')
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if idsToDelete != None:
			idsToDelete = ",".join(map(str, idsToDelete)) if isinstance(idsToDelete, list) else idsToDelete
			url_params.append(f'idsToDelete={idsToDelete}')
		if offset != None:
			url_params.append(f'offset={offset}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if pageSize != None:
			url_params.append(f'pageSize={pageSize}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if updatedBy != None:
			url_params.append(f'updatedBy={updatedBy}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def assigned_agent_groups(self, agentGroupsIds: list = None, excludePolicyId: int = None) -> tuple[bool, None]:
		'''
		Class securebrowserrestapicontroller
		Description: Return true if policies has assigned collector groups.
        
		Args:
			agentGroupsIds (list): agent groups id's
			excludePolicyId (int): exclude policy id

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("assigned_agent_groups", locals())

		url = '/api/secure-browser/policies/assigned-agent-groups'
		url_params = []
		if agentGroupsIds != None:
			agentGroupsIds = ",".join(map(str, agentGroupsIds)) if isinstance(agentGroupsIds, list) else agentGroupsIds
			url_params.append(f'agentGroupsIds={agentGroupsIds}')
		if excludePolicyId != None:
			url_params.append(f'excludePolicyId={excludePolicyId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def update_policy_state(self, allSelected: bool = None, enabled: bool = None, freeTextSearch: str = None, offset: int = None, organizationId: int = None, pageSize: int = None, policiesIds: list = None, sorting: str = None, updatedBy: str = None) -> tuple[bool, None]:
		'''
		Class securebrowserrestapicontroller
		Description: Change secure browser policies state (enable/disable).
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("update_policy_state", locals())

		url = '/api/secure-browser/policies/state'

		request = {}
		if allSelected:
			request["allSelected"] = f"{allSelected}"
		if enabled:
			request["enabled"] = f"{enabled}"
		if freeTextSearch:
			request["freeTextSearch"] = f"{freeTextSearch}"
		if offset != None:
			request["offset"] = f"{offset}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"
		if pageSize != None:
			request["pageSize"] = f"{pageSize}"
		if policiesIds:
			request["policiesIds"] = f"{policiesIds}"
		if sorting:
			request["sorting"] = f"{sorting}"
		if updatedBy:
			request["updatedBy"] = f"{updatedBy}"

		return fortiedr_connection.insert(url, request)

	def get_rules(self, id: int, organizationId: int = None) -> tuple[bool, None]:
		'''
		Class securebrowserrestapicontroller
		Description: Return all secure browser rules for specific policy..
        
		Args:
			id (int): id
			organizationId (int): organizationId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_rules", locals())

		url = f'/api/secure-browser/policies/{id}/rules'
		url_params = []
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def get_get_policy(self, id: int, organizationId: int) -> tuple[bool, None]:
		'''
		Class securebrowserrestapicontroller
		Description: get secure browser policy.
        
		Args:
			id (int): id
			organizationId (int): organizationId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_get_policy", locals())

		url = f'/api/secure-browser/policy/{id}'


		return fortiedr_connection.get(url, organizationId)

	def insert_update_policy(self, id: int, collectorGroups: list = None, description: str = None, enabled: bool = None, name: str = None, organizationId: int = None, updatedBy: str = None) -> tuple[bool, None]:
		'''
		Class securebrowserrestapicontroller
		Description: Update secure browser policy.
        
		Args:
			id (int): id
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("insert_update_policy", locals())

		url = f'/api/secure-browser/policy/{id}'

		request = {}
		if collectorGroups:
			request["collectorGroups"] = f"{collectorGroups}"
		if description:
			request["description"] = f"{description}"
		if enabled:
			request["enabled"] = f"{enabled}"
		if id != None:
			request["id"] = f"{id}"
		if name:
			request["name"] = f"{name}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"
		if updatedBy:
			request["updatedBy"] = f"{updatedBy}"

		return fortiedr_connection.insert(url, request)

	def update_rule(self, id: int, action: str = None, attributes: object = None, enabled: bool = None, organizationId: int = None, policyId: int = None, ruleType: str = None, updatedBy: str = None) -> tuple[bool, None]:
		'''
		Class securebrowserrestapicontroller
		Description: Update rule.
        
		Args:
			id (int): id
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("update_rule", locals())

		url = f'/api/secure-browser/rules/{id}'

		request = {}
		if action:
			request["action"] = f"{action}"
		if attributes:
			request["attributes"] = f"{attributes}"
		if enabled:
			request["enabled"] = f"{enabled}"
		if id != None:
			request["id"] = f"{id}"
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"
		if policyId != None:
			request["policyId"] = f"{policyId}"
		if ruleType:
			request["ruleType"] = f"{ruleType}"
		if updatedBy:
			request["updatedBy"] = f"{updatedBy}"

		return fortiedr_connection.insert(url, request)

	def get_static_data(self) -> tuple[bool, None]:
		'''
		Class securebrowserrestapicontroller
		Description: get static data.
        
		Args:

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_static_data", locals())

		url = '/api/secure-browser/static-data'
		return fortiedr_connection.get(url)

	def update_system_prevention_mode(self, organizationId: int = None, prevention: bool = None) -> tuple[bool, None]:
		'''
		Class securebrowserrestapicontroller
		Description: Change system prevention mode (prevention/simulation).
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("update_system_prevention_mode", locals())

		url = '/api/secure-browser/system-prevention-mode'

		request = {}
		if organizationId != None:
			request["organizationId"] = f"{organizationId}"
		if prevention:
			request["prevention"] = f"{prevention}"

		return fortiedr_connection.insert(url, request)

class Users:
	'''API to define user'''

	def create_user_restapi(self, accountId: int, contact: object, name: str, password: str, passwordConfirm: str, rbacRole: str, customScript: bool = None, remoteShell: bool = None, restApi: bool = None, twoFactorAuthHours: int = None, twoFactorAuthentication: bool = None) -> tuple[bool, None]:
		'''
		Class Users
		Description: This API creates a user in the system. (only for Admin role).
        
		Args:
			createUserRequest (Object): Check 'createUserRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("create_user_restapi", locals())

		url = '/api/users/create-user'

		createUserRequest = {}
		if accountId != None:
			createUserRequest["accountId"] = f"{accountId}"
		if contact:
			createUserRequest["contact"] = f"{contact}"
		if customScript:
			createUserRequest["customScript"] = f"{customScript}"
		if name:
			createUserRequest["name"] = f"{name}"
		if password:
			createUserRequest["password"] = f"{password}"
		if passwordConfirm:
			createUserRequest["passwordConfirm"] = f"{passwordConfirm}"
		if rbacRole:
			createUserRequest["rbacRole"] = f"{rbacRole}"
		if remoteShell:
			createUserRequest["remoteShell"] = f"{remoteShell}"
		if restApi:
			createUserRequest["restApi"] = f"{restApi}"
		if twoFactorAuthHours != None:
			createUserRequest["twoFactorAuthHours"] = f"{twoFactorAuthHours}"
		if twoFactorAuthentication:
			createUserRequest["twoFactorAuthentication"] = f"{twoFactorAuthentication}"

		return fortiedr_connection.send(url, createUserRequest)

	def delete_user(self, userId: int) -> tuple[bool, None]:
		'''
		Class Users
		Description: This API deletes a user (Admin role required).
        
		Args:
			userId (int): userId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_user", locals())

		url = '/api/users/delete-user'
		url_params = []
		if userId != None:
			url_params.append(f'userId={userId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def delete_users(self, userIds: list) -> tuple[bool, None]:
		'''
		Class Users
		Description: This API deletes users (Admin role required).
        
		Args:
			userIds (list): userIds

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_users", locals())

		url = '/api/users/delete-users'
		url_params = []
		if userIds != None:
			userIds = ",".join(map(str, userIds)) if isinstance(userIds, list) else userIds
			url_params.append(f'userIds={userIds}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def environment_password_policy(self) -> tuple[bool, None]:
		'''
		Class Users
		Description: This API fetches the environment password policy..
        
		Args:

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("environment_password_policy", locals())

		url = '/api/users/environment-password-policy'
		return fortiedr_connection.get(url)

	def get_gdpr_privacy_note(self) -> tuple[bool, str]:
		'''
		Class Users
		Description: Get GDPR privacy note.
        
		Args:

		Returns:
			bool: Status of the request (True or False). 
			str
		'''
		validate_params("get_gdpr_privacy_note", locals())

		url = '/api/users/get-gdpr-privacy-note'
		return fortiedr_connection.get(url)

	def get_ldap_relevant_cores(self) -> tuple[bool, list]:
		'''
		Class Users
		Description: Get LDAP relevant cores.
        
		Args:

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("get_ldap_relevant_cores", locals())

		url = '/api/users/ldap-relevant-cores'
		return fortiedr_connection.get(url)

	def get_ldap_settings(self) -> tuple[bool, None]:
		'''
		Class Users
		Description: Get LDAP settings.
        
		Args:

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_ldap_settings", locals())

		url = '/api/users/ldap-settings'
		return fortiedr_connection.get(url)

	def get_ldap_users(self, organizationId: int) -> tuple[bool, list]:
		'''
		Class Users
		Description: Get LDAP users.
        
		Args:
			organizationId (int): organizationId

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("get_ldap_users", locals())

		url = '/api/users/ldap-users'
		url_params = []
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def password_policy_config_by_accountId(self, accountId: int = None) -> tuple[bool, None]:
		'''
		Class Users
		Description: This API fetches an existing password-policy-config..
        
		Args:
			accountId (int): account id

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("password_policy_config_by_accountId", locals())

		url = '/api/users/password-policy-config-by-accountId'
		url_params = []
		if accountId != None:
			url_params.append(f'accountId={accountId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def set_user_preferences(self, entries: object = None, preferenceKey: str = None) -> tuple[bool, None]:
		'''
		Class Users
		Description: Set user preferences.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("set_user_preferences", locals())

		url = '/api/users/preferences'

		request = {}
		if entries:
			request["entries"] = f"{entries}"
		if preferenceKey:
			request["preferenceKey"] = f"{preferenceKey}"

		return fortiedr_connection.insert(url, request)

	def get_user_preferences(self, preferenceKey: str) -> tuple[bool, None]:
		'''
		Class Users
		Description: Get user preferences.
        
		Args:
			preferenceKey (str): preferenceKey

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_user_preferences", locals())

		url = f'/api/users/preferences/{preferenceKey}'
		return fortiedr_connection.get(url)

	def reset_ldap_two_fa(self, userId: int) -> tuple[bool, None]:
		'''
		Class Users
		Description: Reset LDAP Two FA.
        
		Args:
			userId (int): userId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("reset_ldap_two_fa", locals())

		url = '/api/users/reset-ldap-two-fa'


		return fortiedr_connection.send(url, userId)

	def reset_Password(self, userDisplayItem: object = None) -> tuple[bool, None]:
		'''
		Class Users
		Description: This API resets user password and optional require change Password on next sign in (Admin role required).
        
		Args:
			resetPasswordRequest (Object): Check 'resetPasswordRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("reset_Password", locals())

		url = '/api/users/reset-password'

		resetPasswordRequest = {}
		if userDisplayItem:
			resetPasswordRequest["userDisplayItem"] = f"{userDisplayItem}"

		return fortiedr_connection.send(url, resetPasswordRequest)

	def reset_two_factor_authentication(self, userId: int = None) -> tuple[bool, None]:
		'''
		Class Users
		Description: This API resets two-factor authentication for a specified user. (Admin role required).
        
		Args:
			resetTwoFactorAuthenticationRequest (Object): Check 'resetTwoFactorAuthenticationRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("reset_two_factor_authentication", locals())

		url = '/api/users/reset-two-factor-authentication'

		resetTwoFactorAuthenticationRequest = {}
		if userId != None:
			resetTwoFactorAuthenticationRequest["userId"] = f"{userId}"

		return fortiedr_connection.send(url, resetTwoFactorAuthenticationRequest)

	def rbac_roles(self, organizationId: int) -> tuple[bool, list]:
		'''
		Class Users
		Description: Get RBAC roles.
        
		Args:
			organizationId (int): organizationId

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("rbac_roles", locals())

		url = '/api/users/roles'
		url_params = []
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def get_get_saml_settings(self) -> tuple[bool, list]:
		'''
		Class Users
		Description: Get SAML settings.
        
		Args:

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("get_get_saml_settings", locals())

		url = '/api/users/saml-settings'
		return fortiedr_connection.get(url)

	def insert_save_saml_settings(self, accountId: int = None, metadataFileIsDirty: bool = None, metadataUuid: str = None, samlSettings: object = None) -> tuple[bool, None]:
		'''
		Class Users
		Description: Save SAML Settings.
        
		Args:
			samlRequest (Object): Check 'samlRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("insert_save_saml_settings", locals())

		url = '/api/users/saml-settings'

		samlRequest = {}
		if accountId != None:
			samlRequest["accountId"] = f"{accountId}"
		if metadataFileIsDirty:
			samlRequest["metadataFileIsDirty"] = f"{metadataFileIsDirty}"
		if metadataUuid:
			samlRequest["metadataUuid"] = f"{metadataUuid}"
		if samlSettings:
			samlRequest["samlSettings"] = f"{samlSettings}"

		return fortiedr_connection.insert(url, samlRequest)

	def clear_saml_settings(self, organizationId: int) -> tuple[bool, None]:
		'''
		Class Users
		Description: Clear SAML Settings.
        
		Args:
			organizationId (int): organizationId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("clear_saml_settings", locals())

		url = '/api/users/saml-settings/clear'
		url_params = []
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def valid_saml_sso_url(self, organizationId: int, urlPostfix: str) -> tuple[bool, None]:
		'''
		Class Users
		Description: Valid SAML SSO url.
        
		Args:
			organizationId (int): organizationId
			urlPostfix (str): urlPostfix

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("valid_saml_sso_url", locals())

		url = '/api/users/saml-settings/valid-sso-url'
		url_params = []
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if urlPostfix != None:
			url_params.append(f'urlPostfix={urlPostfix}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def save_ldap_settings(self, adminsGroupName: str = None, apiGroupName: str = None, baseDn: str = None, bindDn: str = None, bindPassword: str = None, coreId: int = None, directoryType: str = None, enabled: bool = None, groupsMapping: list = None, host: str = None, hostGroupName: str = None, id: int = None, port: int = None, securityLevel: str = None, twoFactorAuthHours: int = None, twoFactorAuthenticationEnabled: bool = None, usersGroupName: str = None) -> tuple[bool, None]:
		'''
		Class Users
		Description: Save LDAP Settings.
        
		Args:
			ldapConfigRequest (Object): Check 'ldapConfigRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("save_ldap_settings", locals())

		url = '/api/users/save-ldap-settings'

		ldapConfigRequest = {}
		if adminsGroupName:
			ldapConfigRequest["adminsGroupName"] = f"{adminsGroupName}"
		if apiGroupName:
			ldapConfigRequest["apiGroupName"] = f"{apiGroupName}"
		if baseDn:
			ldapConfigRequest["baseDn"] = f"{baseDn}"
		if bindDn:
			ldapConfigRequest["bindDn"] = f"{bindDn}"
		if bindPassword:
			ldapConfigRequest["bindPassword"] = f"{bindPassword}"
		if coreId != None:
			ldapConfigRequest["coreId"] = f"{coreId}"
		if directoryType:
			ldapConfigRequest["directoryType"] = f"{directoryType}"
		if enabled:
			ldapConfigRequest["enabled"] = f"{enabled}"
		if groupsMapping:
			ldapConfigRequest["groupsMapping"] = f"{groupsMapping}"
		if host:
			ldapConfigRequest["host"] = f"{host}"
		if hostGroupName:
			ldapConfigRequest["hostGroupName"] = f"{hostGroupName}"
		if id != None:
			ldapConfigRequest["id"] = f"{id}"
		if port != None:
			ldapConfigRequest["port"] = f"{port}"
		if securityLevel:
			ldapConfigRequest["securityLevel"] = f"{securityLevel}"
		if twoFactorAuthHours != None:
			ldapConfigRequest["twoFactorAuthHours"] = f"{twoFactorAuthHours}"
		if twoFactorAuthenticationEnabled:
			ldapConfigRequest["twoFactorAuthenticationEnabled"] = f"{twoFactorAuthenticationEnabled}"
		if usersGroupName:
			ldapConfigRequest["usersGroupName"] = f"{usersGroupName}"

		return fortiedr_connection.send(url, ldapConfigRequest)

	def save_password_policy_config(self, accountId: int = None, closeSessionImmediately: bool = None, passwordPolicyDisplayItem: object = None) -> tuple[bool, str]:
		'''
		Class Users
		Description: This API save a password policy config..
        
		Args:
			savePasswordPolicyConfigRequest (Object): Check 'savePasswordPolicyConfigRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			str
		'''
		validate_params("save_password_policy_config", locals())

		url = '/api/users/save-password-policy-config'

		savePasswordPolicyConfigRequest = {}
		if accountId != None:
			savePasswordPolicyConfigRequest["accountId"] = f"{accountId}"
		if closeSessionImmediately:
			savePasswordPolicyConfigRequest["closeSessionImmediately"] = f"{closeSessionImmediately}"
		if passwordPolicyDisplayItem:
			savePasswordPolicyConfigRequest["passwordPolicyDisplayItem"] = f"{passwordPolicyDisplayItem}"

		return fortiedr_connection.send(url, savePasswordPolicyConfigRequest)

	def server_name_configured(self) -> tuple[bool, None]:
		'''
		Class Users
		Description: Is Server DNS Name Configured.
        
		Args:

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("server_name_configured", locals())

		url = '/api/users/server-name-configured'
		return fortiedr_connection.get(url)

	def test_ldap_connection(self, adminsGroupName: str = None, apiGroupName: str = None, baseDn: str = None, bindDn: str = None, bindPassword: str = None, coreId: int = None, directoryType: str = None, enabled: bool = None, groupsMapping: list = None, host: str = None, hostGroupName: str = None, id: int = None, port: int = None, securityLevel: str = None, twoFactorAuthHours: int = None, twoFactorAuthenticationEnabled: bool = None, usersGroupName: str = None) -> tuple[bool, None]:
		'''
		Class Users
		Description: Test LDAP connection.
        
		Args:
			ldapConfigRequest (Object): Check 'ldapConfigRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("test_ldap_connection", locals())

		url = '/api/users/test-ldap-connection'

		ldapConfigRequest = {}
		if adminsGroupName:
			ldapConfigRequest["adminsGroupName"] = f"{adminsGroupName}"
		if apiGroupName:
			ldapConfigRequest["apiGroupName"] = f"{apiGroupName}"
		if baseDn:
			ldapConfigRequest["baseDn"] = f"{baseDn}"
		if bindDn:
			ldapConfigRequest["bindDn"] = f"{bindDn}"
		if bindPassword:
			ldapConfigRequest["bindPassword"] = f"{bindPassword}"
		if coreId != None:
			ldapConfigRequest["coreId"] = f"{coreId}"
		if directoryType:
			ldapConfigRequest["directoryType"] = f"{directoryType}"
		if enabled:
			ldapConfigRequest["enabled"] = f"{enabled}"
		if groupsMapping:
			ldapConfigRequest["groupsMapping"] = f"{groupsMapping}"
		if host:
			ldapConfigRequest["host"] = f"{host}"
		if hostGroupName:
			ldapConfigRequest["hostGroupName"] = f"{hostGroupName}"
		if id != None:
			ldapConfigRequest["id"] = f"{id}"
		if port != None:
			ldapConfigRequest["port"] = f"{port}"
		if securityLevel:
			ldapConfigRequest["securityLevel"] = f"{securityLevel}"
		if twoFactorAuthHours != None:
			ldapConfigRequest["twoFactorAuthHours"] = f"{twoFactorAuthHours}"
		if twoFactorAuthenticationEnabled:
			ldapConfigRequest["twoFactorAuthenticationEnabled"] = f"{twoFactorAuthenticationEnabled}"
		if usersGroupName:
			ldapConfigRequest["usersGroupName"] = f"{usersGroupName}"

		return fortiedr_connection.send(url, ldapConfigRequest)

	def update_gdpr_privacy_note(self, userId: int) -> tuple[bool, None]:
		'''
		Class Users
		Description: Put GDPR privacy note.
        
		Args:
			userId (int): userId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("update_gdpr_privacy_note", locals())

		url = '/api/users/update-gdpr-privacy-note'
		url_params = []
		if userId != None:
			url_params.append(f'userId={userId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def update_user_restapi(self, accountId: int, changePasswordOnNextSignIn: bool, contact: object, isLocked: bool, name: str, password: str, passwordConfirm: str, rbacRole: str, accountName: str = None, customScript: bool = None, id: int = None, passwordPolicy: object = None, rbacRoleName: str = None, remoteShell: bool = None, restApi: bool = None, twoFactorAuthHours: int = None, twoFactorAuthentication: bool = None, userType: str = None) -> tuple[bool, None]:
		'''
		Class Users
		Description: This API updates an existing user in the system. (only for Admin role).
        
		Args:
			userToUpdate (Object): Check 'userToUpdate' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("update_user_restapi", locals())

		url = '/api/users/update-user'

		userToUpdate = {}
		if accountId != None:
			userToUpdate["accountId"] = f"{accountId}"
		if accountName:
			userToUpdate["accountName"] = f"{accountName}"
		if changePasswordOnNextSignIn:
			userToUpdate["changePasswordOnNextSignIn"] = f"{changePasswordOnNextSignIn}"
		if contact:
			userToUpdate["contact"] = f"{contact}"
		if customScript:
			userToUpdate["customScript"] = f"{customScript}"
		if id != None:
			userToUpdate["id"] = f"{id}"
		if isLocked:
			userToUpdate["isLocked"] = f"{isLocked}"
		if name:
			userToUpdate["name"] = f"{name}"
		if password:
			userToUpdate["password"] = f"{password}"
		if passwordConfirm:
			userToUpdate["passwordConfirm"] = f"{passwordConfirm}"
		if passwordPolicy:
			userToUpdate["passwordPolicy"] = f"{passwordPolicy}"
		if rbacRole:
			userToUpdate["rbacRole"] = f"{rbacRole}"
		if rbacRoleName:
			userToUpdate["rbacRoleName"] = f"{rbacRoleName}"
		if remoteShell:
			userToUpdate["remoteShell"] = f"{remoteShell}"
		if restApi:
			userToUpdate["restApi"] = f"{restApi}"
		if twoFactorAuthHours != None:
			userToUpdate["twoFactorAuthHours"] = f"{twoFactorAuthHours}"
		if twoFactorAuthentication:
			userToUpdate["twoFactorAuthentication"] = f"{twoFactorAuthentication}"
		if userType:
			userToUpdate["userType"] = f"{userType}"

		return fortiedr_connection.insert(url, userToUpdate)

	def get_users_display_item(self, freeTextSearch: str, offset: int, organizationId: int, pageSize: int, sorting: str) -> tuple[bool, None]:
		'''
		Class Users
		Description: display-item.
        
		Args:
			freeTextSearch (str): Specifies the free text search
			offset (int): Specifies the page offset
			organizationId (int): Specifies the organization id
			pageSize (int): Specifies the page size
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_users_display_item", locals())

		url = '/api/users/users'
		url_params = []
		if freeTextSearch != None:
			url_params.append(f'freeTextSearch={freeTextSearch}')
		if offset != None:
			url_params.append(f'offset={offset}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if pageSize != None:
			url_params.append(f'pageSize={pageSize}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def get_users_by_account(self, includeDummyAccountUsers: bool = None, includeLdapUsers: bool = None, includeSamlUsers: bool = None, organizationId: int = None) -> tuple[bool, list]:
		'''
		Class Users
		Description: Get account users.
        
		Args:
			includeDummyAccountUsers (bool): Whether to include dummy account users
			includeLdapUsers (bool): Whether to include ldap users
			includeSamlUsers (bool): Whether to include saml users
			organizationId (int): Specifies the organization id

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("get_users_by_account", locals())

		url = '/api/users/users-by-account'
		url_params = []
		if includeDummyAccountUsers != None:
			url_params.append(f'includeDummyAccountUsers={includeDummyAccountUsers}')
		if includeLdapUsers != None:
			url_params.append(f'includeLdapUsers={includeLdapUsers}')
		if includeSamlUsers != None:
			url_params.append(f'includeSamlUsers={includeSamlUsers}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def create_user(self, confirmPassword: str, email: str, firstName: str, lastName: str, password: str, role: str, username: str, organization: str = None, customScript: bool = None, remoteShell: bool = None, restApi: bool = None, title: str = None) -> tuple[bool, None]:
		'''
		Class Users
		Description: This API create user in the system. (only for Admin role.
        
		Args:
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non-shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	each – Indicates that the operation applies independently to each organization. For example, let's assume that the same user exists in multiple organizations. When each is specified in the organization parameter, then each organization can update this user separately.
			userRequest (Object): Check 'userRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("create_user", locals())

		url = '/management-rest/users/create-user'
		url_params = []
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)

		userRequest = {}
		if confirmPassword:
			userRequest["confirmPassword"] = f"{confirmPassword}"
		if customScript:
			userRequest["customScript"] = f"{customScript}"
		if email:
			userRequest["email"] = f"{email}"
		if firstName:
			userRequest["firstName"] = f"{firstName}"
		if lastName:
			userRequest["lastName"] = f"{lastName}"
		if password:
			userRequest["password"] = f"{password}"
		if remoteShell:
			userRequest["remoteShell"] = f"{remoteShell}"
		if restApi:
			userRequest["restApi"] = f"{restApi}"
		if role:
			userRequest["role"] = f"{role}"
		if title:
			userRequest["title"] = f"{title}"
		if username:
			userRequest["username"] = f"{username}"

		return fortiedr_connection.send(url, userRequest)

	def delete_saml_settings(self, organizationNameRequest: str) -> tuple[bool, None]:
		'''
		Class Users
		Description: Delete SAML authentication settings per organization.
        
		Args:
			organizationNameRequest (str): organizationNameRequest

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_saml_settings", locals())

		url = '/management-rest/users/delete-saml-settings'
		url_params = []
		if organizationNameRequest != None:
			url_params.append(f'organizationNameRequest={organizationNameRequest}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def delete_user(self, organization: str, username: str) -> tuple[bool, None]:
		'''
		Class Users
		Description: This API delete user from the system. Use the input parameters to filter organization.
        
		Args:
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			username (str): Specifies the name of the user

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_user", locals())

		url = '/management-rest/users/delete-user'
		url_params = []
		if organization != None:
			url_params.append(f'organization={organization}')
		if username != None:
			url_params.append(f'username={username}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def get_sp_metadata(self, organization: str) -> tuple[bool, str]:
		'''
		Class Users
		Description: This API call retrieve the FortiEdr metadata by organization.
        
		Args:
			organization (str): organization

		Returns:
			bool: Status of the request (True or False). 
			str
		'''
		validate_params("get_sp_metadata", locals())

		url = '/management-rest/users/get-sp-metadata'
		url_params = []
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def list_users(self, organization: str = None) -> tuple[bool, list]:
		'''
		Class Users
		Description: This API call outputs a list of the users in the system. Use the input parameters to filter the list.
        
		Args:
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_users", locals())

		url = '/management-rest/users/list-users'
		url_params = []
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def reset_password(self, organization: str, confirmPassword: str, password: str, username: str) -> tuple[bool, None]:
		'''
		Class Users
		Description: This API reset user password. Use the input parameters to filter organization.
        
		Args:
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			userRequest (Object): Check 'userRequest' in the API documentation for further information.
			username (str): Specifies the name of the user

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("reset_password", locals())

		url = '/management-rest/users/reset-password'
		url_params = []
		if organization != None:
			url_params.append(f'organization={organization}')
		if username != None:
			url_params.append(f'username={username}')
		url += '?' + '&'.join(url_params)

		userRequest = {}
		if confirmPassword:
			userRequest["confirmPassword"] = f"{confirmPassword}"
		if password:
			userRequest["password"] = f"{password}"

		return fortiedr_connection.insert(url, userRequest)

	def update_saml_settings(self, idpMetadataFile: BinaryIO) -> tuple[bool, None]:
		'''
		Class Users
		Description: Create / Update SAML authentication settings per organization.
        
		Args:
			idpMetadataFile (BinaryIO): idpMetadataFile

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("update_saml_settings", locals())

		url = '/management-rest/users/update-saml-settings'
		if idpMetadataFile:
			idpMetadataFile = {'idpMetadataFile': idpMetadataFile}


		return fortiedr_connection.upload(url, idpMetadataFile)

	def update_user(self, email: str, firstName: str, lastName: str, role: str, username: str, organization: str = None, customScript: bool = None, remoteShell: bool = None, restApi: bool = None, title: str = None) -> tuple[bool, None]:
		'''
		Class Users
		Description: This API update user in the system. Use the input parameters to filter organization.
        
		Args:
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non-shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	each – Indicates that the operation applies independently to each organization. For example, let's assume that the same user exists in multiple organizations. When each is specified in the organization parameter, then each organization can update this user separately.
			userRequest (Object): Check 'userRequest' in the API documentation for further information.
			username (str): Specifies the name of the user

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("update_user", locals())

		url = '/management-rest/users/update-user'
		url_params = []
		if organization != None:
			url_params.append(f'organization={organization}')
		if username != None:
			url_params.append(f'username={username}')
		url += '?' + '&'.join(url_params)

		userRequest = {}
		if customScript:
			userRequest["customScript"] = f"{customScript}"
		if email:
			userRequest["email"] = f"{email}"
		if firstName:
			userRequest["firstName"] = f"{firstName}"
		if lastName:
			userRequest["lastName"] = f"{lastName}"
		if remoteShell:
			userRequest["remoteShell"] = f"{remoteShell}"
		if restApi:
			userRequest["restApi"] = f"{restApi}"
		if role:
			userRequest["role"] = f"{role}"
		if title:
			userRequest["title"] = f"{title}"
		if username:
			userRequest["username"] = f"{username}"

		return fortiedr_connection.insert(url, userRequest)

class Administrator:
	'''The Administrator module enables administrators to perform administrative operations, such as handling licenses and users.'''

	def delete_collector_installer_version(self, osFamily: str, collectorVersion: str = None, organizationId: int = None) -> tuple[bool, None]:
		'''
		Class Administrator
		Description: Delete collector installer version.
        
		Args:
			collectorVersion (str): Specifies the collector version
			organizationId (int): Specifies the organization id
			osFamily (str): OS

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_collector_installer_version", locals())

		url = '/management-rest/admin/delete-collector-installer-version'
		url_params = []
		if collectorVersion != None:
			url_params.append(f'collectorVersion={collectorVersion}')
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		if osFamily != None:
			url_params.append(f'osFamily={osFamily}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def list_collector_installers(self, organization: str = None) -> tuple[bool, None]:
		'''
		Class Administrator
		Description: This API call output the available collectors installers.
        
		Args:
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("list_collector_installers", locals())

		url = '/management-rest/admin/list-collector-installers'
		url_params = []
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def list_system_summary(self, addLicenseBlob: bool = None, organization: str = None) -> tuple[bool, None]:
		'''
		Class Administrator
		Description: Get System Summary.
        
		Args:
			addLicenseBlob (bool): Indicates whether to put license blob to response. By default addLicenseBlob is false
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("list_system_summary", locals())

		url = '/management-rest/admin/list-system-summary'
		url_params = []
		if addLicenseBlob != None:
			url_params.append(f'addLicenseBlob={addLicenseBlob}')
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def previous_registration_passwords(self, organization: str) -> tuple[bool, list]:
		'''
		Class Administrator
		Description: This API retrieve previous registration passwords for given organization.
        
		Args:
			organizationRequest (Object): Check 'organizationRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("previous_registration_passwords", locals())

		url = '/management-rest/admin/previous-registration-passwords'

		organizationRequest = {}
		if organization:
			organizationRequest["organization"] = f"{organization}"

		return fortiedr_connection.get(url, organizationRequest)

	def previous_registration_passwords(self, organization: str, passwordId: int) -> tuple[bool, str]:
		'''
		Class Administrator
		Description: This API deletes previous registration password for given id.
        
		Args:
			organizationRequest (Object): Check 'organizationRequest' in the API documentation for further information.
			passwordId (int): passwordId

		Returns:
			bool: Status of the request (True or False). 
			str
		'''
		validate_params("previous_registration_passwords", locals())

		url = f'/management-rest/admin/previous-registration-passwords/{passwordId}'

		organizationRequest = {}
		if organization:
			organizationRequest["organization"] = f"{organization}"

		return fortiedr_connection.delete(url, organizationRequest)

	def ready(self) -> tuple[bool, None]:
		'''
		Class Administrator
		Description: Get System Readiness.
        
		Args:

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("ready", locals())

		url = '/management-rest/admin/ready'
		return fortiedr_connection.get(url)

	def registration_password(self, organization: str, password: str) -> tuple[bool, None]:
		'''
		Class Administrator
		Description: This API creates new registration password for given organization.
        
		Args:
			request (Object): Check 'request' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("registration_password", locals())

		url = '/management-rest/admin/registration-password'

		request = {}
		if organization:
			request["organization"] = f"{organization}"
		if password:
			request["password"] = f"{password}"

		return fortiedr_connection.send(url, request)

	def set_system_mode(self, mode: str, forceAll: bool = None, organization: str = None) -> tuple[bool, None]:
		'''
		Class Administrator
		Description: Set system modeThis API call enables you to switch the system to Simulation mode.
        
		Args:
			forceAll (bool): Indicates whether to force set all the policies in 'Prevention' mode
			mode (str): Operation mode
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("set_system_mode", locals())

		url = '/management-rest/admin/set-system-mode'
		url_params = []
		if forceAll != None:
			url_params.append(f'forceAll={forceAll}')
		if mode != None:
			url_params.append(f'mode={mode}')
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def update_collector_installer(self, collectorGroupIds: list = None, collectorGroups: list = None, organization: str = None, updateVersions: list = None) -> tuple[bool, None]:
		'''
		Class Administrator
		Description: This API update collectors target version for collector groups.
        
		Args:
			collectorGroupIds (list): Specifies the list of IDs of all the collector groups which should be updated.
			collectorGroups (list): Specifies the list of all the collector groups which should be updated.
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			requestUpdateData (Object): Check 'requestUpdateData' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("update_collector_installer", locals())

		url = '/management-rest/admin/update-collector-installer'
		url_params = []
		if collectorGroupIds != None:
			collectorGroupIds = ",".join(map(str, collectorGroupIds)) if isinstance(collectorGroupIds, list) else collectorGroupIds
			url_params.append(f'collectorGroupIds={collectorGroupIds}')
		if collectorGroups != None:
			collectorGroups = ",".join(collectorGroups) if isinstance(collectorGroups, list) else collectorGroups
			url_params.append(f'collectorGroups={collectorGroups}')
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)

		requestUpdateData = {}
		if updateVersions:
			requestUpdateData["updateVersions"] = f"{updateVersions}"

		return fortiedr_connection.send(url, requestUpdateData)

	def upload_content(self, file: BinaryIO) -> tuple[bool, str]:
		'''
		Class Administrator
		Description: Upload content to the system.
        
		Args:
			file (BinaryIO): file

		Returns:
			bool: Status of the request (True or False). 
			str
		'''
		validate_params("upload_content", locals())

		url = '/management-rest/admin/upload-content'
		if file:
			file = {'file': file}


		return fortiedr_connection.upload(url, file)

	def upload_license(self, confirmInternalLicense: bool = None, licenseBlob: str = None) -> tuple[bool, None]:
		'''
		Class Administrator
		Description: Upload license to the system.
        
		Args:
			license (Object): Check 'license' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("upload_license", locals())

		url = '/management-rest/admin/upload-license'

		license = {}
		if confirmInternalLicense:
			license["confirmInternalLicense"] = f"{confirmInternalLicense}"
		if licenseBlob:
			license["licenseBlob"] = f"{licenseBlob}"

		return fortiedr_connection.insert(url, license)

class Audit:
	'''The Audit module enables you to retrieve system audit based on given dates'''

	def get_audit(self, fromTime: str = None, organization: str = None, toTime: str = None) -> tuple[bool, list]:
		'''
		Class Audit
		Description: This API retrieve the audit between 2 dates.
        
		Args:
			fromTime (str): Retrieves audit that were written after the given date. Date Format: yyyy-MM-dd (Default is current date)
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			toTime (str): Retrieves audit that were written before the given date. Date Format: yyyy-MM-dd (Default is current date)

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("get_audit", locals())

		url = '/management-rest/audit/get-audit'
		url_params = []
		if fromTime != None:
			url_params.append(f'fromTime={fromTime}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if toTime != None:
			url_params.append(f'toTime={toTime}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

class CommunicationControl:
	'''Fortinet Endpoint Protection and Response Platform’s Communication Control module is responsible for monitoring and handling non-disguised security events. The module uses a set of policies that contain recommendations about whether an application should be approved or denied from communicating outside your organization.'''

	def assign_collector_group(self, collectorGroups: list, organization: str, policyName: str, forceAssign: bool = None) -> tuple[bool, None]:
		'''
		Class CommunicationControl
		Description: Assign collector group to application policy.
        
		Args:
			collectorGroups (list):  Specifies the collector groups whose collector reported the events
			forceAssign (bool): Indicates whether to force the assignment even if the group is assigned to similar policies
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			policyName (str): Specifies the list of policies

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("assign_collector_group", locals())

		url = '/management-rest/comm-control/assign-collector-group'
		url_params = []
		if collectorGroups != None:
			collectorGroups = ",".join(collectorGroups) if isinstance(collectorGroups, list) else collectorGroups
			url_params.append(f'collectorGroups={collectorGroups}')
		if forceAssign != None:
			url_params.append(f'forceAssign={forceAssign}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if policyName != None:
			url_params.append(f'policyName={policyName}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def clone_policy(self, newPolicyName: str, organization: str, sourcePolicyName: str) -> tuple[bool, list]:
		'''
		Class CommunicationControl
		Description: application clone policy.
        
		Args:
			newPolicyName (str): Specifies security policy target name.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			sourcePolicyName (str): Specifies security policy source name

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("clone_policy", locals())

		url = '/management-rest/comm-control/clone-policy'
		url_params = []
		if newPolicyName != None:
			url_params.append(f'newPolicyName={newPolicyName}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if sourcePolicyName != None:
			url_params.append(f'sourcePolicyName={sourcePolicyName}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.send(url)

	def list_policies(self, decisions: list, itemsPerPage: int = None, organization: str = None, pageNumber: int = None, policies: list = None, rules: list = None, sorting: str = None, sources: list = None, state: str = None, strictMode: bool = None) -> tuple[bool, list]:
		'''
		Class CommunicationControl
		Description: This API call outputs a list of all the communication control policies in the system, and information about each of them.
        
		Args:
			decisions (list): Indicates the action
			itemsPerPage (int): An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			pageNumber (int): An integer used for paging that indicates the required page number
			policies (list): Specifies the list of policy names
			rules (list): Specifies the list of rules
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on
			sources (list): Specifies who created the policy
			state (str): Policy rule state
			strictMode (bool): A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_policies", locals())

		url = '/management-rest/comm-control/list-policies'
		url_params = []
		if decisions != None:
			decisions = ",".join(decisions) if isinstance(decisions, list) else decisions
			url_params.append(f'decisions={decisions}')
		if itemsPerPage != None:
			url_params.append(f'itemsPerPage={itemsPerPage}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if pageNumber != None:
			url_params.append(f'pageNumber={pageNumber}')
		if policies != None:
			policies = ",".join(policies) if isinstance(policies, list) else policies
			url_params.append(f'policies={policies}')
		if rules != None:
			rules = ",".join(rules) if isinstance(rules, list) else rules
			url_params.append(f'rules={rules}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if sources != None:
			sources = ",".join(sources) if isinstance(sources, list) else sources
			url_params.append(f'sources={sources}')
		if state != None:
			url_params.append(f'state={state}')
		if strictMode != None:
			url_params.append(f'strictMode={strictMode}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def list_products(self, action: str = None, collectorGroups: list = None, cveIdentifier: str = None, destinationIp: list = None, devices: list = None, firstConnectionTimeEnd: str = None, firstConnectionTimeStart: str = None, handled: bool = None, includeStatistics: bool = None, ips: list = None, itemsPerPage: int = None, lastConnectionTimeEnd: str = None, lastConnectionTimeStart: str = None, organization: str = None, os: list = None, pageNumber: int = None, policies: list = None, processHash: str = None, processes: list = None, product: str = None, products: list = None, reputation: list = None, rule: str = None, rulePolicy: str = None, seen: bool = None, sorting: str = None, strictMode: bool = None, vendor: str = None, vendors: list = None, version: str = None, versions: list = None, vulnerabilities: list = None) -> tuple[bool, list]:
		'''
		Class CommunicationControl
		Description: This API call outputs a list of all the communicating applications in the system, and information about each of them.
        
		Args:
			action (str): Indicates the action: Allow/Deny. This parameter is irrelevant without policies parameter
			collectorGroups (list): Specifies the list of collector groups where the products were seen
			cveIdentifier (str): Specifies the CVE identifier
			destinationIp (list): Destination IPs
			devices (list): Specifies the list of device names where the products were seen
			firstConnectionTimeEnd (str):  Retrieves products whose first connection time is less than the value assigned to this date
			firstConnectionTimeStart (str):  Retrieves products whose first connection time is greater than the value assigned to this date
			handled (bool): A true/false parameter indicating whether events were handled/unhandled
			includeStatistics (bool): A true/false parameter indicating including statistics data
			ips (list): Specifies the list of IPs where the products were seen
			itemsPerPage (int): An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000
			lastConnectionTimeEnd (str):  Retrieves products whose last connection time is less than the value assigned to this date
			lastConnectionTimeStart (str):  Retrieves products whose last connection time is greater than the value assigned to this date
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			os (list): Specifies the list of operating system families where the products were seen
			pageNumber (int): An integer used for paging that indicates the required page number
			policies (list): Specifies the list of policy names whose products have a specific decision, as specified in the action parameter
			processHash (str): Specifies the process hash name
			processes (list): Specifies the list of process names running alongside the products
			product (str): Specifies a single value for the product name. By default, strictMode is false
			products (list): Specifies the list of product names. Names must match exactly (strictMode is always true)
			reputation (list): Specifies the recommendation of the application: Unknown, Known bad, Assumed bad, Contradiction, Assumed good or Known good
			rule (str): Indicates the rule. This parameter is irrelevant without rulePolicy parameter
			rulePolicy (str): Specifies the policy name whose products have a specific rule, as specified in the rule parameter
			seen (bool): A true/false parameter indicating whether events were read/unread by the user operating the API
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on
			strictMode (bool): A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False
			vendor (str): Specifies a single value for the vendor name. By default, strictMode is false
			vendors (list): Specifies the list of vendor names. Names must match exactly (strictMode is always true)
			version (str): Specifies a single value for the version name. By default, strictMode is false
			versions (list): Specifies the list of versions. Names must match exactly (strictMode is always true)
			vulnerabilities (list): Specifies the list of vulnerabilities where the products were seen

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_products", locals())

		url = '/management-rest/comm-control/list-products'
		url_params = []
		if action != None:
			url_params.append(f'action={action}')
		if collectorGroups != None:
			collectorGroups = ",".join(collectorGroups) if isinstance(collectorGroups, list) else collectorGroups
			url_params.append(f'collectorGroups={collectorGroups}')
		if cveIdentifier != None:
			url_params.append(f'cveIdentifier={cveIdentifier}')
		if destinationIp != None:
			destinationIp = ",".join(destinationIp) if isinstance(destinationIp, list) else destinationIp
			url_params.append(f'destinationIp={destinationIp}')
		if devices != None:
			devices = ",".join(devices) if isinstance(devices, list) else devices
			url_params.append(f'devices={devices}')
		if firstConnectionTimeEnd != None:
			url_params.append(f'firstConnectionTimeEnd={firstConnectionTimeEnd}')
		if firstConnectionTimeStart != None:
			url_params.append(f'firstConnectionTimeStart={firstConnectionTimeStart}')
		if handled != None:
			url_params.append(f'handled={handled}')
		if includeStatistics != None:
			url_params.append(f'includeStatistics={includeStatistics}')
		if ips != None:
			ips = ",".join(ips) if isinstance(ips, list) else ips
			url_params.append(f'ips={ips}')
		if itemsPerPage != None:
			url_params.append(f'itemsPerPage={itemsPerPage}')
		if lastConnectionTimeEnd != None:
			url_params.append(f'lastConnectionTimeEnd={lastConnectionTimeEnd}')
		if lastConnectionTimeStart != None:
			url_params.append(f'lastConnectionTimeStart={lastConnectionTimeStart}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if os != None:
			os = ",".join(os) if isinstance(os, list) else os
			url_params.append(f'os={os}')
		if pageNumber != None:
			url_params.append(f'pageNumber={pageNumber}')
		if policies != None:
			policies = ",".join(policies) if isinstance(policies, list) else policies
			url_params.append(f'policies={policies}')
		if processHash != None:
			url_params.append(f'processHash={processHash}')
		if processes != None:
			processes = ",".join(processes) if isinstance(processes, list) else processes
			url_params.append(f'processes={processes}')
		if product != None:
			url_params.append(f'product={product}')
		if products != None:
			products = ",".join(products) if isinstance(products, list) else products
			url_params.append(f'products={products}')
		if reputation != None:
			reputation = ",".join(reputation) if isinstance(reputation, list) else reputation
			url_params.append(f'reputation={reputation}')
		if rule != None:
			url_params.append(f'rule={rule}')
		if rulePolicy != None:
			url_params.append(f'rulePolicy={rulePolicy}')
		if seen != None:
			url_params.append(f'seen={seen}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if strictMode != None:
			url_params.append(f'strictMode={strictMode}')
		if vendor != None:
			url_params.append(f'vendor={vendor}')
		if vendors != None:
			vendors = ",".join(vendors) if isinstance(vendors, list) else vendors
			url_params.append(f'vendors={vendors}')
		if version != None:
			url_params.append(f'version={version}')
		if versions != None:
			versions = ",".join(versions) if isinstance(versions, list) else versions
			url_params.append(f'versions={versions}')
		if vulnerabilities != None:
			vulnerabilities = ",".join(vulnerabilities) if isinstance(vulnerabilities, list) else vulnerabilities
			url_params.append(f'vulnerabilities={vulnerabilities}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def resolve_applications(self, organization: str, applyNested: bool = None, comment: str = None, products: list = None, resolve: bool = None, signed: bool = None, vendors: list = None, versions: list = None) -> tuple[bool, None]:
		'''
		Class CommunicationControl
		Description: Enable resolving/unresolving applications.
        
		Args:
			applyNested (bool): A true/false parameter indicating updating inherited
			comment (str): Specifies a user-defined string to attach to the policy
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			products (list): Specifies the list of product names. Names must match exactly (strictMode is always true)
			resolve (bool): A true/false parameter indicating update the application resolve/unresolve
			signed (bool): A true/false parameter indicating if the policy is signed
			vendors (list): Specifies the list of vendor names. Names must match exactly (strictMode is always true)
			versions (list): Specifies the list of versions. Names must match exactly (strictMode is always true)

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("resolve_applications", locals())

		url = '/management-rest/comm-control/resolve-applications'
		url_params = []
		if applyNested != None:
			url_params.append(f'applyNested={applyNested}')
		if comment != None:
			url_params.append(f'comment={comment}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if products != None:
			products = ",".join(products) if isinstance(products, list) else products
			url_params.append(f'products={products}')
		if resolve != None:
			url_params.append(f'resolve={resolve}')
		if signed != None:
			url_params.append(f'signed={signed}')
		if vendors != None:
			vendors = ",".join(vendors) if isinstance(vendors, list) else vendors
			url_params.append(f'vendors={vendors}')
		if versions != None:
			versions = ",".join(versions) if isinstance(versions, list) else versions
			url_params.append(f'versions={versions}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def set_policy_mode(self, mode: str, organization: str, policyNames: list) -> tuple[bool, None]:
		'''
		Class CommunicationControl
		Description: Set policy to simulation/prevention.
        
		Args:
			mode (str): Operation mode
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			policyNames (list): Specifies the list of policies

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("set_policy_mode", locals())

		url = '/management-rest/comm-control/set-policy-mode'
		url_params = []
		if mode != None:
			url_params.append(f'mode={mode}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if policyNames != None:
			policyNames = ",".join(policyNames) if isinstance(policyNames, list) else policyNames
			url_params.append(f'policyNames={policyNames}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def set_policy_permission(self, decision: str, organization: str, policies: list, applyNested: bool = None, products: list = None, signed: bool = None, vendors: list = None, versions: list = None) -> tuple[bool, None]:
		'''
		Class CommunicationControl
		Description: Set the application allow/deny.
        
		Args:
			applyNested (bool): A true/false parameter indicating updating inherited
			decision (str): Indicates the action
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			policies (list): Specifies the list of policies names
			products (list): Specifies the list of product names. Names must match exactly (strictMode is always true)
			signed (bool): A true/false parameter indicating if the policy is signed
			vendors (list): Specifies the list of vendor names. Names must match exactly (strictMode is always true)
			versions (list): Specifies the list of versions. Names must match exactly (strictMode is always true)

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("set_policy_permission", locals())

		url = '/management-rest/comm-control/set-policy-permission'
		url_params = []
		if applyNested != None:
			url_params.append(f'applyNested={applyNested}')
		if decision != None:
			url_params.append(f'decision={decision}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if policies != None:
			policies = ",".join(policies) if isinstance(policies, list) else policies
			url_params.append(f'policies={policies}')
		if products != None:
			products = ",".join(products) if isinstance(products, list) else products
			url_params.append(f'products={products}')
		if signed != None:
			url_params.append(f'signed={signed}')
		if vendors != None:
			vendors = ",".join(vendors) if isinstance(vendors, list) else vendors
			url_params.append(f'vendors={vendors}')
		if versions != None:
			versions = ",".join(versions) if isinstance(versions, list) else versions
			url_params.append(f'versions={versions}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def set_policy_rule_state(self, organization: str, policyName: str, ruleName: str, state: str) -> tuple[bool, None]:
		'''
		Class CommunicationControl
		Description: Set rule in policy to enable/disable.
        
		Args:
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			policyName (str): Specifies policy name
			ruleName (str): Specifies rule name
			state (str): Policy rule state

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("set_policy_rule_state", locals())

		url = '/management-rest/comm-control/set-policy-rule-state'
		url_params = []
		if organization != None:
			url_params.append(f'organization={organization}')
		if policyName != None:
			url_params.append(f'policyName={policyName}')
		if ruleName != None:
			url_params.append(f'ruleName={ruleName}')
		if state != None:
			url_params.append(f'state={state}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

class Events:
	'''This API call outputs all the events in the system that match the condition(s) you specify in the call. An AND relationship exists when specifying multiple input parameters. When no input parameters are matched, an empty result set is returned'''

	def insert_events(self, actions: list = None, applicationControl: bool = None, archived: bool = None, classifications: list = None, collectorGroups: list = None, collectorIds: list = None, destinations: list = None, device: str = None, deviceControl: bool = None, deviceIps: list = None, eventIds: list = None, eventType: list = None, expired: bool = None, fileHash: str = None, firstSeen: str = None, firstSeenFrom: str = None, firstSeenTo: str = None, handled: bool = None, itemsPerPage: int = None, lastSeen: str = None, lastSeenFrom: str = None, lastSeenTo: str = None, loggedUser: str = None, macAddresses: list = None, muted: bool = None, operatingSystems: list = None, organization: str = None, pageNumber: int = None, paths: list = None, process: str = None, rule: str = None, seen: bool = None, severities: list = None, signed: bool = None, sorting: str = None, strictMode: bool = None, archive: bool = None, classification: str = None, comment: str = None, familyName: str = None, forceUnmute: bool = None, handle: bool = None, malwareType: str = None, mute: bool = None, muteDuration: str = None, read: bool = None, threatName: str = None) -> tuple[bool, None]:
		'''
		Class Events
		Description: This API call updates the handled/unhandled state of an event. The output of this call is a message indicating whether the update succeeded or failed.
        
		Args:
			actions (list): Specifies the action of the event
			applicationControl (bool): A true/false parameter indicating whether to include only application control events
			archived (bool): A true/false parameter indicating whether to include only archived events
			classifications (list): Specifies the classification of the event
			collectorGroups (list): Specifies the collector groups whose collector reported the events
			collectorIds (list): Specifies the collectorIds where the events occurred
			destinations (list): Specifies the connection destination(s) of the events
			device (str): Specifies the device name where the events occurred
			deviceControl (bool): A true/false parameter indicating whether to include only device control events
			deviceIps (list): Specifies the IPs of the devices where the event occurred
			eventIds (list): Specifies the required event IDs
			eventType (list): Specifies the type of the event
			expired (bool): A true/false parameter indicating whether to include only expired events
			fileHash (str): Specifies the hash signature of the main process of the event
			firstSeen (str):  Specifies the date when the event was first seen (Deprecated)
			firstSeenFrom (str): Specifies the from date when the event was first seen
			firstSeenTo (str): Specifies the to date when the event was first seen
			handled (bool):  A true/false parameter indicating whether events were handled/unhandled
			itemsPerPage (int): An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000
			lastSeen (str):  Specifies the date when the event was last seen (Deprecated)
			lastSeenFrom (str): Specifies the from date when the event was last seen
			lastSeenTo (str): Specifies the to date when the event was last seen
			loggedUser (str): Specifies the logged user
			macAddresses (list): Specifies the mac addresses where the event occurred
			muted (bool): A true/false parameter indicating if the event is muted
			operatingSystems (list): Specifies the operating system of the devices where the events occurred
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			pageNumber (int): An integer used for paging that indicates the required page number
			paths (list): Specifies the paths of the processes related to the event
			process (str): Specifies the main process of the event
			rule (str): Specifies the short rule name of the rule that triggered the events
			seen (bool): A true/false parameter indicating whether events were read/unread by the user operating the API
			severities (list): Specifies the severity of the event (Deprecated)
			signed (bool): A true/false parameter indicating if the event is signed
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on
			strictMode (bool): A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False
			updateEventsRequest (Object): Check 'updateEventsRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("insert_events", locals())

		url = '/management-rest/events'
		url_params = []
		if actions != None:
			actions = ",".join(actions) if isinstance(actions, list) else actions
			url_params.append(f'actions={actions}')
		if applicationControl != None:
			url_params.append(f'applicationControl={applicationControl}')
		if archived != None:
			url_params.append(f'archived={archived}')
		if classifications != None:
			classifications = ",".join(classifications) if isinstance(classifications, list) else classifications
			url_params.append(f'classifications={classifications}')
		if collectorGroups != None:
			collectorGroups = ",".join(collectorGroups) if isinstance(collectorGroups, list) else collectorGroups
			url_params.append(f'collectorGroups={collectorGroups}')
		if collectorIds != None:
			collectorIds = ",".join(map(str, collectorIds)) if isinstance(collectorIds, list) else collectorIds
			url_params.append(f'collectorIds={collectorIds}')
		if destinations != None:
			destinations = ",".join(destinations) if isinstance(destinations, list) else destinations
			url_params.append(f'destinations={destinations}')
		if device != None:
			url_params.append(f'device={device}')
		if deviceControl != None:
			url_params.append(f'deviceControl={deviceControl}')
		if deviceIps != None:
			deviceIps = ",".join(deviceIps) if isinstance(deviceIps, list) else deviceIps
			url_params.append(f'deviceIps={deviceIps}')
		if eventIds != None:
			eventIds = ",".join(map(str, eventIds)) if isinstance(eventIds, list) else eventIds
			url_params.append(f'eventIds={eventIds}')
		if eventType != None:
			eventType = ",".join(eventType) if isinstance(eventType, list) else eventType
			url_params.append(f'eventType={eventType}')
		if expired != None:
			url_params.append(f'expired={expired}')
		if fileHash != None:
			url_params.append(f'fileHash={fileHash}')
		if firstSeen != None:
			url_params.append(f'firstSeen={firstSeen}')
		if firstSeenFrom != None:
			url_params.append(f'firstSeenFrom={firstSeenFrom}')
		if firstSeenTo != None:
			url_params.append(f'firstSeenTo={firstSeenTo}')
		if handled != None:
			url_params.append(f'handled={handled}')
		if itemsPerPage != None:
			url_params.append(f'itemsPerPage={itemsPerPage}')
		if lastSeen != None:
			url_params.append(f'lastSeen={lastSeen}')
		if lastSeenFrom != None:
			url_params.append(f'lastSeenFrom={lastSeenFrom}')
		if lastSeenTo != None:
			url_params.append(f'lastSeenTo={lastSeenTo}')
		if loggedUser != None:
			url_params.append(f'loggedUser={loggedUser}')
		if macAddresses != None:
			macAddresses = ",".join(macAddresses) if isinstance(macAddresses, list) else macAddresses
			url_params.append(f'macAddresses={macAddresses}')
		if muted != None:
			url_params.append(f'muted={muted}')
		if operatingSystems != None:
			operatingSystems = ",".join(operatingSystems) if isinstance(operatingSystems, list) else operatingSystems
			url_params.append(f'operatingSystems={operatingSystems}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if pageNumber != None:
			url_params.append(f'pageNumber={pageNumber}')
		if paths != None:
			paths = ",".join(paths) if isinstance(paths, list) else paths
			url_params.append(f'paths={paths}')
		if process != None:
			url_params.append(f'process={process}')
		if rule != None:
			url_params.append(f'rule={rule}')
		if seen != None:
			url_params.append(f'seen={seen}')
		if severities != None:
			severities = ",".join(severities) if isinstance(severities, list) else severities
			url_params.append(f'severities={severities}')
		if signed != None:
			url_params.append(f'signed={signed}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if strictMode != None:
			url_params.append(f'strictMode={strictMode}')
		url += '?' + '&'.join(url_params)

		updateEventsRequest = {}
		if archive:
			updateEventsRequest["archive"] = f"{archive}"
		if classification:
			updateEventsRequest["classification"] = f"{classification}"
		if comment:
			updateEventsRequest["comment"] = f"{comment}"
		if familyName:
			updateEventsRequest["familyName"] = f"{familyName}"
		if forceUnmute:
			updateEventsRequest["forceUnmute"] = f"{forceUnmute}"
		if handle:
			updateEventsRequest["handle"] = f"{handle}"
		if malwareType:
			updateEventsRequest["malwareType"] = f"{malwareType}"
		if mute:
			updateEventsRequest["mute"] = f"{mute}"
		if muteDuration:
			updateEventsRequest["muteDuration"] = f"{muteDuration}"
		if read:
			updateEventsRequest["read"] = f"{read}"
		if threatName:
			updateEventsRequest["threatName"] = f"{threatName}"

		return fortiedr_connection.insert(url, updateEventsRequest)

	def delete_events(self, actions: list = None, applicationControl: bool = None, archived: bool = None, classifications: list = None, collectorGroups: list = None, collectorIds: list = None, deleteAll: bool = None, destinations: list = None, device: str = None, deviceControl: bool = None, deviceIps: list = None, eventIds: list = None, eventType: list = None, expired: bool = None, fileHash: str = None, firstSeen: str = None, firstSeenFrom: str = None, firstSeenTo: str = None, handled: bool = None, itemsPerPage: int = None, lastSeen: str = None, lastSeenFrom: str = None, lastSeenTo: str = None, loggedUser: str = None, macAddresses: list = None, muted: bool = None, operatingSystems: list = None, organization: str = None, pageNumber: int = None, paths: list = None, process: str = None, rule: str = None, seen: bool = None, severities: list = None, signed: bool = None, sorting: str = None, strictMode: bool = None) -> tuple[bool, None]:
		'''
		Class Events
		Description: This API call delete events.
        
		Args:
			actions (list): Specifies the action of the event
			applicationControl (bool): A true/false parameter indicating whether to include only application control events
			archived (bool): A true/false parameter indicating whether to include only archived events
			classifications (list): Specifies the classification of the event
			collectorGroups (list): Specifies the collector groups whose collector reported the events
			collectorIds (list): Specifies the collectorIds where the events occurred
			deleteAll (bool): A true/false parameter indicating if all events should be deleted
			destinations (list): Specifies the connection destination(s) of the events
			device (str): Specifies the device name where the events occurred
			deviceControl (bool): A true/false parameter indicating whether to include only device control events
			deviceIps (list): Specifies the IPs of the devices where the event occurred
			eventIds (list): Specifies the required event IDs
			eventType (list): Specifies the type of the event
			expired (bool): A true/false parameter indicating whether to include only expired events
			fileHash (str): Specifies the hash signature of the main process of the event
			firstSeen (str):  Specifies the date when the event was first seen (Deprecated)
			firstSeenFrom (str): Specifies the from date when the event was first seen
			firstSeenTo (str): Specifies the to date when the event was first seen
			handled (bool):  A true/false parameter indicating whether events were handled/unhandled
			itemsPerPage (int): An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000
			lastSeen (str):  Specifies the date when the event was last seen (Deprecated)
			lastSeenFrom (str): Specifies the from date when the event was last seen
			lastSeenTo (str): Specifies the to date when the event was last seen
			loggedUser (str): Specifies the logged user
			macAddresses (list): Specifies the mac addresses where the event occurred
			muted (bool): A true/false parameter indicating if the event is muted
			operatingSystems (list): Specifies the operating system of the devices where the events occurred
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			pageNumber (int): An integer used for paging that indicates the required page number
			paths (list): Specifies the paths of the processes related to the event
			process (str): Specifies the main process of the event
			rule (str): Specifies the short rule name of the rule that triggered the events
			seen (bool): A true/false parameter indicating whether events were read/unread by the user operating the API
			severities (list): Specifies the severity of the event (Deprecated)
			signed (bool): A true/false parameter indicating if the event is signed
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on
			strictMode (bool): A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_events", locals())

		url = '/management-rest/events'
		url_params = []
		if actions != None:
			actions = ",".join(actions) if isinstance(actions, list) else actions
			url_params.append(f'actions={actions}')
		if applicationControl != None:
			url_params.append(f'applicationControl={applicationControl}')
		if archived != None:
			url_params.append(f'archived={archived}')
		if classifications != None:
			classifications = ",".join(classifications) if isinstance(classifications, list) else classifications
			url_params.append(f'classifications={classifications}')
		if collectorGroups != None:
			collectorGroups = ",".join(collectorGroups) if isinstance(collectorGroups, list) else collectorGroups
			url_params.append(f'collectorGroups={collectorGroups}')
		if collectorIds != None:
			collectorIds = ",".join(map(str, collectorIds)) if isinstance(collectorIds, list) else collectorIds
			url_params.append(f'collectorIds={collectorIds}')
		if deleteAll != None:
			url_params.append(f'deleteAll={deleteAll}')
		if destinations != None:
			destinations = ",".join(destinations) if isinstance(destinations, list) else destinations
			url_params.append(f'destinations={destinations}')
		if device != None:
			url_params.append(f'device={device}')
		if deviceControl != None:
			url_params.append(f'deviceControl={deviceControl}')
		if deviceIps != None:
			deviceIps = ",".join(deviceIps) if isinstance(deviceIps, list) else deviceIps
			url_params.append(f'deviceIps={deviceIps}')
		if eventIds != None:
			eventIds = ",".join(map(str, eventIds)) if isinstance(eventIds, list) else eventIds
			url_params.append(f'eventIds={eventIds}')
		if eventType != None:
			eventType = ",".join(eventType) if isinstance(eventType, list) else eventType
			url_params.append(f'eventType={eventType}')
		if expired != None:
			url_params.append(f'expired={expired}')
		if fileHash != None:
			url_params.append(f'fileHash={fileHash}')
		if firstSeen != None:
			url_params.append(f'firstSeen={firstSeen}')
		if firstSeenFrom != None:
			url_params.append(f'firstSeenFrom={firstSeenFrom}')
		if firstSeenTo != None:
			url_params.append(f'firstSeenTo={firstSeenTo}')
		if handled != None:
			url_params.append(f'handled={handled}')
		if itemsPerPage != None:
			url_params.append(f'itemsPerPage={itemsPerPage}')
		if lastSeen != None:
			url_params.append(f'lastSeen={lastSeen}')
		if lastSeenFrom != None:
			url_params.append(f'lastSeenFrom={lastSeenFrom}')
		if lastSeenTo != None:
			url_params.append(f'lastSeenTo={lastSeenTo}')
		if loggedUser != None:
			url_params.append(f'loggedUser={loggedUser}')
		if macAddresses != None:
			macAddresses = ",".join(macAddresses) if isinstance(macAddresses, list) else macAddresses
			url_params.append(f'macAddresses={macAddresses}')
		if muted != None:
			url_params.append(f'muted={muted}')
		if operatingSystems != None:
			operatingSystems = ",".join(operatingSystems) if isinstance(operatingSystems, list) else operatingSystems
			url_params.append(f'operatingSystems={operatingSystems}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if pageNumber != None:
			url_params.append(f'pageNumber={pageNumber}')
		if paths != None:
			paths = ",".join(paths) if isinstance(paths, list) else paths
			url_params.append(f'paths={paths}')
		if process != None:
			url_params.append(f'process={process}')
		if rule != None:
			url_params.append(f'rule={rule}')
		if seen != None:
			url_params.append(f'seen={seen}')
		if severities != None:
			severities = ",".join(severities) if isinstance(severities, list) else severities
			url_params.append(f'severities={severities}')
		if signed != None:
			url_params.append(f'signed={signed}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if strictMode != None:
			url_params.append(f'strictMode={strictMode}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def count_events(self, actions: list = None, applicationControl: bool = None, archived: bool = None, classifications: list = None, collectorGroups: list = None, collectorIds: list = None, destinations: list = None, device: str = None, deviceControl: bool = None, deviceIps: list = None, eventIds: list = None, eventType: list = None, expired: bool = None, fileHash: str = None, firstSeen: str = None, firstSeenFrom: str = None, firstSeenTo: str = None, handled: bool = None, itemsPerPage: int = None, lastSeen: str = None, lastSeenFrom: str = None, lastSeenTo: str = None, loggedUser: str = None, macAddresses: list = None, muted: bool = None, operatingSystems: list = None, organization: str = None, pageNumber: int = None, paths: list = None, process: str = None, rule: str = None, seen: bool = None, severities: list = None, signed: bool = None, sorting: str = None, strictMode: bool = None) -> tuple[bool, int]:
		'''
		Class Events
		Description: Count Events.
        
		Args:
			actions (list): Specifies the action of the event
			applicationControl (bool): A true/false parameter indicating whether to include only application control events
			archived (bool): A true/false parameter indicating whether to include only archived events
			classifications (list): Specifies the classification of the event
			collectorGroups (list): Specifies the collector groups whose collector reported the events
			collectorIds (list): Specifies the collectorIds where the events occurred
			destinations (list): Specifies the connection destination(s) of the events
			device (str): Specifies the device name where the events occurred
			deviceControl (bool): A true/false parameter indicating whether to include only device control events
			deviceIps (list): Specifies the IPs of the devices where the event occurred
			eventIds (list): Specifies the required event IDs
			eventType (list): Specifies the type of the event
			expired (bool): A true/false parameter indicating whether to include only expired events
			fileHash (str): Specifies the hash signature of the main process of the event
			firstSeen (str):  Specifies the date when the event was first seen (Deprecated)
			firstSeenFrom (str): Specifies the from date when the event was first seen
			firstSeenTo (str): Specifies the to date when the event was first seen
			handled (bool):  A true/false parameter indicating whether events were handled/unhandled
			itemsPerPage (int): An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000
			lastSeen (str):  Specifies the date when the event was last seen (Deprecated)
			lastSeenFrom (str): Specifies the from date when the event was last seen
			lastSeenTo (str): Specifies the to date when the event was last seen
			loggedUser (str): Specifies the logged user
			macAddresses (list): Specifies the mac addresses where the event occurred
			muted (bool): A true/false parameter indicating if the event is muted
			operatingSystems (list): Specifies the operating system of the devices where the events occurred
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			pageNumber (int): An integer used for paging that indicates the required page number
			paths (list): Specifies the paths of the processes related to the event
			process (str): Specifies the main process of the event
			rule (str): Specifies the short rule name of the rule that triggered the events
			seen (bool): A true/false parameter indicating whether events were read/unread by the user operating the API
			severities (list): Specifies the severity of the event (Deprecated)
			signed (bool): A true/false parameter indicating if the event is signed
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on
			strictMode (bool): A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False

		Returns:
			bool: Status of the request (True or False). 
			int
		'''
		validate_params("count_events", locals())

		url = '/management-rest/events/count-events'
		url_params = []
		if actions != None:
			actions = ",".join(actions) if isinstance(actions, list) else actions
			url_params.append(f'actions={actions}')
		if applicationControl != None:
			url_params.append(f'applicationControl={applicationControl}')
		if archived != None:
			url_params.append(f'archived={archived}')
		if classifications != None:
			classifications = ",".join(classifications) if isinstance(classifications, list) else classifications
			url_params.append(f'classifications={classifications}')
		if collectorGroups != None:
			collectorGroups = ",".join(collectorGroups) if isinstance(collectorGroups, list) else collectorGroups
			url_params.append(f'collectorGroups={collectorGroups}')
		if collectorIds != None:
			collectorIds = ",".join(map(str, collectorIds)) if isinstance(collectorIds, list) else collectorIds
			url_params.append(f'collectorIds={collectorIds}')
		if destinations != None:
			destinations = ",".join(destinations) if isinstance(destinations, list) else destinations
			url_params.append(f'destinations={destinations}')
		if device != None:
			url_params.append(f'device={device}')
		if deviceControl != None:
			url_params.append(f'deviceControl={deviceControl}')
		if deviceIps != None:
			deviceIps = ",".join(deviceIps) if isinstance(deviceIps, list) else deviceIps
			url_params.append(f'deviceIps={deviceIps}')
		if eventIds != None:
			eventIds = ",".join(map(str, eventIds)) if isinstance(eventIds, list) else eventIds
			url_params.append(f'eventIds={eventIds}')
		if eventType != None:
			eventType = ",".join(eventType) if isinstance(eventType, list) else eventType
			url_params.append(f'eventType={eventType}')
		if expired != None:
			url_params.append(f'expired={expired}')
		if fileHash != None:
			url_params.append(f'fileHash={fileHash}')
		if firstSeen != None:
			url_params.append(f'firstSeen={firstSeen}')
		if firstSeenFrom != None:
			url_params.append(f'firstSeenFrom={firstSeenFrom}')
		if firstSeenTo != None:
			url_params.append(f'firstSeenTo={firstSeenTo}')
		if handled != None:
			url_params.append(f'handled={handled}')
		if itemsPerPage != None:
			url_params.append(f'itemsPerPage={itemsPerPage}')
		if lastSeen != None:
			url_params.append(f'lastSeen={lastSeen}')
		if lastSeenFrom != None:
			url_params.append(f'lastSeenFrom={lastSeenFrom}')
		if lastSeenTo != None:
			url_params.append(f'lastSeenTo={lastSeenTo}')
		if loggedUser != None:
			url_params.append(f'loggedUser={loggedUser}')
		if macAddresses != None:
			macAddresses = ",".join(macAddresses) if isinstance(macAddresses, list) else macAddresses
			url_params.append(f'macAddresses={macAddresses}')
		if muted != None:
			url_params.append(f'muted={muted}')
		if operatingSystems != None:
			operatingSystems = ",".join(operatingSystems) if isinstance(operatingSystems, list) else operatingSystems
			url_params.append(f'operatingSystems={operatingSystems}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if pageNumber != None:
			url_params.append(f'pageNumber={pageNumber}')
		if paths != None:
			paths = ",".join(paths) if isinstance(paths, list) else paths
			url_params.append(f'paths={paths}')
		if process != None:
			url_params.append(f'process={process}')
		if rule != None:
			url_params.append(f'rule={rule}')
		if seen != None:
			url_params.append(f'seen={seen}')
		if severities != None:
			severities = ",".join(severities) if isinstance(severities, list) else severities
			url_params.append(f'severities={severities}')
		if signed != None:
			url_params.append(f'signed={signed}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if strictMode != None:
			url_params.append(f'strictMode={strictMode}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def create_exception(self, organization: str, allCollectorGroups: bool = None, allDestinations: bool = None, allOrganizations: bool = None, allUsers: bool = None, collectorGroups: list = None, comment: str = None, destinations: list = None, eventId: int = None, exceptionId: int = None, forceCreate: bool = None, isHidden: bool = None, useAnyPath: object = None, useCommandLine: object = None, useInException: object = None, wildcardFiles: object = None, wildcardPaths: object = None, users: list = None) -> tuple[bool, str]:
		'''
		Class Events
		Description: This API call adds an exception to a specific event. The output of this call is a message indicating whether the creation of the exception .
        
		Args:
			allCollectorGroups (bool): A true/false parameter indicating whether the exception should be applied to all collector groups. When not used, all collector groups are selected
			allDestinations (bool): A true/false parameter indicating whether the exception should be applied to all destinations. When not used, all destinations are selected
			allOrganizations (bool): A true/false parameter indicating whether the exception should be applied to all the organizations (tenants). This parameter is only relevant in multi-tenancy environment. This parameter is only allowed for user with Hoster privilege (general admin)
			allUsers (bool): A true/false parameter indicating whether the exception should be applied to all users. When not used, all users are selected
			collectorGroups (list): Specifies the list of all the collector groups to which the exception should be applied. When not used, all collector groups are selected
			comment (str): Specifies a user-defined string to attach to the exception
			destinations (list): A list of IPs to which the exception applies and/or the value all internal destinations
			eventId (int): Specifies the event ID on which to create the exception
			exceptionId (int): Specifies the exception ID to edit
			forceCreate (bool): A true/false parameter indicating whether to create the exception, even if there are already exceptions that cover this given event
			isHidden (bool): A true/false parameter indicating whether the event is hidden
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			updateExceptionAlertsRequest (Object): Check 'updateExceptionAlertsRequest' in the API documentation for further information.
			users (list): A list of users to which the exception

		Returns:
			bool: Status of the request (True or False). 
			str
		'''
		validate_params("create_exception", locals())

		url = '/management-rest/events/create-exception'
		url_params = []
		if allCollectorGroups != None:
			url_params.append(f'allCollectorGroups={allCollectorGroups}')
		if allDestinations != None:
			url_params.append(f'allDestinations={allDestinations}')
		if allOrganizations != None:
			url_params.append(f'allOrganizations={allOrganizations}')
		if allUsers != None:
			url_params.append(f'allUsers={allUsers}')
		if collectorGroups != None:
			collectorGroups = ",".join(collectorGroups) if isinstance(collectorGroups, list) else collectorGroups
			url_params.append(f'collectorGroups={collectorGroups}')
		if comment != None:
			url_params.append(f'comment={comment}')
		if destinations != None:
			destinations = ",".join(destinations) if isinstance(destinations, list) else destinations
			url_params.append(f'destinations={destinations}')
		if eventId != None:
			url_params.append(f'eventId={eventId}')
		if exceptionId != None:
			url_params.append(f'exceptionId={exceptionId}')
		if forceCreate != None:
			url_params.append(f'forceCreate={forceCreate}')
		if isHidden != None:
			url_params.append(f'isHidden={isHidden}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if users != None:
			users = ",".join(users) if isinstance(users, list) else users
			url_params.append(f'users={users}')
		url += '?' + '&'.join(url_params)

		updateExceptionAlertsRequest = {}
		if useAnyPath:
			updateExceptionAlertsRequest["useAnyPath"] = f"{useAnyPath}"
		if useCommandLine:
			updateExceptionAlertsRequest["useCommandLine"] = f"{useCommandLine}"
		if useInException:
			updateExceptionAlertsRequest["useInException"] = f"{useInException}"
		if wildcardFiles:
			updateExceptionAlertsRequest["wildcardFiles"] = f"{wildcardFiles}"
		if wildcardPaths:
			updateExceptionAlertsRequest["wildcardPaths"] = f"{wildcardPaths}"

		return fortiedr_connection.send(url, updateExceptionAlertsRequest)

	def export_raw_data_items_json(self, organization: str, rawItemIds: str = None, download_folder = None) -> tuple[bool, None]:
		'''
		Class Events
		Description: Get event as Json format.
        
		Args:
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			rawItemIds (str): Specifies the raw data item event IDs

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("export_raw_data_items_json", locals())

		url = '/management-rest/events/export-raw-data-items-json'
		url_params = []
		if organization != None:
			url_params.append(f'organization={organization}')
		if rawItemIds != None:
			url_params.append(f'rawItemIds={rawItemIds}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.download(url, download_folder=download_folder)

	def list_events(self, actions: list = None, applicationControl: bool = None, archived: bool = None, classifications: list = None, collectorGroups: list = None, collectorIds: list = None, destinations: list = None, device: str = None, deviceControl: bool = None, deviceIps: list = None, eventIds: list = None, eventType: list = None, expired: bool = None, fileHash: str = None, firstSeen: str = None, firstSeenFrom: str = None, firstSeenTo: str = None, handled: bool = None, itemsPerPage: int = None, lastSeen: str = None, lastSeenFrom: str = None, lastSeenTo: str = None, loggedUser: str = None, macAddresses: list = None, muted: bool = None, operatingSystems: list = None, organization: str = None, pageNumber: int = None, paths: list = None, process: str = None, rule: str = None, seen: bool = None, severities: list = None, signed: bool = None, sorting: str = None, strictMode: bool = None) -> tuple[bool, list]:
		'''
		Class Events
		Description: List Events.
        
		Args:
			actions (list): Specifies the action of the event
			applicationControl (bool): A true/false parameter indicating whether to include only application control events
			archived (bool): A true/false parameter indicating whether to include only archived events
			classifications (list): Specifies the classification of the event
			collectorGroups (list): Specifies the collector groups whose collector reported the events
			collectorIds (list): Specifies the collectorIds where the events occurred
			destinations (list): Specifies the connection destination(s) of the events
			device (str): Specifies the device name where the events occurred
			deviceControl (bool): A true/false parameter indicating whether to include only device control events
			deviceIps (list): Specifies the IPs of the devices where the event occurred
			eventIds (list): Specifies the required event IDs
			eventType (list): Specifies the type of the event
			expired (bool): A true/false parameter indicating whether to include only expired events
			fileHash (str): Specifies the hash signature of the main process of the event
			firstSeen (str):  Specifies the date when the event was first seen (Deprecated)
			firstSeenFrom (str): Specifies the from date when the event was first seen
			firstSeenTo (str): Specifies the to date when the event was first seen
			handled (bool):  A true/false parameter indicating whether events were handled/unhandled
			itemsPerPage (int): An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000
			lastSeen (str):  Specifies the date when the event was last seen (Deprecated)
			lastSeenFrom (str): Specifies the from date when the event was last seen
			lastSeenTo (str): Specifies the to date when the event was last seen
			loggedUser (str): Specifies the logged user
			macAddresses (list): Specifies the mac addresses where the event occurred
			muted (bool): A true/false parameter indicating if the event is muted
			operatingSystems (list): Specifies the operating system of the devices where the events occurred
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			pageNumber (int): An integer used for paging that indicates the required page number
			paths (list): Specifies the paths of the processes related to the event
			process (str): Specifies the main process of the event
			rule (str): Specifies the short rule name of the rule that triggered the events
			seen (bool): A true/false parameter indicating whether events were read/unread by the user operating the API
			severities (list): Specifies the severity of the event (Deprecated)
			signed (bool): A true/false parameter indicating if the event is signed
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on
			strictMode (bool): A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_events", locals())

		url = '/management-rest/events/list-events'
		url_params = []
		if actions != None:
			actions = ",".join(actions) if isinstance(actions, list) else actions
			url_params.append(f'actions={actions}')
		if applicationControl != None:
			url_params.append(f'applicationControl={applicationControl}')
		if archived != None:
			url_params.append(f'archived={archived}')
		if classifications != None:
			classifications = ",".join(classifications) if isinstance(classifications, list) else classifications
			url_params.append(f'classifications={classifications}')
		if collectorGroups != None:
			collectorGroups = ",".join(collectorGroups) if isinstance(collectorGroups, list) else collectorGroups
			url_params.append(f'collectorGroups={collectorGroups}')
		if collectorIds != None:
			collectorIds = ",".join(map(str, collectorIds)) if isinstance(collectorIds, list) else collectorIds
			url_params.append(f'collectorIds={collectorIds}')
		if destinations != None:
			destinations = ",".join(destinations) if isinstance(destinations, list) else destinations
			url_params.append(f'destinations={destinations}')
		if device != None:
			url_params.append(f'device={device}')
		if deviceControl != None:
			url_params.append(f'deviceControl={deviceControl}')
		if deviceIps != None:
			deviceIps = ",".join(deviceIps) if isinstance(deviceIps, list) else deviceIps
			url_params.append(f'deviceIps={deviceIps}')
		if eventIds != None:
			eventIds = ",".join(map(str, eventIds)) if isinstance(eventIds, list) else eventIds
			url_params.append(f'eventIds={eventIds}')
		if eventType != None:
			eventType = ",".join(eventType) if isinstance(eventType, list) else eventType
			url_params.append(f'eventType={eventType}')
		if expired != None:
			url_params.append(f'expired={expired}')
		if fileHash != None:
			url_params.append(f'fileHash={fileHash}')
		if firstSeen != None:
			url_params.append(f'firstSeen={firstSeen}')
		if firstSeenFrom != None:
			url_params.append(f'firstSeenFrom={firstSeenFrom}')
		if firstSeenTo != None:
			url_params.append(f'firstSeenTo={firstSeenTo}')
		if handled != None:
			url_params.append(f'handled={handled}')
		if itemsPerPage != None:
			url_params.append(f'itemsPerPage={itemsPerPage}')
		if lastSeen != None:
			url_params.append(f'lastSeen={lastSeen}')
		if lastSeenFrom != None:
			url_params.append(f'lastSeenFrom={lastSeenFrom}')
		if lastSeenTo != None:
			url_params.append(f'lastSeenTo={lastSeenTo}')
		if loggedUser != None:
			url_params.append(f'loggedUser={loggedUser}')
		if macAddresses != None:
			macAddresses = ",".join(macAddresses) if isinstance(macAddresses, list) else macAddresses
			url_params.append(f'macAddresses={macAddresses}')
		if muted != None:
			url_params.append(f'muted={muted}')
		if operatingSystems != None:
			operatingSystems = ",".join(operatingSystems) if isinstance(operatingSystems, list) else operatingSystems
			url_params.append(f'operatingSystems={operatingSystems}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if pageNumber != None:
			url_params.append(f'pageNumber={pageNumber}')
		if paths != None:
			paths = ",".join(paths) if isinstance(paths, list) else paths
			url_params.append(f'paths={paths}')
		if process != None:
			url_params.append(f'process={process}')
		if rule != None:
			url_params.append(f'rule={rule}')
		if seen != None:
			url_params.append(f'seen={seen}')
		if severities != None:
			severities = ",".join(severities) if isinstance(severities, list) else severities
			url_params.append(f'severities={severities}')
		if signed != None:
			url_params.append(f'signed={signed}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if strictMode != None:
			url_params.append(f'strictMode={strictMode}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def list_raw_data_items(self, eventId: int, collectorGroups: list = None, destinations: list = None, device: str = None, deviceIps: list = None, firstSeen: str = None, firstSeenFrom: str = None, firstSeenTo: str = None, fullDataRequested: bool = None, itemsPerPage: int = None, lastSeen: str = None, lastSeenFrom: str = None, lastSeenTo: str = None, loggedUser: str = None, organization: str = None, pageNumber: int = None, rawEventIds: list = None, sorting: str = None, strictMode: bool = None) -> tuple[bool, list]:
		'''
		Class Events
		Description: List raw data items.
        
		Args:
			collectorGroups (list): Specifies the collector groups whose collector reported the raw events
			destinations (list): Specifies the connection destination(s) of the events
			device (str): Specifies the name of the device where the raw event occurred
			deviceIps (list): Specifies the IPs of the devices where the event occurred
			eventId (int): Specifies the ID of the event that holds the raw data items
			firstSeen (str): Specifies the date when the raw data item was first seen (Deprecated)
			firstSeenFrom (str): Specifies the from date when the raw data item was first seen
			firstSeenTo (str): Specifies the to date when the raw data item was first seen
			fullDataRequested (bool): A true/false parameter indicating whether to include the event internal information
			itemsPerPage (int): An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000
			lastSeen (str): Specifies the date when the raw data item was last seen (Deprecated)
			lastSeenFrom (str): Specifies the from date when the raw data item was last seen
			lastSeenTo (str): Specifies the to date when the raw data item was last seen
			loggedUser (str): Specifies the logged user
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			pageNumber (int): An integer used for paging that indicates the required page number
			rawEventIds (list): Specifies the list of raw data item event IDs
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on
			strictMode (bool): A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_raw_data_items", locals())

		url = '/management-rest/events/list-raw-data-items'
		url_params = []
		if collectorGroups != None:
			collectorGroups = ",".join(collectorGroups) if isinstance(collectorGroups, list) else collectorGroups
			url_params.append(f'collectorGroups={collectorGroups}')
		if destinations != None:
			destinations = ",".join(destinations) if isinstance(destinations, list) else destinations
			url_params.append(f'destinations={destinations}')
		if device != None:
			url_params.append(f'device={device}')
		if deviceIps != None:
			deviceIps = ",".join(deviceIps) if isinstance(deviceIps, list) else deviceIps
			url_params.append(f'deviceIps={deviceIps}')
		if eventId != None:
			url_params.append(f'eventId={eventId}')
		if firstSeen != None:
			url_params.append(f'firstSeen={firstSeen}')
		if firstSeenFrom != None:
			url_params.append(f'firstSeenFrom={firstSeenFrom}')
		if firstSeenTo != None:
			url_params.append(f'firstSeenTo={firstSeenTo}')
		if fullDataRequested != None:
			url_params.append(f'fullDataRequested={fullDataRequested}')
		if itemsPerPage != None:
			url_params.append(f'itemsPerPage={itemsPerPage}')
		if lastSeen != None:
			url_params.append(f'lastSeen={lastSeen}')
		if lastSeenFrom != None:
			url_params.append(f'lastSeenFrom={lastSeenFrom}')
		if lastSeenTo != None:
			url_params.append(f'lastSeenTo={lastSeenTo}')
		if loggedUser != None:
			url_params.append(f'loggedUser={loggedUser}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if pageNumber != None:
			url_params.append(f'pageNumber={pageNumber}')
		if rawEventIds != None:
			rawEventIds = ",".join(map(str, rawEventIds)) if isinstance(rawEventIds, list) else rawEventIds
			url_params.append(f'rawEventIds={rawEventIds}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if strictMode != None:
			url_params.append(f'strictMode={strictMode}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

class Exceptions:
	'''This API call outputs all exceptions in the system'''

	def create_or_edit_exception(self, organization: str, confirmEdit: bool = None, exceptionJSON: str = None) -> tuple[bool, int]:
		'''
		Class Exceptions
		Description: This API call creates a new exception or updates an existing exception based on the given exception JSON body parameter.
        
		Args:
			confirmEdit (bool): Confirm editing an existing exception in case of providing an exception ID in the body JSON. By default confirmEdit is false
			exceptionJSON (str): exceptionJSON
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly

		Returns:
			bool: Status of the request (True or False). 
			int
		'''
		validate_params("create_or_edit_exception", locals())

		url = '/management-rest/exceptions/create-or-edit-exception'
		url_params = []
		if confirmEdit != None:
			url_params.append(f'confirmEdit={confirmEdit}')
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)


		return fortiedr_connection.send(url, exceptionJSON)

	def delete(self, collectorGroups: list = None, comment: str = None, createdAfter: str = None, createdBefore: str = None, deleteAll: bool = None, destination: str = None, exceptionId: int = None, exceptionIds: list = None, organization: str = None, path: str = None, process: str = None, rules: list = None, updatedAfter: str = None, updatedBefore: str = None, user: str = None) -> tuple[bool, None]:
		'''
		Class Exceptions
		Description: Delete exceptions.
        
		Args:
			collectorGroups (list): Specifies the list of all the collector groups to which the exception applied
			comment (str): Specifies a comment attach to the exception
			createdAfter (str): Specifies the date after which the exception was created. Specify the date using the yyyy-MM-dd HH:mm:ss format
			createdBefore (str): Specifies the date before which the exception was created. Specify the date using the yyyy-MM-dd HH:mm:ss format
			deleteAll (bool): A true/false parameter indicating if all exception should be deleted
			destination (str): Specifies a destination IP of the exception
			exceptionId (int): Specifies the required exception ID
			exceptionIds (list): Specifies a list of exception ids
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			path (str): Specifies the path of the exception
			process (str): Specifies the process of the exception
			rules (list): Specifies a list of rule names
			updatedAfter (str): Specifies the date after which the exception was updated. Specify the date using the yyyy-MM-dd HH:mm:ss format
			updatedBefore (str): Specifies the date before which the exception was updated. Specify the date using the yyyy-MM-dd HH:mm:ss format
			user (str): Specifies a user of the exception

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete", locals())

		url = '/management-rest/exceptions/delete'
		url_params = []
		if collectorGroups != None:
			collectorGroups = ",".join(collectorGroups) if isinstance(collectorGroups, list) else collectorGroups
			url_params.append(f'collectorGroups={collectorGroups}')
		if comment != None:
			url_params.append(f'comment={comment}')
		if createdAfter != None:
			url_params.append(f'createdAfter={createdAfter}')
		if createdBefore != None:
			url_params.append(f'createdBefore={createdBefore}')
		if deleteAll != None:
			url_params.append(f'deleteAll={deleteAll}')
		if destination != None:
			url_params.append(f'destination={destination}')
		if exceptionId != None:
			url_params.append(f'exceptionId={exceptionId}')
		if exceptionIds != None:
			exceptionIds = ",".join(map(str, exceptionIds)) if isinstance(exceptionIds, list) else exceptionIds
			url_params.append(f'exceptionIds={exceptionIds}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if path != None:
			url_params.append(f'path={path}')
		if process != None:
			url_params.append(f'process={process}')
		if rules != None:
			rules = ",".join(rules) if isinstance(rules, list) else rules
			url_params.append(f'rules={rules}')
		if updatedAfter != None:
			url_params.append(f'updatedAfter={updatedAfter}')
		if updatedBefore != None:
			url_params.append(f'updatedBefore={updatedBefore}')
		if user != None:
			url_params.append(f'user={user}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def get_event_exceptions(self, eventId: int, organization: str) -> tuple[bool, list]:
		'''
		Class Exceptions
		Description: Show exceptions.
        
		Args:
			eventId (int): Specifies the required event ID
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("get_event_exceptions", locals())

		url = '/management-rest/exceptions/get-event-exceptions'
		url_params = []
		if eventId != None:
			url_params.append(f'eventId={eventId}')
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def list_exceptions(self, collectorGroups: list = None, comment: str = None, createdAfter: str = None, createdBefore: str = None, destination: str = None, exceptionIds: list = None, organization: str = None, path: str = None, process: str = None, rules: list = None, updatedAfter: str = None, updatedBefore: str = None, user: str = None) -> tuple[bool, list]:
		'''
		Class Exceptions
		Description: List of exceptions.
        
		Args:
			collectorGroups (list): Specifies the list of all the collector groups to which the exception applied
			comment (str): Specifies a comment attach to the exception
			createdAfter (str): Specifies the date after which the exception was created. Specify the date using the yyyy-MM-dd HH:mm:ss format
			createdBefore (str): Specifies the date before which the exception was created. Specify the date using the yyyy-MM-dd HH:mm:ss format
			destination (str): Specifies a destination IP of the exception
			exceptionIds (list): Specifies a list of exception ids
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			path (str): Specifies the path of the exception
			process (str): Specifies the process of the exception
			rules (list): Specifies a list of rule names
			updatedAfter (str): Specifies the date after which the exception was updated. Specify the date using the yyyy-MM-dd HH:mm:ss format
			updatedBefore (str): Specifies the date before which the exception was updated. Specify the date using the yyyy-MM-dd HH:mm:ss format
			user (str): Specifies a user of the exception

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_exceptions", locals())

		url = '/management-rest/exceptions/list-exceptions'
		url_params = []
		if collectorGroups != None:
			collectorGroups = ",".join(collectorGroups) if isinstance(collectorGroups, list) else collectorGroups
			url_params.append(f'collectorGroups={collectorGroups}')
		if comment != None:
			url_params.append(f'comment={comment}')
		if createdAfter != None:
			url_params.append(f'createdAfter={createdAfter}')
		if createdBefore != None:
			url_params.append(f'createdBefore={createdBefore}')
		if destination != None:
			url_params.append(f'destination={destination}')
		if exceptionIds != None:
			exceptionIds = ",".join(map(str, exceptionIds)) if isinstance(exceptionIds, list) else exceptionIds
			url_params.append(f'exceptionIds={exceptionIds}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if path != None:
			url_params.append(f'path={path}')
		if process != None:
			url_params.append(f'process={process}')
		if rules != None:
			rules = ",".join(rules) if isinstance(rules, list) else rules
			url_params.append(f'rules={rules}')
		if updatedAfter != None:
			url_params.append(f'updatedAfter={updatedAfter}')
		if updatedBefore != None:
			url_params.append(f'updatedBefore={updatedBefore}')
		if user != None:
			url_params.append(f'user={user}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def update_exceptions_to_all_accounts_groups_coverage(self, organization: str) -> tuple[bool, None]:
		'''
		Class Exceptions
		Description: This API call set an exception to a 'All organizations agents groups'.
        
		Args:
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("update_exceptions_to_all_accounts_groups_coverage", locals())

		url = '/management-rest/exceptions/update-exceptions-to-all-accounts-groups-coverage'
		url_params = []
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.send(url)

class Forensics:
	'''The Forensics module facilitates deep analysis into the actual internals of the communicating devices operating system that led up to an event.'''

	def get_event_file(self, organization: str, rawEventId: int, disk: bool = None, endRange: str = None, filePaths: list = None, memory: bool = None, processId: int = None, startRange: str = None, download_folder = None) -> tuple[bool, None]:
		'''
		Class Forensics
		Description: This API call retrieves a file or memory.
        
		Args:
			disk (bool): A true/false parameter indicating whether find in the disk
			endRange (str): Specifies the memory end range, in Hexadecimal format
			filePaths (list): Specifies the list of file paths
			memory (bool): A true/false parameter indicating whether find in the memory
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			processId (int): Specifies the ID of the process from which to take a memory image. required for memory base action
			rawEventId (int): Specifies the ID of the raw event on which to perform the memory retrieval
			startRange (str): Specifies the memory start range, in Hexadecimal format

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_event_file", locals())

		url = '/management-rest/forensics/get-event-file'
		url_params = []
		if disk != None:
			url_params.append(f'disk={disk}')
		if endRange != None:
			url_params.append(f'endRange={endRange}')
		if filePaths != None:
			filePaths = ",".join(filePaths) if isinstance(filePaths, list) else filePaths
			url_params.append(f'filePaths={filePaths}')
		if memory != None:
			url_params.append(f'memory={memory}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if processId != None:
			url_params.append(f'processId={processId}')
		if rawEventId != None:
			url_params.append(f'rawEventId={rawEventId}')
		if startRange != None:
			url_params.append(f'startRange={startRange}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.download(url, download_folder=download_folder)

	def get_file(self, device: str, filePaths: list, organization: str, type: str, download_folder = None) -> tuple[bool, None]:
		'''
		Class Forensics
		Description: This API call retrieves a file or memory.
        
		Args:
			device (str): Specifies the name or id of the device to remediate
			filePaths (list): Specifies the list of file paths
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			type (str): Specifies the device parameter type used in the request : Name or ID

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_file", locals())

		url = '/management-rest/forensics/get-file'
		url_params = []
		if device != None:
			url_params.append(f'device={device}')
		if filePaths != None:
			filePaths = ",".join(filePaths) if isinstance(filePaths, list) else filePaths
			url_params.append(f'filePaths={filePaths}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if type != None:
			url_params.append(f'type={type}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.download(url, download_folder=download_folder)

	def remediate_device(self, organization: str, terminatedProcessId: int, device: str = None, deviceId: int = None, executablesToRemove: list = None, persistenceDataAction: str = None, persistenceDataNewContent: str = None, persistenceDataPath: str = None, persistenceDataValueName: str = None, persistenceDataValueNewType: str = None, processName: str = None, threadId: int = None) -> tuple[bool, None]:
		'''
		Class Forensics
		Description: This API kill process / delete file / clean persistence, File and persistence paths must be specified in a logical format.
        
		Args:
			device (str): Specifies the name of the device to remediate. You must specify a value for either device or deviceId (see below)
			deviceId (int): Specifies the unique identifier (ID) of the device to remediate. You must specify a value for either deviceId or device (see above)
			executablesToRemove (list): Specifies the list of full paths of executable files (*.exe) to delete on the
			given device
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			persistenceDataAction (str): persistence data desired action
			persistenceDataNewContent (str): persistence data new content
			persistenceDataPath (str): persistence data path
			persistenceDataValueName (str): persistence data value name
			persistenceDataValueNewType (str): persistence data value new type
			processName (str): Specifies the process name
			terminatedProcessId (int): Represents the process ID to terminate on the device
			threadId (int): Specifies the thread ID

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("remediate_device", locals())

		url = '/management-rest/forensics/remediate-device'
		url_params = []
		if device != None:
			url_params.append(f'device={device}')
		if deviceId != None:
			url_params.append(f'deviceId={deviceId}')
		if executablesToRemove != None:
			executablesToRemove = ",".join(executablesToRemove) if isinstance(executablesToRemove, list) else executablesToRemove
			url_params.append(f'executablesToRemove={executablesToRemove}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if persistenceDataAction != None:
			url_params.append(f'persistenceDataAction={persistenceDataAction}')
		if persistenceDataNewContent != None:
			url_params.append(f'persistenceDataNewContent={persistenceDataNewContent}')
		if persistenceDataPath != None:
			url_params.append(f'persistenceDataPath={persistenceDataPath}')
		if persistenceDataValueName != None:
			url_params.append(f'persistenceDataValueName={persistenceDataValueName}')
		if persistenceDataValueNewType != None:
			url_params.append(f'persistenceDataValueNewType={persistenceDataValueNewType}')
		if processName != None:
			url_params.append(f'processName={processName}')
		if terminatedProcessId != None:
			url_params.append(f'terminatedProcessId={terminatedProcessId}')
		if threadId != None:
			url_params.append(f'threadId={threadId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

class HashSearch:
	'''The Hash Search API'''

	def search(self, fileHashes: list, organization: str = None) -> tuple[bool, None]:
		'''
		Class HashSearch
		Description: This API enables the user to search a file hash among the current events, threat hunting repository and communicating applications that exist in the system.
        
		Args:
			fileHashes (list): Specifies the list of files hashes
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("search", locals())

		url = '/management-rest/hash/search'
		url_params = []
		if fileHashes != None:
			fileHashes = ",".join(fileHashes) if isinstance(fileHashes, list) else fileHashes
			url_params.append(f'fileHashes={fileHashes}')
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

class Integrations:
	'''Integrations Rest Api Controller'''

	def connectors_metadata(self, organization: str) -> tuple[bool, None]:
		'''
		Class Integrations
		Description: Get connectors metadata, describing the valid values for connector fields definition and on-premise cores..
        
		Args:
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("connectors_metadata", locals())

		url = '/management-rest/integrations/connectors-metadata'
		url_params = []
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def create_connector(self, connectorActions: list, enabled: bool, host: str, name: str, organization: str, port: str, type: str, vendor: str, apiKey: str = None, apiValue: str = None, coreId: int = None, externalOrganization: str = None, password: str = None, username: str = None) -> tuple[bool, None]:
		'''
		Class Integrations
		Description: Creates a new connector. Please note: Creation of Custom connectors/actions is not yet support..
        
		Args:
			createConnectorRequest (Object): Check 'createConnectorRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("create_connector", locals())

		url = '/management-rest/integrations/create-connector'

		createConnectorRequest = {}
		if apiKey:
			createConnectorRequest["apiKey"] = f"{apiKey}"
		if apiValue:
			createConnectorRequest["apiValue"] = f"{apiValue}"
		if connectorActions:
			createConnectorRequest["connectorActions"] = f"{connectorActions}"
		if coreId != None:
			createConnectorRequest["coreId"] = f"{coreId}"
		if enabled:
			createConnectorRequest["enabled"] = f"{enabled}"
		if externalOrganization:
			createConnectorRequest["externalOrganization"] = f"{externalOrganization}"
		if host:
			createConnectorRequest["host"] = f"{host}"
		if name:
			createConnectorRequest["name"] = f"{name}"
		if organization:
			createConnectorRequest["organization"] = f"{organization}"
		if password:
			createConnectorRequest["password"] = f"{password}"
		if port:
			createConnectorRequest["port"] = f"{port}"
		if type:
			createConnectorRequest["type"] = f"{type}"
		if username:
			createConnectorRequest["username"] = f"{username}"
		if vendor:
			createConnectorRequest["vendor"] = f"{vendor}"

		return fortiedr_connection.send(url, createConnectorRequest)

	def delete_connector(self, connectorName: str, connectorType: str, organization: str) -> tuple[bool, None]:
		'''
		Class Integrations
		Description: Deletes a connector.
        
		Args:
			connectorName (str): Specifies the connector's name (case sensitive)
			connectorType (str): Specifies the connector's type.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_connector", locals())

		url = '/management-rest/integrations/delete-connector'
		url_params = []
		if connectorName != None:
			url_params.append(f'connectorName={connectorName}')
		if connectorType != None:
			url_params.append(f'connectorType={connectorType}')
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def list_connectors(self, organization: str, onlyValidConnectors: bool = None, type: list = None) -> tuple[bool, list]:
		'''
		Class Integrations
		Description: List all organization connectors.
        
		Args:
			onlyValidConnectors (bool): Set to true to retrieve enabled, non-failing connectors.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			type (list): Detection/Response

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_connectors", locals())

		url = '/management-rest/integrations/list-connectors'
		url_params = []
		if onlyValidConnectors != None:
			url_params.append(f'onlyValidConnectors={onlyValidConnectors}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if type != None:
			type = ",".join(type) if isinstance(type, list) else type
			url_params.append(f'type={type}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def test_connector(self, connectorName: str, connectorType: str, organization: str) -> tuple[bool, None]:
		'''
		Class Integrations
		Description: Tests a connector.
        
		Args:
			connectorName (str): Specifies the connector's name (case sensitive)
			connectorType (str): Specifies the connector's type.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("test_connector", locals())

		url = '/management-rest/integrations/test-connector'
		url_params = []
		if connectorName != None:
			url_params.append(f'connectorName={connectorName}')
		if connectorType != None:
			url_params.append(f'connectorType={connectorType}')
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def update_connector(self, connectorActions: list, enabled: bool, host: str, name: str, organization: str, port: str, type: str, vendor: str, apiKey: str = None, apiValue: str = None, coreId: int = None, externalOrganization: str = None, password: str = None, username: str = None) -> tuple[bool, None]:
		'''
		Class Integrations
		Description: Updates an existing connector based on (name, type, organization). Please note: Modification of Custom connectors/actions is not yet support..
        
		Args:
			updateConnectorRequest (Object): Check 'updateConnectorRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("update_connector", locals())

		url = '/management-rest/integrations/update-connector'

		updateConnectorRequest = {}
		if apiKey:
			updateConnectorRequest["apiKey"] = f"{apiKey}"
		if apiValue:
			updateConnectorRequest["apiValue"] = f"{apiValue}"
		if connectorActions:
			updateConnectorRequest["connectorActions"] = f"{connectorActions}"
		if coreId != None:
			updateConnectorRequest["coreId"] = f"{coreId}"
		if enabled:
			updateConnectorRequest["enabled"] = f"{enabled}"
		if externalOrganization:
			updateConnectorRequest["externalOrganization"] = f"{externalOrganization}"
		if host:
			updateConnectorRequest["host"] = f"{host}"
		if name:
			updateConnectorRequest["name"] = f"{name}"
		if organization:
			updateConnectorRequest["organization"] = f"{organization}"
		if password:
			updateConnectorRequest["password"] = f"{password}"
		if port:
			updateConnectorRequest["port"] = f"{port}"
		if type:
			updateConnectorRequest["type"] = f"{type}"
		if username:
			updateConnectorRequest["username"] = f"{username}"
		if vendor:
			updateConnectorRequest["vendor"] = f"{vendor}"

		return fortiedr_connection.insert(url, updateConnectorRequest)

class SystemInventory:
	'''The System Inventory module enables you to monitor the health of Fortinet Endpoint Protection and Response Platform components and to create Collector Groups.'''

	def aggregator_logs(self, organization: str, device: str = None, deviceId: int = None) -> tuple[bool, None]:
		'''
		Class SystemInventory
		Description: This API call retrieves a aggregator logs.
        
		Args:
			device (str): Specifies the name of the device
			deviceId (int): Specifies the ID of the device
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("aggregator_logs", locals())

		url = '/management-rest/inventory/aggregator-logs'
		url_params = []
		if device != None:
			url_params.append(f'device={device}')
		if deviceId != None:
			url_params.append(f'deviceId={deviceId}')
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def check_custom_installer(self, customInstallerID: str) -> tuple[bool, None]:
		'''
		Class SystemInventory
		Description: This API call for checking the results for an custom installer request and getting the installer url.
        
		Args:
			customInstallerID (str): customInstallerID

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("check_custom_installer", locals())

		url = '/management-rest/inventory/check-custom-installer'
		url_params = []
		if customInstallerID != None:
			url_params.append(f'customInstallerID={customInstallerID}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def collector_logs(self, organization: str, device: str = None, deviceId: int = None) -> tuple[bool, None]:
		'''
		Class SystemInventory
		Description: This API call retrieves a collector logs.
        
		Args:
			device (str): Specifies the name of the device
			deviceId (int): Specifies the ID of the device
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("collector_logs", locals())

		url = '/management-rest/inventory/collector-logs'
		url_params = []
		if device != None:
			url_params.append(f'device={device}')
		if deviceId != None:
			url_params.append(f'deviceId={deviceId}')
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def core_logs(self, organization: str, device: str = None, deviceId: int = None) -> tuple[bool, None]:
		'''
		Class SystemInventory
		Description: This API call retrieves a core logs.
        
		Args:
			device (str): Specifies the name of the device
			deviceId (int): Specifies the ID of the device
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("core_logs", locals())

		url = '/management-rest/inventory/core-logs'
		url_params = []
		if device != None:
			url_params.append(f'device={device}')
		if deviceId != None:
			url_params.append(f'deviceId={deviceId}')
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def create_collector_group(self, name: str, organization: str) -> tuple[bool, None]:
		'''
		Class SystemInventory
		Description: This API call create collector group.
        
		Args:
			name (str): Collector group name
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("create_collector_group", locals())

		url = '/management-rest/inventory/create-collector-group'
		url_params = []
		if name != None:
			url_params.append(f'name={name}')
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.send(url)

	def create_ems_custom_installer(self, osType: str, aggregatorAddress: str = None, aggregatorPort: int = None, citrixPVS: bool = None, collectorGroup: str = None, collectorVersion: str = None, distro: str = None, is64bit: bool = None, organization: str = None, proxy: bool = None, vdi: bool = None) -> tuple[bool, None]:
		'''
		Class SystemInventory
		Description: This API call sends request for creating custom-installer for EMS integration.
        
		Args:
			aggregatorAddress (str): Specifies the aggregator ip or dns address
			aggregatorPort (int): Specifies the aggregator port
			citrixPVS (bool): Specifies whether the collector installed with citrix in pvs mode
			collectorGroup (str): Specifies the requested collector group
			collectorVersion (str): Specifies the requested collector version
			distro (str): Specifies the Linux distribution. For example: CentOS_6, CentOS_7, CentOS_8, CentOS_9, Amazon, Oracle_6, Oracle_7, Oracle_8, SLES_12, SLES_15, Ubuntu_16.04, Ubuntu_18.04, Ubuntu_20.04, Ubuntu_22.04
			is64bit (bool): Specifies the Windows os bit version
			organization (str): Specifies the requested organization
			osType (str): Specifies the operating system type
			proxy (bool): Specifies the system proxy settings (Only applies to Collector versions 3.1 and above)
			vdi (bool): Specifies the VDI (Virtual Desktop Infrastructure) installation

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("create_ems_custom_installer", locals())

		url = '/management-rest/inventory/create-ems-custom-installer'
		url_params = []
		if aggregatorAddress != None:
			url_params.append(f'aggregatorAddress={aggregatorAddress}')
		if aggregatorPort != None:
			url_params.append(f'aggregatorPort={aggregatorPort}')
		if citrixPVS != None:
			url_params.append(f'citrixPVS={citrixPVS}')
		if collectorGroup != None:
			url_params.append(f'collectorGroup={collectorGroup}')
		if collectorVersion != None:
			url_params.append(f'collectorVersion={collectorVersion}')
		if distro != None:
			url_params.append(f'distro={distro}')
		if is64bit != None:
			url_params.append(f'is64bit={is64bit}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if osType != None:
			url_params.append(f'osType={osType}')
		if proxy != None:
			url_params.append(f'proxy={proxy}')
		if vdi != None:
			url_params.append(f'vdi={vdi}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.send(url)

	def delete_collectors(self, cloudAccounts: list = None, cloudProviders: list = None, clusters: list = None, collectorGroups: list = None, collectorGroupsIds: list = None, collectorType: str = None, confirmDeletion: bool = None, deleteAll: bool = None, devices: list = None, devicesIds: list = None, firstSeen: str = None, hasCrashDumps: bool = None, ips: list = None, itemsPerPage: int = None, lastSeenEnd: str = None, lastSeenStart: str = None, loggedUser: str = None, operatingSystems: list = None, organization: str = None, osFamilies: list = None, pageNumber: int = None, showExpired: bool = None, sorting: str = None, states: list = None, strictMode: bool = None, versions: list = None) -> tuple[bool, None]:
		'''
		Class SystemInventory
		Description: This API call deletes a Collector(s).
        
		Args:
			cloudAccounts (list): Specifies the list cloud account names
			cloudProviders (list): Specifies the list of cloud providers: AWS, Azure, GCP
			clusters (list): Specifies the list of cluster
			collectorGroups (list): Specifies the list of collector group names and retrieves collectors under the
			given groups
			collectorGroupsIds (list): Specifies the list of collector group Ids and retrieves collectors under the
			given groups
			collectorType (str): Specifies the group types of the collectors. Types: All, Collector, Workloads. All by default
			confirmDeletion (bool): A true/false parameter indicating if to detach/delete relevant exceptions from Collector groups about to be deleted
			deleteAll (bool): A true/false parameter indicating if all collectors should be deleted
			devices (list): Specifies the list of device names
			devicesIds (list): Specifies the list of device ids
			firstSeen (str): Retrieves collectors that were first seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss
			hasCrashDumps (bool): Retrieves collectors that have crash dumps
			ips (list): Specifies the list of IP values
			itemsPerPage (int): An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000
			lastSeenEnd (str): Retrieves collectors that were last seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss
			lastSeenStart (str): Retrieves collectors that were last seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss
			loggedUser (str): Specifies the user that was logged when the event occurred
			operatingSystems (list): Specifies the list of specific operating systems. For example, Windows 7 Pro
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			
			osFamilies (list): Specifies the list of operating system families: Windows, Windows Server or OS X
			pageNumber (int): An integer used for paging that indicates the required page number
			showExpired (bool): Specifies whether to include collectors which have been disconnected for more than 30 days (sequentially) and are marked as Expired
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on
			states (list): Specifies the list of collector states: Running, Disconnected, Disabled, Degraded, 
			Pending Reboot, Isolated, Expired, Migrated or Pending Migration
			strictMode (bool): A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False
			versions (list): Specifies the list of collector versions

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_collectors", locals())

		url = '/management-rest/inventory/delete-collectors'
		url_params = []
		if cloudAccounts != None:
			cloudAccounts = ",".join(cloudAccounts) if isinstance(cloudAccounts, list) else cloudAccounts
			url_params.append(f'cloudAccounts={cloudAccounts}')
		if cloudProviders != None:
			cloudProviders = ",".join(cloudProviders) if isinstance(cloudProviders, list) else cloudProviders
			url_params.append(f'cloudProviders={cloudProviders}')
		if clusters != None:
			clusters = ",".join(clusters) if isinstance(clusters, list) else clusters
			url_params.append(f'clusters={clusters}')
		if collectorGroups != None:
			collectorGroups = ",".join(collectorGroups) if isinstance(collectorGroups, list) else collectorGroups
			url_params.append(f'collectorGroups={collectorGroups}')
		if collectorGroupsIds != None:
			collectorGroupsIds = ",".join(map(str, collectorGroupsIds)) if isinstance(collectorGroupsIds, list) else collectorGroupsIds
			url_params.append(f'collectorGroupsIds={collectorGroupsIds}')
		if collectorType != None:
			url_params.append(f'collectorType={collectorType}')
		if confirmDeletion != None:
			url_params.append(f'confirmDeletion={confirmDeletion}')
		if deleteAll != None:
			url_params.append(f'deleteAll={deleteAll}')
		if devices != None:
			devices = ",".join(devices) if isinstance(devices, list) else devices
			url_params.append(f'devices={devices}')
		if devicesIds != None:
			devicesIds = ",".join(map(str, devicesIds)) if isinstance(devicesIds, list) else devicesIds
			url_params.append(f'devicesIds={devicesIds}')
		if firstSeen != None:
			url_params.append(f'firstSeen={firstSeen}')
		if hasCrashDumps != None:
			url_params.append(f'hasCrashDumps={hasCrashDumps}')
		if ips != None:
			ips = ",".join(ips) if isinstance(ips, list) else ips
			url_params.append(f'ips={ips}')
		if itemsPerPage != None:
			url_params.append(f'itemsPerPage={itemsPerPage}')
		if lastSeenEnd != None:
			url_params.append(f'lastSeenEnd={lastSeenEnd}')
		if lastSeenStart != None:
			url_params.append(f'lastSeenStart={lastSeenStart}')
		if loggedUser != None:
			url_params.append(f'loggedUser={loggedUser}')
		if operatingSystems != None:
			operatingSystems = ",".join(operatingSystems) if isinstance(operatingSystems, list) else operatingSystems
			url_params.append(f'operatingSystems={operatingSystems}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if osFamilies != None:
			osFamilies = ",".join(osFamilies) if isinstance(osFamilies, list) else osFamilies
			url_params.append(f'osFamilies={osFamilies}')
		if pageNumber != None:
			url_params.append(f'pageNumber={pageNumber}')
		if showExpired != None:
			url_params.append(f'showExpired={showExpired}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if states != None:
			states = ",".join(states) if isinstance(states, list) else states
			url_params.append(f'states={states}')
		if strictMode != None:
			url_params.append(f'strictMode={strictMode}')
		if versions != None:
			versions = ",".join(versions) if isinstance(versions, list) else versions
			url_params.append(f'versions={versions}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def ems_move_collectors(self, targetCollectorGroup: str, collectorIds: list = None, collectorSIDs: list = None, collectors: list = None, forceAssign: bool = None, organization: str = None) -> tuple[bool, list]:
		'''
		Class SystemInventory
		Description: This API call move collector between groups for EMS integration.
        
		Args:
			collectorIds (list): value = Array of collectors Ids. To move collectors from one organization to another
			collectorSIDs (list): value = Array of collectors SIDS. To move collectors from one organization to another
			collectors (list): Array of collectors names. To move collectors from one organization to another, for each collector please add the organization name before the collector name (<organization-name>//<collector-name>)
			forceAssign (bool): Indicates whether to force the assignment even if the organization of the target Collector group is under migration
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			targetCollectorGroup (str): Collector group. To move collectors from one organization to another, please add the organization name before the target collector group (<organization-name>//<collector-group-name>)

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("ems_move_collectors", locals())

		url = '/management-rest/inventory/ems-move-collectors'
		url_params = []
		if collectorIds != None:
			collectorIds = ",".join(map(str, collectorIds)) if isinstance(collectorIds, list) else collectorIds
			url_params.append(f'collectorIds={collectorIds}')
		if collectorSIDs != None:
			collectorSIDs = ",".join(collectorSIDs) if isinstance(collectorSIDs, list) else collectorSIDs
			url_params.append(f'collectorSIDs={collectorSIDs}')
		if collectors != None:
			collectors = ",".join(collectors) if isinstance(collectors, list) else collectors
			url_params.append(f'collectors={collectors}')
		if forceAssign != None:
			url_params.append(f'forceAssign={forceAssign}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if targetCollectorGroup != None:
			url_params.append(f'targetCollectorGroup={targetCollectorGroup}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def isolate_collectors(self, organization: str, devices: list = None, devicesIds: list = None) -> tuple[bool, None]:
		'''
		Class SystemInventory
		Description: This API call isolate collector functionality.
        
		Args:
			devices (list): Specifies the list of device names
			devicesIds (list): Specifies the list of device ids
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("isolate_collectors", locals())

		url = '/management-rest/inventory/isolate-collectors'
		url_params = []
		if devices != None:
			devices = ",".join(devices) if isinstance(devices, list) else devices
			url_params.append(f'devices={devices}')
		if devicesIds != None:
			devicesIds = ",".join(map(str, devicesIds)) if isinstance(devicesIds, list) else devicesIds
			url_params.append(f'devicesIds={devicesIds}')
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def list_aggregators(self, ip: str = None, names: list = None, organization: str = None, versions: list = None) -> tuple[bool, list]:
		'''
		Class SystemInventory
		Description: This API call output the list of aggregators.
        
		Args:
			ip (str): IP
			names (list): List of aggregators names
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			versions (list): List of aggregators versions

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_aggregators", locals())

		url = '/management-rest/inventory/list-aggregators'
		url_params = []
		if ip != None:
			url_params.append(f'ip={ip}')
		if names != None:
			names = ",".join(names) if isinstance(names, list) else names
			url_params.append(f'names={names}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if versions != None:
			versions = ",".join(versions) if isinstance(versions, list) else versions
			url_params.append(f'versions={versions}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def list_collector_groups(self, organization: str = None) -> tuple[bool, list]:
		'''
		Class SystemInventory
		Description: This API call output the collectors groups.
        
		Args:
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_collector_groups", locals())

		url = '/management-rest/inventory/list-collector-groups'
		url_params = []
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def list_collectors(self, cloudAccounts: list = None, cloudProviders: list = None, clusters: list = None, collectorGroups: list = None, collectorGroupsIds: list = None, collectorType: str = None, devices: list = None, devicesIds: list = None, firstSeen: str = None, hasCrashDumps: bool = None, ips: list = None, itemsPerPage: int = None, lastSeenEnd: str = None, lastSeenStart: str = None, loggedUser: str = None, operatingSystems: list = None, organization: str = None, osFamilies: list = None, pageNumber: int = None, showExpired: bool = None, sorting: str = None, states: list = None, strictMode: bool = None, versions: list = None) -> tuple[bool, list]:
		'''
		Class SystemInventory
		Description: This API call outputs a list of the Collectors in the system. Use the input parameters to filter the list.
        
		Args:
			cloudAccounts (list): Specifies the list cloud account names
			cloudProviders (list): Specifies the list of cloud providers: AWS, Azure, GCP
			clusters (list): Specifies the list of cluster
			collectorGroups (list): Specifies the list of collector group names and retrieves collectors under the
			given groups
			collectorGroupsIds (list): Specifies the list of collector group Ids and retrieves collectors under the
			given groups
			collectorType (str): Specifies the group types of the collectors. Types: All, Collector, Workloads. All by default
			devices (list): Specifies the list of device names
			devicesIds (list): Specifies the list of device ids
			firstSeen (str): Retrieves collectors that were first seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss
			hasCrashDumps (bool): Retrieves collectors that have crash dumps
			ips (list): Specifies the list of IP values
			itemsPerPage (int): An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000
			lastSeenEnd (str): Retrieves collectors that were last seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss
			lastSeenStart (str): Retrieves collectors that were last seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss
			loggedUser (str): Specifies the user that was logged when the event occurred
			operatingSystems (list): Specifies the list of specific operating systems. For example, Windows 7 Pro
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			
			osFamilies (list): Specifies the list of operating system families: Windows, Windows Server or OS X
			pageNumber (int): An integer used for paging that indicates the required page number
			showExpired (bool): Specifies whether to include collectors which have been disconnected for more than 30 days (sequentially) and are marked as Expired
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on
			states (list): Specifies the list of collector states: Running, Disconnected, Disabled, Degraded, 
			Pending Reboot, Isolated, Expired, Migrated or Pending Migration
			strictMode (bool): A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False
			versions (list): Specifies the list of collector versions

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_collectors", locals())

		url = '/management-rest/inventory/list-collectors'
		url_params = []
		if cloudAccounts != None:
			cloudAccounts = ",".join(cloudAccounts) if isinstance(cloudAccounts, list) else cloudAccounts
			url_params.append(f'cloudAccounts={cloudAccounts}')
		if cloudProviders != None:
			cloudProviders = ",".join(cloudProviders) if isinstance(cloudProviders, list) else cloudProviders
			url_params.append(f'cloudProviders={cloudProviders}')
		if clusters != None:
			clusters = ",".join(clusters) if isinstance(clusters, list) else clusters
			url_params.append(f'clusters={clusters}')
		if collectorGroups != None:
			collectorGroups = ",".join(collectorGroups) if isinstance(collectorGroups, list) else collectorGroups
			url_params.append(f'collectorGroups={collectorGroups}')
		if collectorGroupsIds != None:
			collectorGroupsIds = ",".join(map(str, collectorGroupsIds)) if isinstance(collectorGroupsIds, list) else collectorGroupsIds
			url_params.append(f'collectorGroupsIds={collectorGroupsIds}')
		if collectorType != None:
			url_params.append(f'collectorType={collectorType}')
		if devices != None:
			devices = ",".join(devices) if isinstance(devices, list) else devices
			url_params.append(f'devices={devices}')
		if devicesIds != None:
			devicesIds = ",".join(map(str, devicesIds)) if isinstance(devicesIds, list) else devicesIds
			url_params.append(f'devicesIds={devicesIds}')
		if firstSeen != None:
			url_params.append(f'firstSeen={firstSeen}')
		if hasCrashDumps != None:
			url_params.append(f'hasCrashDumps={hasCrashDumps}')
		if ips != None:
			ips = ",".join(ips) if isinstance(ips, list) else ips
			url_params.append(f'ips={ips}')
		if itemsPerPage != None:
			url_params.append(f'itemsPerPage={itemsPerPage}')
		if lastSeenEnd != None:
			url_params.append(f'lastSeenEnd={lastSeenEnd}')
		if lastSeenStart != None:
			url_params.append(f'lastSeenStart={lastSeenStart}')
		if loggedUser != None:
			url_params.append(f'loggedUser={loggedUser}')
		if operatingSystems != None:
			operatingSystems = ",".join(operatingSystems) if isinstance(operatingSystems, list) else operatingSystems
			url_params.append(f'operatingSystems={operatingSystems}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if osFamilies != None:
			osFamilies = ",".join(osFamilies) if isinstance(osFamilies, list) else osFamilies
			url_params.append(f'osFamilies={osFamilies}')
		if pageNumber != None:
			url_params.append(f'pageNumber={pageNumber}')
		if showExpired != None:
			url_params.append(f'showExpired={showExpired}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if states != None:
			states = ",".join(states) if isinstance(states, list) else states
			url_params.append(f'states={states}')
		if strictMode != None:
			url_params.append(f'strictMode={strictMode}')
		if versions != None:
			versions = ",".join(versions) if isinstance(versions, list) else versions
			url_params.append(f'versions={versions}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def list_cores(self, deploymentModes: list = None, hasCrashDumps: bool = None, ip: str = None, names: list = None, organization: str = None, versions: list = None) -> tuple[bool, list]:
		'''
		Class SystemInventory
		Description: This API call output the list of cores.
        
		Args:
			deploymentModes (list): List of cores deployments modes
			hasCrashDumps (bool): Has crash dumps
			ip (str): IP
			names (list): List of cores names
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			versions (list): List of cores versions

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_cores", locals())

		url = '/management-rest/inventory/list-cores'
		url_params = []
		if deploymentModes != None:
			deploymentModes = ",".join(deploymentModes) if isinstance(deploymentModes, list) else deploymentModes
			url_params.append(f'deploymentModes={deploymentModes}')
		if hasCrashDumps != None:
			url_params.append(f'hasCrashDumps={hasCrashDumps}')
		if ip != None:
			url_params.append(f'ip={ip}')
		if names != None:
			names = ",".join(names) if isinstance(names, list) else names
			url_params.append(f'names={names}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if versions != None:
			versions = ",".join(versions) if isinstance(versions, list) else versions
			url_params.append(f'versions={versions}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def list_repositories(self) -> tuple[bool, list]:
		'''
		Class SystemInventory
		Description: This API call output the list of repositories (edrs).
        
		Args:

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_repositories", locals())

		url = '/management-rest/inventory/list-repositories'
		return fortiedr_connection.get(url)

	def list_unmanaged_devices(self, itemsPerPage: int = None, organization: str = None, pageNumber: int = None, sorting: str = None, strictMode: bool = None) -> tuple[bool, list]:
		'''
		Class SystemInventory
		Description: This API call outputs a list of the unmanaged devices in the system.
        
		Args:
			itemsPerPage (int): An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			pageNumber (int): An integer used for paging that indicates the required page number
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on
			strictMode (bool): A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_unmanaged_devices", locals())

		url = '/management-rest/inventory/list-unmanaged-devices'
		url_params = []
		if itemsPerPage != None:
			url_params.append(f'itemsPerPage={itemsPerPage}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if pageNumber != None:
			url_params.append(f'pageNumber={pageNumber}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if strictMode != None:
			url_params.append(f'strictMode={strictMode}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def move_collectors(self, targetCollectorGroup: str, collectorIds: list = None, collectorSIDs: list = None, collectors: list = None, forceAssign: bool = None, organization: str = None) -> tuple[bool, None]:
		'''
		Class SystemInventory
		Description: This API call move collector between groups.
        
		Args:
			collectorIds (list): value = Array of collectors Ids. To move collectors from one organization to another
			collectorSIDs (list): value = Array of collectors SIDS. To move collectors from one organization to another
			collectors (list): Array of collectors names. To move collectors from one organization to another, for each collector please add the organization name before the collector name (<organization-name>//<collector-name>)
			forceAssign (bool): Indicates whether to force the assignment even if the organization of the target Collector group is under migration
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			targetCollectorGroup (str): Collector group. To move collectors from one organization to another, please add the organization name before the target collector group (<organization-name>//<collector-group-name>)

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("move_collectors", locals())

		url = '/management-rest/inventory/move-collectors'
		url_params = []
		if collectorIds != None:
			collectorIds = ",".join(map(str, collectorIds)) if isinstance(collectorIds, list) else collectorIds
			url_params.append(f'collectorIds={collectorIds}')
		if collectorSIDs != None:
			collectorSIDs = ",".join(collectorSIDs) if isinstance(collectorSIDs, list) else collectorSIDs
			url_params.append(f'collectorSIDs={collectorSIDs}')
		if collectors != None:
			collectors = ",".join(collectors) if isinstance(collectors, list) else collectors
			url_params.append(f'collectors={collectors}')
		if forceAssign != None:
			url_params.append(f'forceAssign={forceAssign}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if targetCollectorGroup != None:
			url_params.append(f'targetCollectorGroup={targetCollectorGroup}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def moveCollectorsToAnotherAggregator(self, address: str = None, cloudAccounts: list = None, cloudProviders: list = None, clusters: list = None, collectorGroups: list = None, collectorGroupsIds: list = None, collectorType: str = None, destinationAccountName: str = None, devices: list = None, devicesIds: list = None, firstSeen: str = None, hasCrashDumps: bool = None, ips: list = None, itemsPerPage: int = None, lastSeenEnd: str = None, lastSeenStart: str = None, loggedUser: str = None, operatingSystems: list = None, organization: str = None, osFamilies: list = None, pageNumber: int = None, showExpired: bool = None, sorting: str = None, states: list = None, strictMode: bool = None, versions: list = None) -> tuple[bool, None]:
		'''
		Class SystemInventory
		Description: This API call starts collectors transfer to another aggregator. Use the input parameters to filter the list.
        
		Args:
			address (str): Specifies the address of the destination aggregator
			cloudAccounts (list): Specifies the list cloud account names
			cloudProviders (list): Specifies the list of cloud providers: AWS, Azure, GCP
			clusters (list): Specifies the list of cluster
			collectorGroups (list): Specifies the list of collector group names and retrieves collectors under the
			given groups
			collectorGroupsIds (list): Specifies the list of collector group Ids and retrieves collectors under the
			given groups
			collectorType (str): Specifies the group types of the collectors. Types: All, Collector, Workloads. All by default
			destinationAccountName (str): Specifies the name of the destination account
			devices (list): Specifies the list of device names
			devicesIds (list): Specifies the list of device ids
			firstSeen (str): Retrieves collectors that were first seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss
			hasCrashDumps (bool): Retrieves collectors that have crash dumps
			ips (list): Specifies the list of IP values
			itemsPerPage (int): An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000
			lastSeenEnd (str): Retrieves collectors that were last seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss
			lastSeenStart (str): Retrieves collectors that were last seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss
			loggedUser (str): Specifies the user that was logged when the event occurred
			operatingSystems (list): Specifies the list of specific operating systems. For example, Windows 7 Pro
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			
			osFamilies (list): Specifies the list of operating system families: Windows, Windows Server or OS X
			pageNumber (int): An integer used for paging that indicates the required page number
			showExpired (bool): Specifies whether to include collectors which have been disconnected for more than 30 days (sequentially) and are marked as Expired
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on
			states (list): Specifies the list of collector states: Running, Disconnected, Disabled, Degraded, 
			Pending Reboot, Isolated, Expired, Migrated or Pending Migration
			strictMode (bool): A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False
			versions (list): Specifies the list of collector versions

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("moveCollectorsToAnotherAggregator", locals())

		url = '/management-rest/inventory/moveCollectorsToAnotherAggregator'
		url_params = []
		if address != None:
			url_params.append(f'address={address}')
		if cloudAccounts != None:
			cloudAccounts = ",".join(cloudAccounts) if isinstance(cloudAccounts, list) else cloudAccounts
			url_params.append(f'cloudAccounts={cloudAccounts}')
		if cloudProviders != None:
			cloudProviders = ",".join(cloudProviders) if isinstance(cloudProviders, list) else cloudProviders
			url_params.append(f'cloudProviders={cloudProviders}')
		if clusters != None:
			clusters = ",".join(clusters) if isinstance(clusters, list) else clusters
			url_params.append(f'clusters={clusters}')
		if collectorGroups != None:
			collectorGroups = ",".join(collectorGroups) if isinstance(collectorGroups, list) else collectorGroups
			url_params.append(f'collectorGroups={collectorGroups}')
		if collectorGroupsIds != None:
			collectorGroupsIds = ",".join(map(str, collectorGroupsIds)) if isinstance(collectorGroupsIds, list) else collectorGroupsIds
			url_params.append(f'collectorGroupsIds={collectorGroupsIds}')
		if collectorType != None:
			url_params.append(f'collectorType={collectorType}')
		if destinationAccountName != None:
			url_params.append(f'destinationAccountName={destinationAccountName}')
		if devices != None:
			devices = ",".join(devices) if isinstance(devices, list) else devices
			url_params.append(f'devices={devices}')
		if devicesIds != None:
			devicesIds = ",".join(map(str, devicesIds)) if isinstance(devicesIds, list) else devicesIds
			url_params.append(f'devicesIds={devicesIds}')
		if firstSeen != None:
			url_params.append(f'firstSeen={firstSeen}')
		if hasCrashDumps != None:
			url_params.append(f'hasCrashDumps={hasCrashDumps}')
		if ips != None:
			ips = ",".join(ips) if isinstance(ips, list) else ips
			url_params.append(f'ips={ips}')
		if itemsPerPage != None:
			url_params.append(f'itemsPerPage={itemsPerPage}')
		if lastSeenEnd != None:
			url_params.append(f'lastSeenEnd={lastSeenEnd}')
		if lastSeenStart != None:
			url_params.append(f'lastSeenStart={lastSeenStart}')
		if loggedUser != None:
			url_params.append(f'loggedUser={loggedUser}')
		if operatingSystems != None:
			operatingSystems = ",".join(operatingSystems) if isinstance(operatingSystems, list) else operatingSystems
			url_params.append(f'operatingSystems={operatingSystems}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if osFamilies != None:
			osFamilies = ",".join(osFamilies) if isinstance(osFamilies, list) else osFamilies
			url_params.append(f'osFamilies={osFamilies}')
		if pageNumber != None:
			url_params.append(f'pageNumber={pageNumber}')
		if showExpired != None:
			url_params.append(f'showExpired={showExpired}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if states != None:
			states = ",".join(states) if isinstance(states, list) else states
			url_params.append(f'states={states}')
		if strictMode != None:
			url_params.append(f'strictMode={strictMode}')
		if versions != None:
			versions = ",".join(versions) if isinstance(versions, list) else versions
			url_params.append(f'versions={versions}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.send(url)

	def release_license(self, releaseLicense: bool, cloudAccounts: list = None, cloudProviders: list = None, clusters: list = None, collectorGroups: list = None, collectorGroupsIds: list = None, collectorType: str = None, devices: list = None, devicesIds: list = None, firstSeen: str = None, hasCrashDumps: bool = None, ips: list = None, itemsPerPage: int = None, lastSeenEnd: str = None, lastSeenStart: str = None, loggedUser: str = None, operatingSystems: list = None, organization: str = None, osFamilies: list = None, pageNumber: int = None, showExpired: bool = None, sorting: str = None, states: list = None, strictMode: bool = None, versions: list = None) -> tuple[bool, list]:
		'''
		Class SystemInventory
		Description: This API call enables/disables a Collector(s) and release it license. You must specify whether the License must be released or acquired! Cooldown between the requests should be 2-3 minutes!.
        
		Args:
			cloudAccounts (list): Specifies the list cloud account names
			cloudProviders (list): Specifies the list of cloud providers: AWS, Azure, GCP
			clusters (list): Specifies the list of cluster
			collectorGroups (list): Specifies the list of collector group names and retrieves collectors under the
			given groups
			collectorGroupsIds (list): Specifies the list of collector group Ids and retrieves collectors under the
			given groups
			collectorType (str): Specifies the group types of the collectors. Types: All, Collector, Workloads. All by default
			devices (list): Specifies the list of device names
			devicesIds (list): Specifies the list of device ids
			firstSeen (str): Retrieves collectors that were first seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss
			hasCrashDumps (bool): Retrieves collectors that have crash dumps
			ips (list): Specifies the list of IP values
			itemsPerPage (int): An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000
			lastSeenEnd (str): Retrieves collectors that were last seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss
			lastSeenStart (str): Retrieves collectors that were last seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss
			loggedUser (str): Specifies the user that was logged when the event occurred
			operatingSystems (list): Specifies the list of specific operating systems. For example, Windows 7 Pro
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			
			osFamilies (list): Specifies the list of operating system families: Windows, Windows Server or OS X
			pageNumber (int): An integer used for paging that indicates the required page number
			releaseLicense (bool): Collector releaseLicense
			showExpired (bool): Specifies whether to include collectors which have been disconnected for more than 30 days (sequentially) and are marked as Expired
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on
			states (list): Specifies the list of collector states: Running, Disconnected, Disabled, Degraded, 
			Pending Reboot, Isolated, Expired, Migrated or Pending Migration
			strictMode (bool): A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False
			versions (list): Specifies the list of collector versions

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("release_license", locals())

		url = '/management-rest/inventory/release-license'
		url_params = []
		if cloudAccounts != None:
			cloudAccounts = ",".join(cloudAccounts) if isinstance(cloudAccounts, list) else cloudAccounts
			url_params.append(f'cloudAccounts={cloudAccounts}')
		if cloudProviders != None:
			cloudProviders = ",".join(cloudProviders) if isinstance(cloudProviders, list) else cloudProviders
			url_params.append(f'cloudProviders={cloudProviders}')
		if clusters != None:
			clusters = ",".join(clusters) if isinstance(clusters, list) else clusters
			url_params.append(f'clusters={clusters}')
		if collectorGroups != None:
			collectorGroups = ",".join(collectorGroups) if isinstance(collectorGroups, list) else collectorGroups
			url_params.append(f'collectorGroups={collectorGroups}')
		if collectorGroupsIds != None:
			collectorGroupsIds = ",".join(map(str, collectorGroupsIds)) if isinstance(collectorGroupsIds, list) else collectorGroupsIds
			url_params.append(f'collectorGroupsIds={collectorGroupsIds}')
		if collectorType != None:
			url_params.append(f'collectorType={collectorType}')
		if devices != None:
			devices = ",".join(devices) if isinstance(devices, list) else devices
			url_params.append(f'devices={devices}')
		if devicesIds != None:
			devicesIds = ",".join(map(str, devicesIds)) if isinstance(devicesIds, list) else devicesIds
			url_params.append(f'devicesIds={devicesIds}')
		if firstSeen != None:
			url_params.append(f'firstSeen={firstSeen}')
		if hasCrashDumps != None:
			url_params.append(f'hasCrashDumps={hasCrashDumps}')
		if ips != None:
			ips = ",".join(ips) if isinstance(ips, list) else ips
			url_params.append(f'ips={ips}')
		if itemsPerPage != None:
			url_params.append(f'itemsPerPage={itemsPerPage}')
		if lastSeenEnd != None:
			url_params.append(f'lastSeenEnd={lastSeenEnd}')
		if lastSeenStart != None:
			url_params.append(f'lastSeenStart={lastSeenStart}')
		if loggedUser != None:
			url_params.append(f'loggedUser={loggedUser}')
		if operatingSystems != None:
			operatingSystems = ",".join(operatingSystems) if isinstance(operatingSystems, list) else operatingSystems
			url_params.append(f'operatingSystems={operatingSystems}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if osFamilies != None:
			osFamilies = ",".join(osFamilies) if isinstance(osFamilies, list) else osFamilies
			url_params.append(f'osFamilies={osFamilies}')
		if pageNumber != None:
			url_params.append(f'pageNumber={pageNumber}')
		if releaseLicense != None:
			url_params.append(f'releaseLicense={releaseLicense}')
		if showExpired != None:
			url_params.append(f'showExpired={showExpired}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if states != None:
			states = ",".join(states) if isinstance(states, list) else states
			url_params.append(f'states={states}')
		if strictMode != None:
			url_params.append(f'strictMode={strictMode}')
		if versions != None:
			versions = ",".join(versions) if isinstance(versions, list) else versions
			url_params.append(f'versions={versions}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def system_logs(self) -> tuple[bool, None]:
		'''
		Class SystemInventory
		Description: This API call retrieves a system logs.
        
		Args:

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("system_logs", locals())

		url = '/management-rest/inventory/system-logs'
		return fortiedr_connection.get(url)

	def toggle_collectors(self, enable: bool, cloudAccounts: list = None, cloudProviders: list = None, clusters: list = None, collectorGroups: list = None, collectorGroupsIds: list = None, collectorType: str = None, devices: list = None, devicesIds: list = None, firstSeen: str = None, hasCrashDumps: bool = None, ips: list = None, itemsPerPage: int = None, lastSeenEnd: str = None, lastSeenStart: str = None, loggedUser: str = None, operatingSystems: list = None, organization: str = None, osFamilies: list = None, pageNumber: int = None, showExpired: bool = None, sorting: str = None, states: list = None, strictMode: bool = None, versions: list = None) -> tuple[bool, str]:
		'''
		Class SystemInventory
		Description: This API call enables/disables a Collector(s). You must specify whether the Collector is to be enabled or disabled.
        
		Args:
			cloudAccounts (list): Specifies the list cloud account names
			cloudProviders (list): Specifies the list of cloud providers: AWS, Azure, GCP
			clusters (list): Specifies the list of cluster
			collectorGroups (list): Specifies the list of collector group names and retrieves collectors under the
			given groups
			collectorGroupsIds (list): Specifies the list of collector group Ids and retrieves collectors under the
			given groups
			collectorType (str): Specifies the group types of the collectors. Types: All, Collector, Workloads. All by default
			devices (list): Specifies the list of device names
			devicesIds (list): Specifies the list of device ids
			enable (bool): Toggle enable
			firstSeen (str): Retrieves collectors that were first seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss
			hasCrashDumps (bool): Retrieves collectors that have crash dumps
			ips (list): Specifies the list of IP values
			itemsPerPage (int): An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000
			lastSeenEnd (str): Retrieves collectors that were last seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss
			lastSeenStart (str): Retrieves collectors that were last seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss
			loggedUser (str): Specifies the user that was logged when the event occurred
			operatingSystems (list): Specifies the list of specific operating systems. For example, Windows 7 Pro
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			
			osFamilies (list): Specifies the list of operating system families: Windows, Windows Server or OS X
			pageNumber (int): An integer used for paging that indicates the required page number
			showExpired (bool): Specifies whether to include collectors which have been disconnected for more than 30 days (sequentially) and are marked as Expired
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on
			states (list): Specifies the list of collector states: Running, Disconnected, Disabled, Degraded, 
			Pending Reboot, Isolated, Expired, Migrated or Pending Migration
			strictMode (bool): A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False
			versions (list): Specifies the list of collector versions

		Returns:
			bool: Status of the request (True or False). 
			str
		'''
		validate_params("toggle_collectors", locals())

		url = '/management-rest/inventory/toggle-collectors'
		url_params = []
		if cloudAccounts != None:
			cloudAccounts = ",".join(cloudAccounts) if isinstance(cloudAccounts, list) else cloudAccounts
			url_params.append(f'cloudAccounts={cloudAccounts}')
		if cloudProviders != None:
			cloudProviders = ",".join(cloudProviders) if isinstance(cloudProviders, list) else cloudProviders
			url_params.append(f'cloudProviders={cloudProviders}')
		if clusters != None:
			clusters = ",".join(clusters) if isinstance(clusters, list) else clusters
			url_params.append(f'clusters={clusters}')
		if collectorGroups != None:
			collectorGroups = ",".join(collectorGroups) if isinstance(collectorGroups, list) else collectorGroups
			url_params.append(f'collectorGroups={collectorGroups}')
		if collectorGroupsIds != None:
			collectorGroupsIds = ",".join(map(str, collectorGroupsIds)) if isinstance(collectorGroupsIds, list) else collectorGroupsIds
			url_params.append(f'collectorGroupsIds={collectorGroupsIds}')
		if collectorType != None:
			url_params.append(f'collectorType={collectorType}')
		if devices != None:
			devices = ",".join(devices) if isinstance(devices, list) else devices
			url_params.append(f'devices={devices}')
		if devicesIds != None:
			devicesIds = ",".join(map(str, devicesIds)) if isinstance(devicesIds, list) else devicesIds
			url_params.append(f'devicesIds={devicesIds}')
		if enable != None:
			url_params.append(f'enable={enable}')
		if firstSeen != None:
			url_params.append(f'firstSeen={firstSeen}')
		if hasCrashDumps != None:
			url_params.append(f'hasCrashDumps={hasCrashDumps}')
		if ips != None:
			ips = ",".join(ips) if isinstance(ips, list) else ips
			url_params.append(f'ips={ips}')
		if itemsPerPage != None:
			url_params.append(f'itemsPerPage={itemsPerPage}')
		if lastSeenEnd != None:
			url_params.append(f'lastSeenEnd={lastSeenEnd}')
		if lastSeenStart != None:
			url_params.append(f'lastSeenStart={lastSeenStart}')
		if loggedUser != None:
			url_params.append(f'loggedUser={loggedUser}')
		if operatingSystems != None:
			operatingSystems = ",".join(operatingSystems) if isinstance(operatingSystems, list) else operatingSystems
			url_params.append(f'operatingSystems={operatingSystems}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if osFamilies != None:
			osFamilies = ",".join(osFamilies) if isinstance(osFamilies, list) else osFamilies
			url_params.append(f'osFamilies={osFamilies}')
		if pageNumber != None:
			url_params.append(f'pageNumber={pageNumber}')
		if showExpired != None:
			url_params.append(f'showExpired={showExpired}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if states != None:
			states = ",".join(states) if isinstance(states, list) else states
			url_params.append(f'states={states}')
		if strictMode != None:
			url_params.append(f'strictMode={strictMode}')
		if versions != None:
			versions = ",".join(versions) if isinstance(versions, list) else versions
			url_params.append(f'versions={versions}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def uninstall_collectors(self, organization: str, collectorIDs: list = None, collectorSIDs: list = None) -> tuple[bool, list]:
		'''
		Class SystemInventory
		Description: This API uninstall collectors.
        
		Args:
			collectorIDs (list): Specifies the list of device ids
			collectorSIDs (list): Specifies the list of device machine SID
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("uninstall_collectors", locals())

		url = '/management-rest/inventory/uninstall-collectors'
		url_params = []
		if collectorIDs != None:
			collectorIDs = ",".join(map(str, collectorIDs)) if isinstance(collectorIDs, list) else collectorIDs
			url_params.append(f'collectorIDs={collectorIDs}')
		if collectorSIDs != None:
			collectorSIDs = ",".join(collectorSIDs) if isinstance(collectorSIDs, list) else collectorSIDs
			url_params.append(f'collectorSIDs={collectorSIDs}')
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.send(url)

	def unisolate_collectors(self, organization: str, devices: list = None, devicesIds: list = None) -> tuple[bool, None]:
		'''
		Class SystemInventory
		Description: This API call isolate collector functionality.
        
		Args:
			devices (list): Specifies the list of device names
			devicesIds (list): Specifies the list of device ids
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("unisolate_collectors", locals())

		url = '/management-rest/inventory/unisolate-collectors'
		url_params = []
		if devices != None:
			devices = ",".join(devices) if isinstance(devices, list) else devices
			url_params.append(f'devices={devices}')
		if devicesIds != None:
			devicesIds = ",".join(map(str, devicesIds)) if isinstance(devicesIds, list) else devicesIds
			url_params.append(f'devicesIds={devicesIds}')
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def update_collector_group_name(self, collectorGroupId: int, groupName: str) -> tuple[bool, None]:
		'''
		Class SystemInventory
		Description: This API updates collector group name!.
        
		Args:
			collectorGroupId (int): Collector Group id
			groupName (str): New group name

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("update_collector_group_name", locals())

		url = '/management-rest/inventory/update-collector-group-name'
		url_params = []
		if collectorGroupId != None:
			url_params.append(f'collectorGroupId={collectorGroupId}')
		if groupName != None:
			url_params.append(f'groupName={groupName}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

class IoT:
	'''The IoT module enables you to monitor the devices found in IoT scans and create/move IoT Groups.'''

	def create_iot_group(self, name: str, organization: str) -> tuple[bool, None]:
		'''
		Class IoT
		Description: This API call create IoT group.
        
		Args:
			name (str): IoT group name
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("create_iot_group", locals())

		url = '/management-rest/iot/create-iot-group'
		url_params = []
		if name != None:
			url_params.append(f'name={name}')
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.send(url)

	def delete_devices(self, categories: list = None, devices: list = None, devicesIds: list = None, firstSeenEnd: str = None, firstSeenStart: str = None, internalIps: list = None, iotGroups: list = None, iotGroupsIds: list = None, itemsPerPage: int = None, lastSeenEnd: str = None, lastSeenStart: str = None, locations: list = None, macAddresses: list = None, models: list = None, organization: str = None, pageNumber: int = None, showExpired: bool = None, sorting: str = None, strictMode: bool = None, vendors: list = None) -> tuple[bool, None]:
		'''
		Class IoT
		Description: This API call deletes a IoT device(s).
        
		Args:
			categories (list): Specifies the list of categories values
			devices (list): Specifies the list of device names
			devicesIds (list): Specifies the list of device ids
			firstSeenEnd (str): Retrieves IoT devices that were first seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss
			firstSeenStart (str): Retrieves IoT devices that were first seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss
			internalIps (list): Specifies the list of IP values
			iotGroups (list): Specifies the list of collector group names and retrieves collectors under the given groups
			iotGroupsIds (list): Specifies the list of collector group ids and retrieves collectors under the given groups
			itemsPerPage (int): An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000
			lastSeenEnd (str): Retrieves IoT devices that were last seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss
			lastSeenStart (str): Retrieves IoT devices that were last seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss
			locations (list): Specifies the list of locations values
			macAddresses (list): Specifies the list of mac address values
			models (list): Specifies the list of models values
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			
			pageNumber (int): An integer used for paging that indicates the required page number
			showExpired (bool): Specifies whether to include IoT devices which have been disconnected for more than 3 days (sequentially) and are marked as Expired
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on
			strictMode (bool): A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False
			vendors (list): Specifies the list of vendors values

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_devices", locals())

		url = '/management-rest/iot/delete-devices'
		url_params = []
		if categories != None:
			categories = ",".join(categories) if isinstance(categories, list) else categories
			url_params.append(f'categories={categories}')
		if devices != None:
			devices = ",".join(devices) if isinstance(devices, list) else devices
			url_params.append(f'devices={devices}')
		if devicesIds != None:
			devicesIds = ",".join(map(str, devicesIds)) if isinstance(devicesIds, list) else devicesIds
			url_params.append(f'devicesIds={devicesIds}')
		if firstSeenEnd != None:
			url_params.append(f'firstSeenEnd={firstSeenEnd}')
		if firstSeenStart != None:
			url_params.append(f'firstSeenStart={firstSeenStart}')
		if internalIps != None:
			internalIps = ",".join(internalIps) if isinstance(internalIps, list) else internalIps
			url_params.append(f'internalIps={internalIps}')
		if iotGroups != None:
			iotGroups = ",".join(iotGroups) if isinstance(iotGroups, list) else iotGroups
			url_params.append(f'iotGroups={iotGroups}')
		if iotGroupsIds != None:
			iotGroupsIds = ",".join(map(str, iotGroupsIds)) if isinstance(iotGroupsIds, list) else iotGroupsIds
			url_params.append(f'iotGroupsIds={iotGroupsIds}')
		if itemsPerPage != None:
			url_params.append(f'itemsPerPage={itemsPerPage}')
		if lastSeenEnd != None:
			url_params.append(f'lastSeenEnd={lastSeenEnd}')
		if lastSeenStart != None:
			url_params.append(f'lastSeenStart={lastSeenStart}')
		if locations != None:
			locations = ",".join(locations) if isinstance(locations, list) else locations
			url_params.append(f'locations={locations}')
		if macAddresses != None:
			macAddresses = ",".join(macAddresses) if isinstance(macAddresses, list) else macAddresses
			url_params.append(f'macAddresses={macAddresses}')
		if models != None:
			models = ",".join(models) if isinstance(models, list) else models
			url_params.append(f'models={models}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if pageNumber != None:
			url_params.append(f'pageNumber={pageNumber}')
		if showExpired != None:
			url_params.append(f'showExpired={showExpired}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if strictMode != None:
			url_params.append(f'strictMode={strictMode}')
		if vendors != None:
			vendors = ",".join(vendors) if isinstance(vendors, list) else vendors
			url_params.append(f'vendors={vendors}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def export_iot_json(self, iotDeviceIds: list, organization: str = None) -> tuple[bool, None]:
		'''
		Class IoT
		Description: This API call outputs a list of the IoT devices info.
        
		Args:
			iotDeviceIds (list): Specifies the list of device ids
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("export_iot_json", locals())

		url = '/management-rest/iot/export-iot-json'
		url_params = []
		if iotDeviceIds != None:
			iotDeviceIds = ",".join(map(str, iotDeviceIds)) if isinstance(iotDeviceIds, list) else iotDeviceIds
			url_params.append(f'iotDeviceIds={iotDeviceIds}')
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def list_iot_devices(self, categories: list = None, devices: list = None, devicesIds: list = None, firstSeenEnd: str = None, firstSeenStart: str = None, internalIps: list = None, iotGroups: list = None, iotGroupsIds: list = None, itemsPerPage: int = None, lastSeenEnd: str = None, lastSeenStart: str = None, locations: list = None, macAddresses: list = None, models: list = None, organization: str = None, pageNumber: int = None, showExpired: bool = None, sorting: str = None, strictMode: bool = None, vendors: list = None) -> tuple[bool, list]:
		'''
		Class IoT
		Description: This API call outputs a list of the IoT devices in the system. Use the input parameters to filter the list.
        
		Args:
			categories (list): Specifies the list of categories values
			devices (list): Specifies the list of device names
			devicesIds (list): Specifies the list of device ids
			firstSeenEnd (str): Retrieves IoT devices that were first seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss
			firstSeenStart (str): Retrieves IoT devices that were first seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss
			internalIps (list): Specifies the list of IP values
			iotGroups (list): Specifies the list of collector group names and retrieves collectors under the given groups
			iotGroupsIds (list): Specifies the list of collector group ids and retrieves collectors under the given groups
			itemsPerPage (int): An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000
			lastSeenEnd (str): Retrieves IoT devices that were last seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss
			lastSeenStart (str): Retrieves IoT devices that were last seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss
			locations (list): Specifies the list of locations values
			macAddresses (list): Specifies the list of mac address values
			models (list): Specifies the list of models values
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			
			pageNumber (int): An integer used for paging that indicates the required page number
			showExpired (bool): Specifies whether to include IoT devices which have been disconnected for more than 3 days (sequentially) and are marked as Expired
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on
			strictMode (bool): A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False
			vendors (list): Specifies the list of vendors values

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_iot_devices", locals())

		url = '/management-rest/iot/list-iot-devices'
		url_params = []
		if categories != None:
			categories = ",".join(categories) if isinstance(categories, list) else categories
			url_params.append(f'categories={categories}')
		if devices != None:
			devices = ",".join(devices) if isinstance(devices, list) else devices
			url_params.append(f'devices={devices}')
		if devicesIds != None:
			devicesIds = ",".join(map(str, devicesIds)) if isinstance(devicesIds, list) else devicesIds
			url_params.append(f'devicesIds={devicesIds}')
		if firstSeenEnd != None:
			url_params.append(f'firstSeenEnd={firstSeenEnd}')
		if firstSeenStart != None:
			url_params.append(f'firstSeenStart={firstSeenStart}')
		if internalIps != None:
			internalIps = ",".join(internalIps) if isinstance(internalIps, list) else internalIps
			url_params.append(f'internalIps={internalIps}')
		if iotGroups != None:
			iotGroups = ",".join(iotGroups) if isinstance(iotGroups, list) else iotGroups
			url_params.append(f'iotGroups={iotGroups}')
		if iotGroupsIds != None:
			iotGroupsIds = ",".join(map(str, iotGroupsIds)) if isinstance(iotGroupsIds, list) else iotGroupsIds
			url_params.append(f'iotGroupsIds={iotGroupsIds}')
		if itemsPerPage != None:
			url_params.append(f'itemsPerPage={itemsPerPage}')
		if lastSeenEnd != None:
			url_params.append(f'lastSeenEnd={lastSeenEnd}')
		if lastSeenStart != None:
			url_params.append(f'lastSeenStart={lastSeenStart}')
		if locations != None:
			locations = ",".join(locations) if isinstance(locations, list) else locations
			url_params.append(f'locations={locations}')
		if macAddresses != None:
			macAddresses = ",".join(macAddresses) if isinstance(macAddresses, list) else macAddresses
			url_params.append(f'macAddresses={macAddresses}')
		if models != None:
			models = ",".join(models) if isinstance(models, list) else models
			url_params.append(f'models={models}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if pageNumber != None:
			url_params.append(f'pageNumber={pageNumber}')
		if showExpired != None:
			url_params.append(f'showExpired={showExpired}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if strictMode != None:
			url_params.append(f'strictMode={strictMode}')
		if vendors != None:
			vendors = ",".join(vendors) if isinstance(vendors, list) else vendors
			url_params.append(f'vendors={vendors}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def list_iot_groups(self, organization: str = None) -> tuple[bool, list]:
		'''
		Class IoT
		Description: This API call output the IoT devices groups.
        
		Args:
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_iot_groups", locals())

		url = '/management-rest/iot/list-iot-groups'
		url_params = []
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def move_iot_devices(self, iotDeviceIds: list, organization: str, targetIotGroup: str) -> tuple[bool, None]:
		'''
		Class IoT
		Description: This API call move IoT devices between groups.
        
		Args:
			iotDeviceIds (list): Array of IoT device ids
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			targetIotGroup (str): IoT target group name

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("move_iot_devices", locals())

		url = '/management-rest/iot/move-iot-devices'
		url_params = []
		if iotDeviceIds != None:
			iotDeviceIds = ",".join(map(str, iotDeviceIds)) if isinstance(iotDeviceIds, list) else iotDeviceIds
			url_params.append(f'iotDeviceIds={iotDeviceIds}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if targetIotGroup != None:
			url_params.append(f'targetIotGroup={targetIotGroup}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def rescan_iot_device_details(self, categories: list = None, devices: list = None, devicesIds: list = None, firstSeenEnd: str = None, firstSeenStart: str = None, internalIps: list = None, iotGroups: list = None, iotGroupsIds: list = None, itemsPerPage: int = None, lastSeenEnd: str = None, lastSeenStart: str = None, locations: list = None, macAddresses: list = None, models: list = None, organization: str = None, pageNumber: int = None, showExpired: bool = None, sorting: str = None, strictMode: bool = None, vendors: list = None) -> tuple[bool, str]:
		'''
		Class IoT
		Description: This API call device details scan on IoT device(s).
        
		Args:
			categories (list): Specifies the list of categories values
			devices (list): Specifies the list of device names
			devicesIds (list): Specifies the list of device ids
			firstSeenEnd (str): Retrieves IoT devices that were first seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss
			firstSeenStart (str): Retrieves IoT devices that were first seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss
			internalIps (list): Specifies the list of IP values
			iotGroups (list): Specifies the list of collector group names and retrieves collectors under the given groups
			iotGroupsIds (list): Specifies the list of collector group ids and retrieves collectors under the given groups
			itemsPerPage (int): An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000
			lastSeenEnd (str): Retrieves IoT devices that were last seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss
			lastSeenStart (str): Retrieves IoT devices that were last seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss
			locations (list): Specifies the list of locations values
			macAddresses (list): Specifies the list of mac address values
			models (list): Specifies the list of models values
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			
			pageNumber (int): An integer used for paging that indicates the required page number
			showExpired (bool): Specifies whether to include IoT devices which have been disconnected for more than 3 days (sequentially) and are marked as Expired
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on
			strictMode (bool): A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False
			vendors (list): Specifies the list of vendors values

		Returns:
			bool: Status of the request (True or False). 
			str
		'''
		validate_params("rescan_iot_device_details", locals())

		url = '/management-rest/iot/rescan-iot-device-details'
		url_params = []
		if categories != None:
			categories = ",".join(categories) if isinstance(categories, list) else categories
			url_params.append(f'categories={categories}')
		if devices != None:
			devices = ",".join(devices) if isinstance(devices, list) else devices
			url_params.append(f'devices={devices}')
		if devicesIds != None:
			devicesIds = ",".join(map(str, devicesIds)) if isinstance(devicesIds, list) else devicesIds
			url_params.append(f'devicesIds={devicesIds}')
		if firstSeenEnd != None:
			url_params.append(f'firstSeenEnd={firstSeenEnd}')
		if firstSeenStart != None:
			url_params.append(f'firstSeenStart={firstSeenStart}')
		if internalIps != None:
			internalIps = ",".join(internalIps) if isinstance(internalIps, list) else internalIps
			url_params.append(f'internalIps={internalIps}')
		if iotGroups != None:
			iotGroups = ",".join(iotGroups) if isinstance(iotGroups, list) else iotGroups
			url_params.append(f'iotGroups={iotGroups}')
		if iotGroupsIds != None:
			iotGroupsIds = ",".join(map(str, iotGroupsIds)) if isinstance(iotGroupsIds, list) else iotGroupsIds
			url_params.append(f'iotGroupsIds={iotGroupsIds}')
		if itemsPerPage != None:
			url_params.append(f'itemsPerPage={itemsPerPage}')
		if lastSeenEnd != None:
			url_params.append(f'lastSeenEnd={lastSeenEnd}')
		if lastSeenStart != None:
			url_params.append(f'lastSeenStart={lastSeenStart}')
		if locations != None:
			locations = ",".join(locations) if isinstance(locations, list) else locations
			url_params.append(f'locations={locations}')
		if macAddresses != None:
			macAddresses = ",".join(macAddresses) if isinstance(macAddresses, list) else macAddresses
			url_params.append(f'macAddresses={macAddresses}')
		if models != None:
			models = ",".join(models) if isinstance(models, list) else models
			url_params.append(f'models={models}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if pageNumber != None:
			url_params.append(f'pageNumber={pageNumber}')
		if showExpired != None:
			url_params.append(f'showExpired={showExpired}')
		if sorting != None:
			url_params.append(f'sorting={sorting}')
		if strictMode != None:
			url_params.append(f'strictMode={strictMode}')
		if vendors != None:
			vendors = ",".join(vendors) if isinstance(vendors, list) else vendors
			url_params.append(f'vendors={vendors}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

class IPsets:
	'''API to define IPs sets and use them for exceptions'''

	def create_ip_set(self, include: list, name: str, description: str = None, exclude: list = None, organization: str = None) -> tuple[bool, None]:
		'''
		Class IPsets
		Description: This API create IP sets in the system.
	Use the input parameter organization=All organizations to create for all the organization. (only for Admin role.
        
		Args:
			ipGroupsRequest (Object): Check 'ipGroupsRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("create_ip_set", locals())

		url = '/management-rest/ip-sets/create-ip-set'

		ipGroupsRequest = {}
		if description:
			ipGroupsRequest["description"] = f"{description}"
		if exclude:
			ipGroupsRequest["exclude"] = f"{exclude}"
		if include:
			ipGroupsRequest["include"] = f"{include}"
		if name:
			ipGroupsRequest["name"] = f"{name}"
		if organization:
			ipGroupsRequest["organization"] = f"{organization}"

		return fortiedr_connection.send(url, ipGroupsRequest)

	def delete_ip_set(self, ipSets: list, organization: str = None) -> tuple[bool, None]:
		'''
		Class IPsets
		Description: This API delete IP sets from the system. Use the input parameters to filter organization.
        
		Args:
			ipSets (list): Specifies the list of IP name to delete
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_ip_set", locals())

		url = '/management-rest/ip-sets/delete-ip-set'
		url_params = []
		if ipSets != None:
			ipSets = ",".join(ipSets) if isinstance(ipSets, list) else ipSets
			url_params.append(f'ipSets={ipSets}')
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def list_ip_sets(self, ip: str = None, organization: str = None) -> tuple[bool, list]:
		'''
		Class IPsets
		Description: This API call outputs a list of the IP sets in the system. Use the input parameters to filter the list.
        
		Args:
			ip (str): Specifies the IP of the requested sets
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_ip_sets", locals())

		url = '/management-rest/ip-sets/list-ip-sets'
		url_params = []
		if ip != None:
			url_params.append(f'ip={ip}')
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def update_ip_set(self, include: list, name: str, description: str = None, exclude: list = None, organization: str = None) -> tuple[bool, None]:
		'''
		Class IPsets
		Description: This API update IP sets in the system. Use the input parameters to filter organization.
        
		Args:
			ipGroupsRequest (Object): Check 'ipGroupsRequest' in the API documentation for further information.
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non-shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			•	each – Indicates that the operation applies independently to each organization. For example, let's assume that the same user exists in multiple organizations. When each is specified in the organization parameter, then each organization can update this user separately.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("update_ip_set", locals())

		url = '/management-rest/ip-sets/update-ip-set'
		url_params = []
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)

		ipGroupsRequest = {}
		if description:
			ipGroupsRequest["description"] = f"{description}"
		if exclude:
			ipGroupsRequest["exclude"] = f"{exclude}"
		if include:
			ipGroupsRequest["include"] = f"{include}"
		if name:
			ipGroupsRequest["name"] = f"{name}"

		return fortiedr_connection.insert(url, ipGroupsRequest)

class Organizations:
	'''Organizations API'''

	def create_organization(self, eXtendedDetection: bool = None, edr: bool = None, edrAddOnsAllocated: int = None, edrBackupEnabled: bool = None, edrEnabled: bool = None, edrNumberOfShards: int = None, edrStorageAllocatedInMb: int = None, expirationDate: str = None, forensics: bool = None, iotAllocated: int = None, name: str = None, password: str = None, passwordConfirmation: str = None, requestPolicyEngineLibUpdates: bool = None, serialNumber: str = None, serversAllocated: int = None, vulnerabilityAndIoT: bool = None, workstationsAllocated: int = None) -> tuple[bool, None]:
		'''
		Class Organizations
		Description: This API creates organization in the system (only for Admin role).
        
		Args:
			createAccountRequest (Object): Check 'createAccountRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("create_organization", locals())

		url = '/management-rest/organizations/create-organization'

		createAccountRequest = {}
		if eXtendedDetection:
			createAccountRequest["eXtendedDetection"] = f"{eXtendedDetection}"
		if edr:
			createAccountRequest["edr"] = f"{edr}"
		if edrAddOnsAllocated != None:
			createAccountRequest["edrAddOnsAllocated"] = f"{edrAddOnsAllocated}"
		if edrBackupEnabled:
			createAccountRequest["edrBackupEnabled"] = f"{edrBackupEnabled}"
		if edrEnabled:
			createAccountRequest["edrEnabled"] = f"{edrEnabled}"
		if edrNumberOfShards != None:
			createAccountRequest["edrNumberOfShards"] = f"{edrNumberOfShards}"
		if edrStorageAllocatedInMb != None:
			createAccountRequest["edrStorageAllocatedInMb"] = f"{edrStorageAllocatedInMb}"
		if endpointsAllocated != None:
			createAccountRequest["endpointsAllocated"] = f"{endpointsAllocated}"
		if expirationDate:
			createAccountRequest["expirationDate"] = f"{expirationDate}"
		if forensics:
			createAccountRequest["forensics"] = f"{forensics}"
		if iotAllocated != None:
			createAccountRequest["iotAllocated"] = f"{iotAllocated}"
		if mobileEnabled:
			createAccountRequest["mobileEnabled"] = f"{mobileEnabled}"
		if name:
			createAccountRequest["name"] = f"{name}"
		if password:
			createAccountRequest["password"] = f"{password}"
		if passwordConfirmation:
			createAccountRequest["passwordConfirmation"] = f"{passwordConfirmation}"
		if requestPolicyEngineLibUpdates:
			createAccountRequest["requestPolicyEngineLibUpdates"] = f"{requestPolicyEngineLibUpdates}"
		if secureBrowserEnabled:
			createAccountRequest["secureBrowserEnabled"] = f"{secureBrowserEnabled}"
		if serialNumber:
			createAccountRequest["serialNumber"] = f"{serialNumber}"
		if serversAllocated != None:
			createAccountRequest["serversAllocated"] = f"{serversAllocated}"
		if vulnerabilityAndIoT:
			createAccountRequest["vulnerabilityAndIoT"] = f"{vulnerabilityAndIoT}"
		if workstationsAllocated != None:
			createAccountRequest["workstationsAllocated"] = f"{workstationsAllocated}"
		if endpointsAllocated != None:
			createAccountRequest["endpointsAllocated"] = f"{endpointsAllocated}"
		if mobileEnabled:
			createAccountRequest["mobileEnabled"] = f"{mobileEnabled}"
		if secureBrowserEnabled:
			createAccountRequest["secureBrowserEnabled"] = f"{secureBrowserEnabled}"


		return fortiedr_connection.send(url, createAccountRequest)

	def delete_organization(self, organization: str = None) -> tuple[bool, None]:
		'''
		Class Organizations
		Description: This API delete organization in the system (only for Admin role).
        
		Args:
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_organization", locals())

		url = '/management-rest/organizations/delete-organization'
		url_params = []
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def get_available_license_count(self) -> tuple[bool, list]:
		'''
		Class Organizations
		Description: This API returns number of remained licenses for all organizations.
        
		Args:

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("get_available_license_count", locals())

		url = '/management-rest/organizations/get-available-license-count'
		return fortiedr_connection.get(url)

	def list_organizations(self) -> tuple[bool, list]:
		'''
		Class Organizations
		Description: This API call outputs a list of the accounts in the system..
        
		Args:

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_organizations", locals())

		url = '/management-rest/organizations/list-organizations'
		return fortiedr_connection.get(url)

	def update_organization(self, organization: str, eXtendedDetection: bool = None, edr: bool = None, edrAddOnsAllocated: int = None, edrBackupEnabled: bool = None, edrEnabled: bool = None, edrNumberOfShards: int = None, edrStorageAllocatedInMb: int = None, endpointsAllocated: int = None, expirationDate: str = None, forensics: bool = None, iotAllocated: int = None, mobileEnabled: bool = None, name: str = None, requestPolicyEngineLibUpdates: bool = None, secureBrowserEnabled: bool = None, serialNumber: str = None, serversAllocated: int = None, vulnerabilityAndIoT: bool = None, workstationsAllocated: int = None) -> tuple[bool, None]:
		'''
		Class Organizations
		Description: This API update organization in the system (only for Admin role).
        
		Args:
			accountRequest (Object): Check 'accountRequest' in the API documentation for further information.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("update_organization", locals())

		url = '/management-rest/organizations/update-organization'
		url_params = []
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)

		accountRequest = {}
		if eXtendedDetection:
			accountRequest["eXtendedDetection"] = f"{eXtendedDetection}"
		if edr:
			accountRequest["edr"] = f"{edr}"
		if edrAddOnsAllocated != None:
			accountRequest["edrAddOnsAllocated"] = f"{edrAddOnsAllocated}"
		if edrBackupEnabled:
			accountRequest["edrBackupEnabled"] = f"{edrBackupEnabled}"
		if edrEnabled:
			accountRequest["edrEnabled"] = f"{edrEnabled}"
		if edrNumberOfShards != None:
			accountRequest["edrNumberOfShards"] = f"{edrNumberOfShards}"
		if edrStorageAllocatedInMb != None:
			accountRequest["edrStorageAllocatedInMb"] = f"{edrStorageAllocatedInMb}"
		if endpointsAllocated != None:
			accountRequest["endpointsAllocated"] = f"{endpointsAllocated}"
		if expirationDate:
			accountRequest["expirationDate"] = f"{expirationDate}"
		if forensics:
			accountRequest["forensics"] = f"{forensics}"
		if iotAllocated != None:
			accountRequest["iotAllocated"] = f"{iotAllocated}"
		if mobileEnabled:
			accountRequest["mobileEnabled"] = f"{mobileEnabled}"
		if name:
			accountRequest["name"] = f"{name}"
		if requestPolicyEngineLibUpdates:
			accountRequest["requestPolicyEngineLibUpdates"] = f"{requestPolicyEngineLibUpdates}"
		if secureBrowserEnabled:
			accountRequest["secureBrowserEnabled"] = f"{secureBrowserEnabled}"
		if serialNumber:
			accountRequest["serialNumber"] = f"{serialNumber}"
		if serversAllocated != None:
			accountRequest["serversAllocated"] = f"{serversAllocated}"
		if vulnerabilityAndIoT:
			accountRequest["vulnerabilityAndIoT"] = f"{vulnerabilityAndIoT}"
		if workstationsAllocated != None:
			accountRequest["workstationsAllocated"] = f"{workstationsAllocated}"

		return fortiedr_connection.insert(url, accountRequest)

class Playbookspolicies:
	'''Playbooks-policies API'''

	def assign_collector_group(self, collectorGroupNames: list, organization: str, policyName: str, forceAssign: bool = None) -> tuple[bool, None]:
		'''
		Class Playbookspolicies
		Description: Assign collector group to air policy.
        
		Args:
			collectorGroupNames (list): Specifies the list of collector group names
			forceAssign (bool): Indicates whether to force the assignment even if the group is assigned to similar policies
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			policyName (str): Specifies policy name

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("assign_collector_group", locals())

		url = '/management-rest/playbooks-policies/assign-collector-group'
		url_params = []
		if collectorGroupNames != None:
			collectorGroupNames = ",".join(collectorGroupNames) if isinstance(collectorGroupNames, list) else collectorGroupNames
			url_params.append(f'collectorGroupNames={collectorGroupNames}')
		if forceAssign != None:
			url_params.append(f'forceAssign={forceAssign}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if policyName != None:
			url_params.append(f'policyName={policyName}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def clone(self, newPolicyName: str, organization: str, sourcePolicyName: str) -> tuple[bool, list]:
		'''
		Class Playbookspolicies
		Description: clone policy.
        
		Args:
			newPolicyName (str): Specifies security policy target name.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			sourcePolicyName (str): Specifies security policy source name

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("clone", locals())

		url = '/management-rest/playbooks-policies/clone'
		url_params = []
		if newPolicyName != None:
			url_params.append(f'newPolicyName={newPolicyName}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if sourcePolicyName != None:
			url_params.append(f'sourcePolicyName={sourcePolicyName}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.send(url)

	def list_policies(self, organization: str = None) -> tuple[bool, list]:
		'''
		Class Playbookspolicies
		Description: List policies.
        
		Args:
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_policies", locals())

		url = '/management-rest/playbooks-policies/list-policies'
		url_params = []
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def map_connectors_to_actions(self, policyName: str, organization: str, customActionsToConnectorsMaps: list = None, fortinetActionsToConnectorsMaps: list = None) -> tuple[bool, None]:
		'''
		Class Playbookspolicies
		Description: Assign policy actions with connectors..
        
		Args:
			assignAIRActionsWithConnectorsRequest (Object): Check 'assignAIRActionsWithConnectorsRequest' in the API documentation for further information.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("map_connectors_to_actions", locals())

		url = '/management-rest/playbooks-policies/map-connectors-to-actions'
		url_params = []
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)

		assignAIRActionsWithConnectorsRequest = {}
		if customActionsToConnectorsMaps:
			assignAIRActionsWithConnectorsRequest["customActionsToConnectorsMaps"] = f"{customActionsToConnectorsMaps}"
		if fortinetActionsToConnectorsMaps:
			assignAIRActionsWithConnectorsRequest["fortinetActionsToConnectorsMaps"] = f"{fortinetActionsToConnectorsMaps}"
		if policyName:
			assignAIRActionsWithConnectorsRequest["policyName"] = f"{policyName}"

		return fortiedr_connection.insert(url, assignAIRActionsWithConnectorsRequest)

	def set_action_classification(self, organization: str, policyName: str, customActionsToClassificationMaps: list = None, fortinetActionsToClassificationMaps: list = None) -> tuple[bool, None]:
		'''
		Class Playbookspolicies
		Description: Set the air policy actions' classifications..
        
		Args:
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			setActionsClassificationRequest (Object): Check 'setActionsClassificationRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("set_action_classification", locals())

		url = '/management-rest/playbooks-policies/set-action-classification'
		url_params = []
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)

		setActionsClassificationRequest = {}
		if customActionsToClassificationMaps:
			setActionsClassificationRequest["customActionsToClassificationMaps"] = f"{customActionsToClassificationMaps}"
		if fortinetActionsToClassificationMaps:
			setActionsClassificationRequest["fortinetActionsToClassificationMaps"] = f"{fortinetActionsToClassificationMaps}"
		if policyName:
			setActionsClassificationRequest["policyName"] = f"{policyName}"

		return fortiedr_connection.insert(url, setActionsClassificationRequest)

	def set_mode(self, mode: str, organization: str, policyName: str) -> tuple[bool, None]:
		'''
		Class Playbookspolicies
		Description: Set playbook to simulation/prevention.
        
		Args:
			mode (str): Operation mode
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			policyName (str): Specifies security policy name

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("set_mode", locals())

		url = '/management-rest/playbooks-policies/set-mode'
		url_params = []
		if mode != None:
			url_params.append(f'mode={mode}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if policyName != None:
			url_params.append(f'policyName={policyName}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

class Policies:
	'''Policies API'''

	def assign_collector_group(self, collectorsGroupName: list, organization: str, policyName: str, forceAssign: bool = None) -> tuple[bool, None]:
		'''
		Class Policies
		Description: Assign collector group to policy.
        
		Args:
			collectorsGroupName (list): Specifies the list of collector group names
			forceAssign (bool): Indicates whether to force the assignment even if the group is assigned to similar policies
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			policyName (str): Specifies security policy name

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("assign_collector_group", locals())

		url = '/management-rest/policies/assign-collector-group'
		url_params = []
		if collectorsGroupName != None:
			collectorsGroupName = ",".join(collectorsGroupName) if isinstance(collectorsGroupName, list) else collectorsGroupName
			url_params.append(f'collectorsGroupName={collectorsGroupName}')
		if forceAssign != None:
			url_params.append(f'forceAssign={forceAssign}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if policyName != None:
			url_params.append(f'policyName={policyName}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def clone(self, newPolicyName: str, organization: str, sourcePolicyName: str) -> tuple[bool, list]:
		'''
		Class Policies
		Description: clone policy.
        
		Args:
			newPolicyName (str): Specifies security policy target name.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			sourcePolicyName (str): Specifies security policy source name

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("clone", locals())

		url = '/management-rest/policies/clone'
		url_params = []
		if newPolicyName != None:
			url_params.append(f'newPolicyName={newPolicyName}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if sourcePolicyName != None:
			url_params.append(f'sourcePolicyName={sourcePolicyName}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.send(url)

	def list_policies(self, organization: str = None) -> tuple[bool, list]:
		'''
		Class Policies
		Description: List policies.
        
		Args:
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_policies", locals())

		url = '/management-rest/policies/list-policies'
		url_params = []
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def scan_files(self, applyRecursiveScan: bool, executableFilesOnly: bool, organization: str, origin: str, scanBy: str, filePaths: list = None, scanSelection: list = None) -> tuple[bool, None]:
		'''
		Class Policies
		Description: Scan Files.
        
		Args:
			applyRecursiveScan (bool): Specifies if execution includes recursive scan
			executableFilesOnly (bool): Specifies if execution includes only files
			filePaths (list): Specifies file path
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			origin (str): Specifies scan origin
			scanBy (str): Specifies scan by choice
			scanSelection (list): Specifies scan selection

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("scan_files", locals())

		url = '/management-rest/policies/scan-files'
		url_params = []
		if applyRecursiveScan != None:
			url_params.append(f'applyRecursiveScan={applyRecursiveScan}')
		if executableFilesOnly != None:
			url_params.append(f'executableFilesOnly={executableFilesOnly}')
		if filePaths != None:
			filePaths = ",".join(filePaths) if isinstance(filePaths, list) else filePaths
			url_params.append(f'filePaths={filePaths}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if origin != None:
			url_params.append(f'origin={origin}')
		if scanBy != None:
			url_params.append(f'scanBy={scanBy}')
		if scanSelection != None:
			scanSelection = ",".join(scanSelection) if isinstance(scanSelection, list) else scanSelection
			url_params.append(f'scanSelection={scanSelection}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.send(url)

	def set_mode(self, mode: str, organization: str, policyName: str) -> tuple[bool, None]:
		'''
		Class Policies
		Description: Set policy to simulation/prevention.
        
		Args:
			mode (str): Operation mode
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			policyName (str): Specifies security policy name

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("set_mode", locals())

		url = '/management-rest/policies/set-mode'
		url_params = []
		if mode != None:
			url_params.append(f'mode={mode}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if policyName != None:
			url_params.append(f'policyName={policyName}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def set_policy_rule_action(self, action: str, organization: str, policyName: str, ruleName: str) -> tuple[bool, None]:
		'''
		Class Policies
		Description: Set rule in policy to block/log.
        
		Args:
			action (str): Specifies the policy action
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			policyName (str): Specifies security policy name
			ruleName (str): Specifies rule name

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("set_policy_rule_action", locals())

		url = '/management-rest/policies/set-policy-rule-action'
		url_params = []
		if action != None:
			url_params.append(f'action={action}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if policyName != None:
			url_params.append(f'policyName={policyName}')
		if ruleName != None:
			url_params.append(f'ruleName={ruleName}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def set_policy_rule_state(self, organization: str, policyName: str, ruleName: str, state: str) -> tuple[bool, None]:
		'''
		Class Policies
		Description: Set rule in policy to enable/disable.
        
		Args:
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			policyName (str): Specifies security policy name
			ruleName (str): Specifies rule name
			state (str): Policy rule state

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("set_policy_rule_state", locals())

		url = '/management-rest/policies/set-policy-rule-state'
		url_params = []
		if organization != None:
			url_params.append(f'organization={organization}')
		if policyName != None:
			url_params.append(f'policyName={policyName}')
		if ruleName != None:
			url_params.append(f'ruleName={ruleName}')
		if state != None:
			url_params.append(f'state={state}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

class SendableEntities:
	'''API to create and test sendable entities'''

	def set_mail_format(self, format: str, organization: str) -> tuple[bool, None]:
		'''
		Class SendableEntities
		Description: set mail format.
        
		Args:
			format (str): Specifies email format type
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("set_mail_format", locals())

		url = '/management-rest/sendable-entities/set-mail-format'
		url_params = []
		if format != None:
			url_params.append(f'format={format}')
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def syslog(self, organization: str, host: str, name: str, port: int, protocol: str, syslogFormat: str, syslogRFCFormat: str, certificateBlob: str = None, fazDevId: str = None, privateKeyFile: str = None, privateKeyPassword: str = None, useClientCertificate: bool = None, useSSL: bool = None) -> tuple[bool, None]:
		'''
		Class SendableEntities
		Description: This API creates syslog.
        
		Args:
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			syslogRequest (Object): Check 'syslogRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("syslog", locals())

		url = '/management-rest/sendable-entities/syslog'
		url_params = []
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)

		syslogRequest = {}
		if certificateBlob:
			syslogRequest["certificateBlob"] = f"{certificateBlob}"
		if fazDevId:
			syslogRequest["fazDevId"] = f"{fazDevId}"
		if host:
			syslogRequest["host"] = f"{host}"
		if name:
			syslogRequest["name"] = f"{name}"
		if organization:
			syslogRequest["organization"] = f"{organization}"
		if port != None:
			syslogRequest["port"] = f"{port}"
		if privateKeyFile:
			syslogRequest["privateKeyFile"] = f"{privateKeyFile}"
		if privateKeyPassword:
			syslogRequest["privateKeyPassword"] = f"{privateKeyPassword}"
		if protocol:
			syslogRequest["protocol"] = f"{protocol}"
		if syslogFormat:
			syslogRequest["syslogFormat"] = f"{syslogFormat}"
		if syslogRFCFormat:
			syslogRequest["syslogRFCFormat"] = f"{syslogRFCFormat}"
		if useClientCertificate:
			syslogRequest["useClientCertificate"] = f"{useClientCertificate}"
		if useSSL:
			syslogRequest["useSSL"] = f"{useSSL}"

		return fortiedr_connection.send(url, syslogRequest)

class ExportSettingsSMTP:
	'''Smtp Rest Controller'''

	def get_get_smtp_settings(self, organizationId: int) -> tuple[bool, None]:
		'''
		Class ExportSettingsSMTP
		Description: Load the current SMTP configuration settings.
        
		Args:
			organizationId (int): organizationId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_get_smtp_settings", locals())

		url = '/management-rest/settings/smtp'
		url_params = []
		if organizationId != None:
			url_params.append(f'organizationId={organizationId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def send_save_smtp_settings(self, authenticate: bool = None, encryptionType: str = None, existingPasswordLength: int = None, fromEmail: str = None, organizationId: int = None, password: str = None, port: int = None, senderName: str = None, serverName: str = None, username: str = None) -> tuple[bool, None]:
		'''
		Class ExportSettingsSMTP
		Description: Save new SMTP configuration settings.
        
		Args:
			smtpConfig (Object): Check 'smtpConfig' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("send_save_smtp_settings", locals())

		url = '/management-rest/settings/smtp'

		smtpConfig = {}
		if authenticate:
			smtpConfig["authenticate"] = f"{authenticate}"
		if encryptionType:
			smtpConfig["encryptionType"] = f"{encryptionType}"
		if existingPasswordLength != None:
			smtpConfig["existingPasswordLength"] = f"{existingPasswordLength}"
		if fromEmail:
			smtpConfig["fromEmail"] = f"{fromEmail}"
		if organizationId != None:
			smtpConfig["organizationId"] = f"{organizationId}"
		if password:
			smtpConfig["password"] = f"{password}"
		if port != None:
			smtpConfig["port"] = f"{port}"
		if senderName:
			smtpConfig["senderName"] = f"{senderName}"
		if serverName:
			smtpConfig["serverName"] = f"{serverName}"
		if username:
			smtpConfig["username"] = f"{username}"

		return fortiedr_connection.send(url, smtpConfig)

class ThreatHuntingExclusions:
	'''API to create Threat Hunting exclusions.'''

	def send_exclusion(self, exclusionListName: str, exclusions: list, organization: str) -> tuple[bool, list]:
		'''
		Class ThreatHuntingExclusions
		Description: Creates exclusions..
        
		Args:
			createExclusionsRequest (Object): Check 'createExclusionsRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("send_exclusion", locals())

		url = '/management-rest/threat-hunting-exclusions/exclusion'

		createExclusionsRequest = {}
		if exclusionListName:
			createExclusionsRequest["exclusionListName"] = f"{exclusionListName}"
		if exclusions:
			createExclusionsRequest["exclusions"] = f"{exclusions}"
		if organization:
			createExclusionsRequest["organization"] = f"{organization}"

		return fortiedr_connection.send(url, createExclusionsRequest)

	def insert_exclusions(self, exclusionListName: str, exclusions: list, organization: str) -> tuple[bool, list]:
		'''
		Class ThreatHuntingExclusions
		Description: Update exclusions..
        
		Args:
			updateExclusionsRequest (Object): Check 'updateExclusionsRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("insert_exclusions", locals())

		url = '/management-rest/threat-hunting-exclusions/exclusion'

		updateExclusionsRequest = {}
		if exclusionListName:
			updateExclusionsRequest["exclusionListName"] = f"{exclusionListName}"
		if exclusions:
			updateExclusionsRequest["exclusions"] = f"{exclusions}"
		if organization:
			updateExclusionsRequest["organization"] = f"{organization}"

		return fortiedr_connection.insert(url, updateExclusionsRequest)

	def delete_exclusion(self, exclusionIds: list, organization: str) -> tuple[bool, str]:
		'''
		Class ThreatHuntingExclusions
		Description: Deletes one or more exclusions by Id..
        
		Args:
			deleteExclusionsRequest (Object): Check 'deleteExclusionsRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			str
		'''
		validate_params("delete_exclusion", locals())

		url = '/management-rest/threat-hunting-exclusions/exclusion'

		deleteExclusionsRequest = {}
		if exclusionIds:
			deleteExclusionsRequest["exclusionIds"] = f"{exclusionIds}"
		if organization:
			deleteExclusionsRequest["organization"] = f"{organization}"

		return fortiedr_connection.delete(url, deleteExclusionsRequest)

	def get_exclusions_list(self, organization: str) -> tuple[bool, list]:
		'''
		Class ThreatHuntingExclusions
		Description: Get the list of Exclusions lists..
        
		Args:
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("get_exclusions_list", locals())

		url = '/management-rest/threat-hunting-exclusions/exclusions-list'
		url_params = []
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def send_exclusions_list(self, name: str, organization: str, collectorGroupIds: list = None) -> tuple[bool, None]:
		'''
		Class ThreatHuntingExclusions
		Description: Creates an exclusions list.
        
		Args:
			createExclusionListRequest (Object): Check 'createExclusionListRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("send_exclusions_list", locals())

		url = '/management-rest/threat-hunting-exclusions/exclusions-list'

		createExclusionListRequest = {}
		if collectorGroupIds:
			createExclusionListRequest["collectorGroupIds"] = f"{collectorGroupIds}"
		if name:
			createExclusionListRequest["name"] = f"{name}"
		if organization:
			createExclusionListRequest["organization"] = f"{organization}"

		return fortiedr_connection.send(url, createExclusionListRequest)

	def insert_exclusions_list(self, collectorGroupIds: list, listName: str, organization: str, newName: str = None) -> tuple[bool, None]:
		'''
		Class ThreatHuntingExclusions
		Description: Updates an exclusions list.
        
		Args:
			updateExclusionListRequest (Object): Check 'updateExclusionListRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("insert_exclusions_list", locals())

		url = '/management-rest/threat-hunting-exclusions/exclusions-list'

		updateExclusionListRequest = {}
		if collectorGroupIds:
			updateExclusionListRequest["collectorGroupIds"] = f"{collectorGroupIds}"
		if listName:
			updateExclusionListRequest["listName"] = f"{listName}"
		if newName:
			updateExclusionListRequest["newName"] = f"{newName}"
		if organization:
			updateExclusionListRequest["organization"] = f"{organization}"

		return fortiedr_connection.insert(url, updateExclusionListRequest)

	def delete_exclusions_list(self, listName: str, organization: str) -> tuple[bool, None]:
		'''
		Class ThreatHuntingExclusions
		Description: Deletes an exclusions list..
        
		Args:
			listName (str): Exclusions list name.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_exclusions_list", locals())

		url = '/management-rest/threat-hunting-exclusions/exclusions-list'
		url_params = []
		if listName != None:
			url_params.append(f'listName={listName}')
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def exclusions_metadata(self) -> tuple[bool, None]:
		'''
		Class ThreatHuntingExclusions
		Description: Get the metadata and available properties for exclusions configuration. When creating/modifying an exclusion, use the response of this API as a guide for the valid attribute names and values, and their corresponding EDR event types. Every attribute corresponds to an EDR category (for example, Filename attribute corresponds with the File category), and each category is a set of EDR event types. .
        
		Args:

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("exclusions_metadata", locals())

		url = '/management-rest/threat-hunting-exclusions/exclusions-metadata'
		return fortiedr_connection.get(url)

	def exclusions_search(self, organization: str, searchText: str, os: list = None) -> tuple[bool, list]:
		'''
		Class ThreatHuntingExclusions
		Description: Free-text search of exclusions.
        
		Args:
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			os (list): OS identifiers list.
			searchText (str): The free text search string. The API will return every exclusion list that contains this string, or contains an exclusion with any field that contains it.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("exclusions_search", locals())

		url = '/management-rest/threat-hunting-exclusions/exclusions-search'
		url_params = []
		if organization != None:
			url_params.append(f'organization={organization}')
		if os != None:
			os = ",".join(os) if isinstance(os, list) else os
			url_params.append(f'os={os}')
		if searchText != None:
			url_params.append(f'searchText={searchText}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

class ThreatHuntingSettings:
	'''API to configure Threat Hunting Settings.'''

	def threat_hunting_metadata(self) -> tuple[bool, list]:
		'''
		Class ThreatHuntingSettings
		Description: Get the Threat Hunting Settings metadata object, listing the available configuration options (Category and Event Types)..
        
		Args:

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("threat_hunting_metadata", locals())

		url = '/management-rest/threat-hunting-settings/threat-hunting-metadata'
		return fortiedr_connection.get(url)

	def get_threat_hunting_profile(self, organization: str) -> tuple[bool, list]:
		'''
		Class ThreatHuntingSettings
		Description: Get the list of Threat Hunting Setting profiles..
        
		Args:
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("get_threat_hunting_profile", locals())

		url = '/management-rest/threat-hunting-settings/threat-hunting-profile'
		url_params = []
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def send_threat_hunting_profile(self, associatedCollectorGroupIds: list, name: str, organization: str, threatHuntingCategoryList: list, newName: str = None) -> tuple[bool, None]:
		'''
		Class ThreatHuntingSettings
		Description: Update Threat Hunting profile.
        
		Args:
			threatHuntingUpdateRequest (Object): Check 'threatHuntingUpdateRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("send_threat_hunting_profile", locals())

		url = '/management-rest/threat-hunting-settings/threat-hunting-profile'

		threatHuntingUpdateRequest = {}
		if associatedCollectorGroupIds:
			threatHuntingUpdateRequest["associatedCollectorGroupIds"] = f"{associatedCollectorGroupIds}"
		if name:
			threatHuntingUpdateRequest["name"] = f"{name}"
		if newName:
			threatHuntingUpdateRequest["newName"] = f"{newName}"
		if organization:
			threatHuntingUpdateRequest["organization"] = f"{organization}"
		if threatHuntingCategoryList:
			threatHuntingUpdateRequest["threatHuntingCategoryList"] = f"{threatHuntingCategoryList}"

		return fortiedr_connection.send(url, threatHuntingUpdateRequest)

	def delete_threat_hunting_profile(self, name: str, organization: str) -> tuple[bool, None]:
		'''
		Class ThreatHuntingSettings
		Description: Deletes a Threat Hunting profile..
        
		Args:
			name (str): To be deleted profile's name.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_threat_hunting_profile", locals())

		url = '/management-rest/threat-hunting-settings/threat-hunting-profile'
		url_params = []
		if name != None:
			url_params.append(f'name={name}')
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def threat_hunting_profile_clone(self, cloneProfileName: str, existingProfileName: str, organization: str) -> tuple[bool, None]:
		'''
		Class ThreatHuntingSettings
		Description: Clone a Threat Hunting Settings profile..
        
		Args:
			cloneProfileName (str): Cloned profile name.
			existingProfileName (str): Existing profile name.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("threat_hunting_profile_clone", locals())

		url = '/management-rest/threat-hunting-settings/threat-hunting-profile-clone'
		url_params = []
		if cloneProfileName != None:
			url_params.append(f'cloneProfileName={cloneProfileName}')
		if existingProfileName != None:
			url_params.append(f'existingProfileName={existingProfileName}')
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.send(url)

	def threat_hunting_profile_assign_collector_groups(self, associatedCollectorGroupIds: list, name: str, organization: str) -> tuple[bool, list]:
		'''
		Class ThreatHuntingSettings
		Description: Update Threat Hunting profile assigned collector groups. Returns the updated list of assigned collector groups..
        
		Args:
			threatHuntingAssignGroupsRequest (Object): Check 'threatHuntingAssignGroupsRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("threat_hunting_profile_assign_collector_groups", locals())

		url = '/management-rest/threat-hunting-settings/threat-hunting-profile/collector-groups'

		threatHuntingAssignGroupsRequest = {}
		if associatedCollectorGroupIds:
			threatHuntingAssignGroupsRequest["associatedCollectorGroupIds"] = f"{associatedCollectorGroupIds}"
		if name:
			threatHuntingAssignGroupsRequest["name"] = f"{name}"
		if organization:
			threatHuntingAssignGroupsRequest["organization"] = f"{organization}"

		return fortiedr_connection.send(url, threatHuntingAssignGroupsRequest)

class ThreatHunting:
	'''API for Activity events'''

	def counts(self, accountId: int = None, category: str = None, devices: list = None, filters: list = None, fromTime: str = None, itemsPerPage: int = None, organization: str = None, pageNumber: int = None, query: str = None, sorting: list = None, time: str = None, toTime: str = None) -> tuple[bool, None]:
		'''
		Class ThreatHunting
		Description: This API call outputs EDR total events for every EDR category.
        
		Args:
			edrRequest (Object): Check 'edrRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("counts", locals())

		url = '/management-rest/threat-hunting/counts'

		edrRequest = {}
		if accountId != None:
			edrRequest["accountId"] = f"{accountId}"
		if category:
			edrRequest["category"] = f"{category}"
		if devices:
			edrRequest["devices"] = f"{devices}"
		if filters:
			edrRequest["filters"] = f"{filters}"
		if fromTime:
			edrRequest["fromTime"] = f"{fromTime}"
		if itemsPerPage != None:
			edrRequest["itemsPerPage"] = f"{itemsPerPage}"
		if organization:
			edrRequest["organization"] = f"{organization}"
		if pageNumber != None:
			edrRequest["pageNumber"] = f"{pageNumber}"
		if query:
			edrRequest["query"] = f"{query}"
		if sorting:
			edrRequest["sorting"] = f"{sorting}"
		if time:
			edrRequest["time"] = f"{time}"
		if toTime:
			edrRequest["toTime"] = f"{toTime}"

		return fortiedr_connection.send(url, edrRequest)

	def create_or_edit_tag(self, newTagName: str, organization: str = None, tagId: int = None, tagName: str = None) -> tuple[bool, None]:
		'''
		Class ThreatHunting
		Description: This API creates or edits the saved queries tag.
        
		Args:
			createOrEditTagRequest (Object): Check 'createOrEditTagRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("create_or_edit_tag", locals())

		url = '/management-rest/threat-hunting/create-or-edit-tag'

		createOrEditTagRequest = {}
		if newTagName:
			createOrEditTagRequest["newTagName"] = f"{newTagName}"
		if organization:
			createOrEditTagRequest["organization"] = f"{organization}"
		if tagId != None:
			createOrEditTagRequest["tagId"] = f"{tagId}"
		if tagName:
			createOrEditTagRequest["tagName"] = f"{tagName}"

		return fortiedr_connection.send(url, createOrEditTagRequest)

	def customize_fortinet_query(self, organization: str, id: int = None, dayOfMonth: int = None, dayOfWeek: int = None, forceSaving: bool = None, frequency: int = None, frequencyUnit: str = None, fromTime: str = None, hour: int = None, scheduled: bool = None, state: bool = None, time: str = None, toTime: str = None, queryToEdit: str = None) -> tuple[bool, None]:
		'''
		Class ThreatHunting
		Description: This API customizes the scheduling properties of a Fortinet query.
        
		Args:
			id (int): Specifies the query ID to edit
			ootbQueryCustomizeRequest (Object): Check 'ootbQueryCustomizeRequest' in the API documentation for further information.
			queryToEdit (str): Specifies the query name to edit

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("customize_fortinet_query", locals())

		url = '/management-rest/threat-hunting/customize-fortinet-query'
		url_params = []
		if id != None:
			url_params.append(f'id={id}')
		if queryToEdit != None:
			url_params.append(f'queryToEdit={queryToEdit}')
		url += '?' + '&'.join(url_params)

		ootbQueryCustomizeRequest = {}
		if dayOfMonth != None:
			ootbQueryCustomizeRequest["dayOfMonth"] = f"{dayOfMonth}"
		if dayOfWeek != None:
			ootbQueryCustomizeRequest["dayOfWeek"] = f"{dayOfWeek}"
		if forceSaving:
			ootbQueryCustomizeRequest["forceSaving"] = f"{forceSaving}"
		if frequency != None:
			ootbQueryCustomizeRequest["frequency"] = f"{frequency}"
		if frequencyUnit:
			ootbQueryCustomizeRequest["frequencyUnit"] = f"{frequencyUnit}"
		if fromTime:
			ootbQueryCustomizeRequest["fromTime"] = f"{fromTime}"
		if hour != None:
			ootbQueryCustomizeRequest["hour"] = f"{hour}"
		if organization:
			ootbQueryCustomizeRequest["organization"] = f"{organization}"
		if scheduled:
			ootbQueryCustomizeRequest["scheduled"] = f"{scheduled}"
		if state:
			ootbQueryCustomizeRequest["state"] = f"{state}"
		if time:
			ootbQueryCustomizeRequest["time"] = f"{time}"
		if toTime:
			ootbQueryCustomizeRequest["toTime"] = f"{toTime}"

		return fortiedr_connection.send(url, ootbQueryCustomizeRequest)

	def delete_saved_queries(self, deleteAll: bool = None, deleteFromCommunity: bool = None, organization: str = None, queryIds: list = None, queryNames: list = None, scheduled: bool = None, source: list = None) -> tuple[bool, None]:
		'''
		Class ThreatHunting
		Description: This API deletes the saved queries.
        
		Args:
			deleteAll (bool): A true/false parameter indicating whether all queries should be deleted. False by default
			deleteFromCommunity (bool): A true/false parameter indicating if whether to delete a query from the FortiEDR Community also
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			queryIds (list): Specifies the query IDs list
			queryNames (list): Specifies the query names list
			scheduled (bool): A true/false parameter indicating whether the query is scheduled
			source (list): Specifies the query source list

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_saved_queries", locals())

		url = '/management-rest/threat-hunting/delete-saved-queries'
		url_params = []
		if deleteAll != None:
			url_params.append(f'deleteAll={deleteAll}')
		if deleteFromCommunity != None:
			url_params.append(f'deleteFromCommunity={deleteFromCommunity}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if queryIds != None:
			queryIds = ",".join(map(str, queryIds)) if isinstance(queryIds, list) else queryIds
			url_params.append(f'queryIds={queryIds}')
		if queryNames != None:
			queryNames = ",".join(queryNames) if isinstance(queryNames, list) else queryNames
			url_params.append(f'queryNames={queryNames}')
		if scheduled != None:
			url_params.append(f'scheduled={scheduled}')
		if source != None:
			source = ",".join(source) if isinstance(source, list) else source
			url_params.append(f'source={source}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def delete_syslog_server(self, id: int) -> tuple[bool, str]:
		'''
		Class ThreatHunting
		Description: This API delete a syslog server.
        
		Args:
			id (int): id

		Returns:
			bool: Status of the request (True or False). 
			str
		'''
		validate_params("delete_syslog_server", locals())

		url = '/management-rest/threat-hunting/delete-syslog-server'
		url_params = []
		if id != None:
			url_params.append(f'id={id}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def delete_tags(self, organization: str = None, tagIds: list = None, tagNames: list = None) -> tuple[bool, None]:
		'''
		Class ThreatHunting
		Description: This API deletes the saved queries tags.
        
		Args:
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			tagIds (list): Specifies the tag ID list
			tagNames (list): Specifies the tag name list

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_tags", locals())

		url = '/management-rest/threat-hunting/delete-tags'
		url_params = []
		if organization != None:
			url_params.append(f'organization={organization}')
		if tagIds != None:
			tagIds = ",".join(map(str, tagIds)) if isinstance(tagIds, list) else tagIds
			url_params.append(f'tagIds={tagIds}')
		if tagNames != None:
			tagNames = ",".join(tagNames) if isinstance(tagNames, list) else tagNames
			url_params.append(f'tagNames={tagNames}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def facets(self, facets: list, accountId: int = None, category: str = None, devices: list = None, filters: list = None, fromTime: str = None, itemsPerPage: int = None, organization: str = None, pageNumber: int = None, query: str = None, sorting: list = None, time: str = None, toTime: str = None) -> tuple[bool, list]:
		'''
		Class ThreatHunting
		Description: This API retrieves EDR total events for every EDR facet item.
        
		Args:
			facetsRequest (Object): Check 'facetsRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("facets", locals())

		url = '/management-rest/threat-hunting/facets'

		facetsRequest = {}
		if accountId != None:
			facetsRequest["accountId"] = f"{accountId}"
		if category:
			facetsRequest["category"] = f"{category}"
		if devices:
			facetsRequest["devices"] = f"{devices}"
		if facets:
			facetsRequest["facets"] = f"{facets}"
		if filters:
			facetsRequest["filters"] = f"{filters}"
		if fromTime:
			facetsRequest["fromTime"] = f"{fromTime}"
		if itemsPerPage != None:
			facetsRequest["itemsPerPage"] = f"{itemsPerPage}"
		if organization:
			facetsRequest["organization"] = f"{organization}"
		if pageNumber != None:
			facetsRequest["pageNumber"] = f"{pageNumber}"
		if query:
			facetsRequest["query"] = f"{query}"
		if sorting:
			facetsRequest["sorting"] = f"{sorting}"
		if time:
			facetsRequest["time"] = f"{time}"
		if toTime:
			facetsRequest["toTime"] = f"{toTime}"

		return fortiedr_connection.send(url, facetsRequest)

	def get_syslog_servers(self, accountId: int) -> tuple[bool, None]:
		'''
		Class ThreatHunting
		Description: This API get the syslog servers.
        
		Args:
			accountId (int): accountId

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_syslog_servers", locals())

		url = '/management-rest/threat-hunting/get-syslog-servers'
		url_params = []
		if accountId != None:
			url_params.append(f'accountId={accountId}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def list_saved_queries(self, organization: str = None, scheduled: bool = None, source: list = None) -> tuple[bool, list]:
		'''
		Class ThreatHunting
		Description: This API retrieves the existing saved queries list.
        
		Args:
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			scheduled (bool): A true/false parameter indicating whether the query is scheduled
			source (list): Specifies the query source list

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_saved_queries", locals())

		url = '/management-rest/threat-hunting/list-saved-queries'
		url_params = []
		if organization != None:
			url_params.append(f'organization={organization}')
		if scheduled != None:
			url_params.append(f'scheduled={scheduled}')
		if source != None:
			source = ",".join(source) if isinstance(source, list) else source
			url_params.append(f'source={source}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def list_tags(self, organization: str = None) -> tuple[bool, list]:
		'''
		Class ThreatHunting
		Description: This API retrieves the existing saved queries tag list.
        
		Args:
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_tags", locals())

		url = '/management-rest/threat-hunting/list-tags'
		url_params = []
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def save_query(self, organization: str, id: int = None, queryToEdit: str = None, category: str = None, classification: str = None, collectorNames: list = None, community: bool = None, dayOfMonth: int = None, dayOfWeek: int = None, description: str = None, forceSaving: bool = None, frequency: int = None, frequencyUnit: str = None, fromTime: str = None, hour: int = None, name: str = None, query: str = None, scheduled: bool = None, state: bool = None, tagIds: list = None, tagNames: list = None, time: str = None, toTime: str = None) -> tuple[bool, None]:
		'''
		Class ThreatHunting
		Description: This API saves the query.
        
		Args:
			id (int): Specifies the query ID to edit
			queryToEdit (str): Specifies the query name to edit
			saveQueryRequest (Object): Check 'saveQueryRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("save_query", locals())

		url = '/management-rest/threat-hunting/save-query'
		url_params = []
		if id != None:
			url_params.append(f'id={id}')
		if queryToEdit != None:
			url_params.append(f'queryToEdit={queryToEdit}')
		url += '?' + '&'.join(url_params)

		saveQueryRequest = {}
		if category:
			saveQueryRequest["category"] = f"{category}"
		if classification:
			saveQueryRequest["classification"] = f"{classification}"
		if collectorNames:
			saveQueryRequest["collectorNames"] = f"{collectorNames}"
		if community:
			saveQueryRequest["community"] = f"{community}"
		if dayOfMonth != None:
			saveQueryRequest["dayOfMonth"] = f"{dayOfMonth}"
		if dayOfWeek != None:
			saveQueryRequest["dayOfWeek"] = f"{dayOfWeek}"
		if description:
			saveQueryRequest["description"] = f"{description}"
		if forceSaving:
			saveQueryRequest["forceSaving"] = f"{forceSaving}"
		if frequency != None:
			saveQueryRequest["frequency"] = f"{frequency}"
		if frequencyUnit:
			saveQueryRequest["frequencyUnit"] = f"{frequencyUnit}"
		if fromTime:
			saveQueryRequest["fromTime"] = f"{fromTime}"
		if hour != None:
			saveQueryRequest["hour"] = f"{hour}"
		if name:
			saveQueryRequest["name"] = f"{name}"
		if organization:
			saveQueryRequest["organization"] = f"{organization}"
		if query:
			saveQueryRequest["query"] = f"{query}"
		if scheduled:
			saveQueryRequest["scheduled"] = f"{scheduled}"
		if state:
			saveQueryRequest["state"] = f"{state}"
		if tagIds:
			saveQueryRequest["tagIds"] = f"{tagIds}"
		if tagNames:
			saveQueryRequest["tagNames"] = f"{tagNames}"
		if time:
			saveQueryRequest["time"] = f"{time}"
		if toTime:
			saveQueryRequest["toTime"] = f"{toTime}"

		return fortiedr_connection.send(url, saveQueryRequest)

	def search(self, accountId: int = None, category: str = None, devices: list = None, filters: list = None, fromTime: str = None, itemsPerPage: int = None, organization: str = None, pageNumber: int = None, query: str = None, sorting: list = None, time: str = None, toTime: str = None) -> tuple[bool, list]:
		'''
		Class ThreatHunting
		Description: This API call outputs a list of Activity events from middleware..
        
		Args:
			edrRequest (Object): Check 'edrRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("search", locals())

		url = '/management-rest/threat-hunting/search'

		edrRequest = {}
		if accountId != None:
			edrRequest["accountId"] = f"{accountId}"
		if category:
			edrRequest["category"] = f"{category}"
		if devices:
			edrRequest["devices"] = f"{devices}"
		if filters:
			edrRequest["filters"] = f"{filters}"
		if fromTime:
			edrRequest["fromTime"] = f"{fromTime}"
		if itemsPerPage != None:
			edrRequest["itemsPerPage"] = f"{itemsPerPage}"
		if organization:
			edrRequest["organization"] = f"{organization}"
		if pageNumber != None:
			edrRequest["pageNumber"] = f"{pageNumber}"
		if query:
			edrRequest["query"] = f"{query}"
		if sorting:
			edrRequest["sorting"] = f"{sorting}"
		if time:
			edrRequest["time"] = f"{time}"
		if toTime:
			edrRequest["toTime"] = f"{toTime}"

		return fortiedr_connection.send(url, edrRequest)

	def set_query_state(self, state: bool, markAll: bool = None, organization: str = None, queryIds: list = None, queryNames: list = None, source: list = None) -> tuple[bool, None]:
		'''
		Class ThreatHunting
		Description: This API updates the scheduled saved query state.
        
		Args:
			markAll (bool): A true/false parameter indicating whether all queries should be marked with the same value as 'state' property. False by default
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
			•	Exact organization name – Specifies the name of a specific organization. The value that you specify here must match exactly.
			•	All organizations – Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			queryIds (list): Specifies the query ID list
			queryNames (list): Specifies the query name list
			source (list): Specifies the query source list
			state (bool): A true/false parameter indicating whether to save the query as enabled

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("set_query_state", locals())

		url = '/management-rest/threat-hunting/set-query-state'
		url_params = []
		if markAll != None:
			url_params.append(f'markAll={markAll}')
		if organization != None:
			url_params.append(f'organization={organization}')
		if queryIds != None:
			queryIds = ",".join(map(str, queryIds)) if isinstance(queryIds, list) else queryIds
			url_params.append(f'queryIds={queryIds}')
		if queryNames != None:
			queryNames = ",".join(queryNames) if isinstance(queryNames, list) else queryNames
			url_params.append(f'queryNames={queryNames}')
		if source != None:
			source = ",".join(source) if isinstance(source, list) else source
			url_params.append(f'source={source}')
		if state != None:
			url_params.append(f'state={state}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def test_syslog_server(self, accountId: int = None, host: str = None, id: int = None, name: str = None, port: int = None, protocol: str = None, syslogRFCFormat: str = None, useSSL: bool = None) -> tuple[bool, None]:
		'''
		Class ThreatHunting
		Description: This API test a syslog server connection.
        
		Args:
			syslogServer (Object): Check 'syslogServer' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("test_syslog_server", locals())

		url = '/management-rest/threat-hunting/test-syslog-server'

		syslogServer = {}
		if accountId != None:
			syslogServer["accountId"] = f"{accountId}"
		if host:
			syslogServer["host"] = f"{host}"
		if id != None:
			syslogServer["id"] = f"{id}"
		if name:
			syslogServer["name"] = f"{name}"
		if port != None:
			syslogServer["port"] = f"{port}"
		if protocol:
			syslogServer["protocol"] = f"{protocol}"
		if syslogRFCFormat:
			syslogServer["syslogRFCFormat"] = f"{syslogRFCFormat}"
		if useSSL:
			syslogServer["useSSL"] = f"{useSSL}"

		return fortiedr_connection.send(url, syslogServer)

	def update_syslog_server(self, accountId: int = None, agentGroupIds: list = None, host: str = None, id: int = None, name: str = None, port: int = None, protocol: str = None, syslogRFCFormat: str = None, useSSL: bool = None) -> tuple[bool, str]:
		'''
		Class ThreatHunting
		Description: This API update a syslog server.
        
		Args:
			updateSyslogServer (Object): Check 'updateSyslogServer' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			str
		'''
		validate_params("update_syslog_server", locals())

		url = '/management-rest/threat-hunting/update-syslog-server'

		updateSyslogServer = {}
		if accountId != None:
			updateSyslogServer["accountId"] = f"{accountId}"
		if agentGroupIds:
			updateSyslogServer["agentGroupIds"] = f"{agentGroupIds}"
		if host:
			updateSyslogServer["host"] = f"{host}"
		if id != None:
			updateSyslogServer["id"] = f"{id}"
		if name:
			updateSyslogServer["name"] = f"{name}"
		if port != None:
			updateSyslogServer["port"] = f"{port}"
		if protocol:
			updateSyslogServer["protocol"] = f"{protocol}"
		if syslogRFCFormat:
			updateSyslogServer["syslogRFCFormat"] = f"{syslogRFCFormat}"
		if useSSL:
			updateSyslogServer["useSSL"] = f"{useSSL}"

		return fortiedr_connection.send(url, updateSyslogServer)


debug = None
ssl_enabled = True
organization = None
               
def ignore_certificate():
	global ssl_enabled
	ssl_enabled = False
	print("[!] - We strongly advise you to enable SSL validations. Use this at your own risk!")

def enable_debug():
	global debug
	debug = True

def set_organization(orgname):
	global organization
	organization = orgname


def validate_params(function_name, local_params):
	global api_json_params
	if not api_json_params:
		print("Have you authenticated first?")
		exit() 

	data_types = {
		'int': int,
		'set': set,
		'str': str,
		'bool': bool,
		'dict': dict,
		'object': dict,
		'list': list,
		'NoneType': None,
		'BinaryIO': bytes,
	}
	json_params = api_json_params[function_name]
	for key, value in local_params.items():
		if key == "self" or value is None or key not in json_params.keys() : continue
		if json_params[key] == 'list': continue

		t = data_types[json_params[key]]
		r = str(type(value))
		if not isinstance(value, t):
			print(f"Error on defined params!\nParam '{key}' should be defined as type '{json_params[key]}', not {r}")
			exit()
         

def auth( host: str, user: str, passw: str, org: str = None):
	global debug
	global api_json_params
	global fortiedr_connection
	login = fedrAuth()

	ManagementHost = re.search(r'(https?://)?(([a-zA-Z0-9]+)(\.[a-zA-Z0-9.-]+))', host)
	host = ManagementHost.group(2)

	if org:
		set_organization(org)

	headers, host = login.get_headers(
		fedr_host=host,
		fedr_user=user,
		fedr_pass=passw,
		fedr_org=org
	)

	if headers is None:
		status = False
		data = host
	else:
		status = True
		data = 'AUTHENTICATION_SUCCEEDED'

		fortiedr_connection = FortiEDR_API_GW()
		authentication = fortiedr_connection.conn(headers, host, debug, ssl_enabled, organization)

		cur_dir = os.path.dirname(__file__)
		json_file = f'{cur_dir}/api_parameters.json'
		with open(json_file, 'r') as fp:
			api_json_params = json.loads(fp.read())

	return {
		'status': status,
		'data': data
	}
