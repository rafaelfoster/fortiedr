
import re
import os
import json
from typing import BinaryIO
from fortiedr.auth import Auth as fedrAuth
from fortiedr.connector import FortiEDR_API_GW

version = '3.7.1'

fortiedr_connection = None

class ApplicationControl:
	'''Application Control Rest Api Controller'''

	def get_applications(self, currentPage: int, organization: str, fileName: str = None, path: str = None, signer: str = None, enabled: bool = None, hash: str = None, operatingSystem: str = None, policyIds: list = None, tag: str = None) -> tuple[bool, None]:
		'''
		Class ApplicationControl
		Description: Get application controls.
        
		Args:
			fileName (str): Specifies the file name, if contains special characters - encode to HTML URL Encoding.
			attributes.fileName (str): Specifies the file name, if contains special characters - encode to HTML URL Encoding.
			path (str): Specifies the path, if contains special characters - encode to HTML URL Encoding.
			attributes.path (str): Specifies the path, if contains special characters - encode to HTML URL Encoding.
			signer (str): Specifies the value, if contains special characters - encode to HTML URL Encoding.
			attributes.signer (str): Specifies the value, if contains special characters - encode to HTML URL Encoding.
			currentPage (int): Specifies the current page.
			enabled (bool): Specifies the state of the application control.
			hash (str): Specifies the hash of the application control.
			operatingSystem (str): Specifies the operating system of the application control.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.
			policyIds (list): Specifies the IDs of the relevant policies for application control.
			integer (list): Specifies the IDs of the relevant policies for application control.
			tag (str): Specifies the tag related to application control.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_applications", locals())

		url = '/api/application-control/applications'
		url_params = []
		if fileName:
			url_params.append('attributes.fileName=' + fileName)
		if path:
			url_params.append('attributes.path=' + path)
		if signer:
			url_params.append('attributes.signer=' + signer)
		if currentPage:
			url_params.append('currentPage=' + currentPage)
		if enabled:
			url_params.append('enabled=' + enabled)
		if hash:
			url_params.append('hash=' + hash)
		if operatingSystem:
			url_params.append('operatingSystem=' + operatingSystem)
		if organization:
			url_params.append('organization=' + organization)
		if policyIds:
			url_params.append('policyIds=' + ",".join(map(str, policyIds)))
		if tag:
			url_params.append('tag=' + tag)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def send_applications(self, applicationControls: list = None, organization: str = None) -> tuple[bool, None]:
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
		if applicationControls: applicationControlSaveRequest["applicationControls"] = applicationControls
		if organization: applicationControlSaveRequest["organization"] = organization

		return fortiedr_connection.send(url, applicationControlSaveRequest)

	def insert_applications(self, appIds: list, organization: str, enabled: bool = None, groupIds: list = None, isOverridePolicies: bool = None, policyIds: list = None, tagId: int = None) -> tuple[bool, list]:
		'''
		Class ApplicationControl
		Description: Edits existing application control and returns the affected ones.
        
		Args:
			appIds (list): The relevant application IDs to edit.
			integer (list): The relevant application IDs to edit.
			modifiedFields (Object): Check 'modifiedFields' in the API documentation for further information.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("insert_applications", locals())

		url = '/api/application-control/applications'
		url_params = []
		if appIds:
			url_params.append('appIds=' + ",".join(map(str, appIds)))
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)

		modifiedFields = {}
		if enabled: modifiedFields["enabled"] = enabled
		if groupIds: modifiedFields["groupIds"] = groupIds
		if isOverridePolicies: modifiedFields["isOverridePolicies"] = isOverridePolicies
		if policyIds: modifiedFields["policyIds"] = policyIds
		if tagId: modifiedFields["tagId"] = str(tagId)

		return fortiedr_connection.insert(url, modifiedFields)

	def delete_applications(self, organization: str, applicationIds: list = None) -> tuple[bool, None]:
		'''
		Class ApplicationControl
		Description: Deletes application controls.
        
		Args:
			applicationIds (list): The IDs of the applications to be deleted.
			integer (list): The IDs of the applications to be deleted.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_applications", locals())

		url = '/api/application-control/applications'
		url_params = []
		if applicationIds:
			url_params.append('applicationIds=' + ",".join(map(str, applicationIds)))
		if organization:
			url_params.append('organization=' + organization)
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

	def tags(self, name: str = None, organization: str = None) -> tuple[bool, None]:
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
		if name: applicationControlTagCreateRequest["name"] = name
		if organization: applicationControlTagCreateRequest["organization"] = organization

		return fortiedr_connection.send(url, applicationControlTagCreateRequest)

class Administrator:
	'''The Administrator module enables administrators to perform administrative operations, such as handling licenses and users.'''

	def set_tray_notification_settings(self, enabledPopup: bool = None, enabledTrayNotification: bool = None, message: str = None, organization: str = None) -> tuple[bool, None]:
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
		if enabledPopup: adminSetTrayNotificationSettingsRequest["enabledPopup"] = enabledPopup
		if enabledTrayNotification: adminSetTrayNotificationSettingsRequest["enabledTrayNotification"] = enabledTrayNotification
		if message: adminSetTrayNotificationSettingsRequest["message"] = message
		if organization: adminSetTrayNotificationSettingsRequest["organization"] = organization

		return fortiedr_connection.send(url, adminSetTrayNotificationSettingsRequest)


	def list_collector_installers(self, organization: str = None) -> tuple[bool, None]:
		'''
		Class Administrator
		Description: This API call output the available collectors installers.
        
		Args:
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations..

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("list_collector_installers", locals())

		url = '/management-rest/admin/list-collector-installers'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def list_system_summary(self, addLicenseBlob: bool = None, organization: str = None) -> tuple[bool, None]:
		'''
		Class Administrator
		Description: Get System Summary.
        
		Args:
			addLicenseBlob (bool): Indicates whether to put license blob to response. By default addLicenseBlob is false.
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations..

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("list_system_summary", locals())

		url = '/management-rest/admin/list-system-summary'
		url_params = []
		if addLicenseBlob:
			url_params.append('addLicenseBlob=' + addLicenseBlob)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def previous_registration_passwords(self, organization: str = None) -> tuple[bool, list]:
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
		if organization: organizationRequest["organization"] = organization

		return fortiedr_connection.get(url, organizationRequest)

	def previous_registration_passwords(self, passwordId: int, organization: str = None) -> tuple[bool, str]:
		'''
		Class Administrator
		Description: This API deletes previous registration password for given id.
        
		Args:
			organizationRequest (Object): Check 'organizationRequest' in the API documentation for further information.
			passwordId (int): passwordId.

		Returns:
			bool: Status of the request (True or False). 
			str
		'''
		validate_params("previous_registration_passwords", locals())

		url = f'/management-rest/admin/previous-registration-passwords/{passwordId}'

		organizationRequest = {}
		if organization: organizationRequest["organization"] = organization

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

	def registration_password(self, organization: str = None, password: str = None) -> tuple[bool, None]:
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
		if organization: request["organization"] = organization
		if password: request["password"] = password

		return fortiedr_connection.send(url, request)

	def set_system_mode(self, mode: str, forceAll: bool = None, organization: str = None) -> tuple[bool, None]:
		'''
		Class Administrator
		Description: Set system modeThis API call enables you to switch the system to Simulation mode.
        
		Args:
			forceAll (bool): Indicates whether to force set all the policies in 'Prevention' mode.
			mode (str): Operation mode.
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations..

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("set_system_mode", locals())

		url = '/management-rest/admin/set-system-mode'
		url_params = []
		if forceAll:
			url_params.append('forceAll=' + forceAll)
		if mode:
			url_params.append('mode=' + mode)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def update_collector_installer(self, collectorGroupIds: list = None, collectorGroups: list = None, organization: str = None, updateVersions: list = None) -> tuple[bool, None]:
		'''
		Class Administrator
		Description: This API update collectors target version for collector groups.
        
		Args:
			collectorGroupIds (list): Specifies the list of IDs of all the collector groups which should be updated..
			integer (list): Specifies the list of IDs of all the collector groups which should be updated..
			collectorGroups (list): Specifies the list of all the collector groups which should be updated..
			string (list): Specifies the list of all the collector groups which should be updated..
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations..
			requestUpdateData (Object): Check 'requestUpdateData' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("update_collector_installer", locals())

		url = '/management-rest/admin/update-collector-installer'
		url_params = []
		if collectorGroupIds:
			url_params.append('collectorGroupIds=' + ",".join(map(str, collectorGroupIds)))
		if collectorGroups:
			url_params.append('collectorGroups=' + ",".join(str(collectorGroups)))
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)

		requestUpdateData = {}
		if updateVersions: requestUpdateData["updateVersions"] = updateVersions

		return fortiedr_connection.send(url, requestUpdateData)

	def upload_content(self, file: BinaryIO, ) -> tuple[bool, str]:
		'''
		Class Administrator
		Description: Upload content to the system.
        
		Args:
			file (BinaryIO): file.

		Returns:
			bool: Status of the request (True or False). 
			str
		'''
		validate_params("upload_content", locals())

		url = '/management-rest/admin/upload-content'
		if file:
			file = {'file': file}


		return fortiedr_connection.upload(url, file)

	def upload_license(self, licenseBlob: str = None) -> tuple[bool, None]:
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
		if licenseBlob: license["licenseBlob"] = licenseBlob

		return fortiedr_connection.insert(url, license)

class Audit:
	'''The Audit module enables you to retrieve system audit based on given dates'''

	def get_audit(self, fromTime: str = None, organization: str = None, toTime: str = None) -> tuple[bool, list]:
		'''
		Class Audit
		Description: This API retrieve the audit between 2 dates.
        
		Args:
			fromTime (str): Retrieves audit that were written after the given date. Date Format: yyyy-MM-dd (Default is current date).
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations..
			toTime (str): Retrieves audit that were written before the given date. Date Format: yyyy-MM-dd (Default is current date).

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("get_audit", locals())

		url = '/management-rest/audit/get-audit'
		url_params = []
		if fromTime:
			url_params.append('fromTime=' + fromTime)
		if organization:
			url_params.append('organization=' + organization)
		if toTime:
			url_params.append('toTime=' + toTime)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

class CommunicationControl:
	'''Fortinet Endpoint Protection and Response Platform’s Communication Control module is responsible for monitoring and handling non-disguised security events. The module uses a set of policies that contain recommendations about whether an application should be approved or denied from communicating outside your organization.'''

	def assign_collector_group(self, collectorGroups: list, policyName: str, forceAssign: bool = None, organization: str = None) -> tuple[bool, None]:
		'''
		Class CommunicationControl
		Description: Assign collector group to application policy.
        
		Args:
			collectorGroups (list):  Specifies the collector groups whose collector reported the events.
			string (list):  Specifies the collector groups whose collector reported the events.
			forceAssign (bool): Indicates whether to force the assignment even if the group is assigned to similar policies.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.
			policyName (str): Specifies the list of policies.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("assign_collector_group", locals())

		url = '/management-rest/comm-control/assign-collector-group'
		url_params = []
		if collectorGroups:
			url_params.append('collectorGroups=' + ",".join(str(collectorGroups)))
		if forceAssign:
			url_params.append('forceAssign=' + forceAssign)
		if organization:
			url_params.append('organization=' + organization)
		if policyName:
			url_params.append('policyName=' + policyName)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def clone_policy(self, newPolicyName: str, sourcePolicyName: str, organization: str = None) -> tuple[bool, None]:
		'''
		Class CommunicationControl
		Description: application clone policy.
        
		Args:
			newPolicyName (str): Specifies security policy target name..
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.
			sourcePolicyName (str): Specifies security policy source name.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("clone_policy", locals())

		url = '/management-rest/comm-control/clone-policy'
		url_params = []
		if newPolicyName:
			url_params.append('newPolicyName=' + newPolicyName)
		if organization:
			url_params.append('organization=' + organization)
		if sourcePolicyName:
			url_params.append('sourcePolicyName=' + sourcePolicyName)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.send(url)

	def list_policies(self, decisions: list, itemsPerPage: int = None, organization: str = None, pageNumber: int = None, policies: list = None, rules: list = None, sorting: str = None, sources: list = None, state: str = None, strictMode: bool = None) -> tuple[bool, list]:
		'''
		Class CommunicationControl
		Description: This API call outputs a list of all the communication control policies in the system, and information about each of them.
        
		Args:
			decisions (list): Indicates the action.
			string (list): Indicates the action.
			itemsPerPage (int): An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.
			pageNumber (int): An integer used for paging that indicates the required page number.
			policies (list): Specifies the list of policy names.
			string (list): Specifies the list of policy names.
			rules (list): Specifies the list of rules.
			string (list): Specifies the list of rules.
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on.
			sources (list): Specifies who created the policy.
			string (list): Specifies who created the policy.
			state (str): Policy rule state.
			strictMode (bool): A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_policies", locals())

		url = '/management-rest/comm-control/list-policies'
		url_params = []
		if decisions:
			url_params.append('decisions=' + ",".join(str(decisions)))
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if organization:
			url_params.append('organization=' + organization)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if policies:
			url_params.append('policies=' + ",".join(str(policies)))
		if rules:
			url_params.append('rules=' + ",".join(str(rules)))
		if sorting:
			url_params.append('sorting=' + sorting)
		if sources:
			url_params.append('sources=' + ",".join(str(sources)))
		if state:
			url_params.append('state=' + state)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def list_products(self, action: str = None, collectorGroups: list = None, cveIdentifier: str = None, destinationIp: list = None, devices: list = None, firstConnectionTimeEnd: str = None, firstConnectionTimeStart: str = None, handled: bool = None, includeStatistics: bool = None, ips: list = None, itemsPerPage: int = None, lastConnectionTimeEnd: str = None, lastConnectionTimeStart: str = None, organization: str = None, os: list = None, pageNumber: int = None, policies: list = None, processHash: str = None, processes: list = None, product: str = None, products: list = None, reputation: list = None, rule: str = None, rulePolicy: str = None, seen: bool = None, sorting: str = None, strictMode: bool = None, vendor: str = None, vendors: list = None, version: str = None, versions: list = None, vulnerabilities: list = None) -> tuple[bool, list]:
		'''
		Class CommunicationControl
		Description: This API call outputs a list of all the communicating applications in the system, and information about each of them.
        
		Args:
			action (str): Indicates the action: Allow/Deny. This parameter is irrelevant without policies parameter.
			collectorGroups (list): Specifies the list of collector groups where the products were seen.
			string (list): Specifies the list of collector groups where the products were seen.
			cveIdentifier (str): Specifies the CVE identifier.
			destinationIp (list): Destination IPs.
			string (list): Destination IPs.
			devices (list): Specifies the list of device names where the products were seen.
			string (list): Specifies the list of device names where the products were seen.
			firstConnectionTimeEnd (str):  Retrieves products whose first connection time is less than the value assigned to this date.
			firstConnectionTimeStart (str):  Retrieves products whose first connection time is greater than the value assigned to this date.
			handled (bool): A true/false parameter indicating whether events were handled/unhandled.
			includeStatistics (bool): A true/false parameter indicating including statistics data.
			ips (list): Specifies the list of IPs where the products were seen.
			string (list): Specifies the list of IPs where the products were seen.
			itemsPerPage (int): An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000.
			lastConnectionTimeEnd (str):  Retrieves products whose last connection time is less than the value assigned to this date.
			lastConnectionTimeStart (str):  Retrieves products whose last connection time is greater than the value assigned to this date.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.
			os (list): Specifies the list of operating system families where the products were seen.
			string (list): Specifies the list of operating system families where the products were seen.
			pageNumber (int): An integer used for paging that indicates the required page number.
			policies (list): Specifies the list of policy names whose products have a specific decision, as specified in the action parameter.
			string (list): Specifies the list of policy names whose products have a specific decision, as specified in the action parameter.
			processHash (str): Specifies the process hash name.
			processes (list): Specifies the list of process names running alongside the products.
			string (list): Specifies the list of process names running alongside the products.
			product (str): Specifies a single value for the product name. By default, strictMode is false.
			products (list): Specifies the list of product names. Names must match exactly (strictMode is always true).
			string (list): Specifies the list of product names. Names must match exactly (strictMode is always true).
			reputation (list): Specifies the recommendation of the application: Unknown, Known bad, Assumed bad, Contradiction, Assumed good or Known good.
			string (list): Specifies the recommendation of the application: Unknown, Known bad, Assumed bad, Contradiction, Assumed good or Known good.
			rule (str): Indicates the rule. This parameter is irrelevant without rulePolicy parameter.
			rulePolicy (str): Specifies the policy name whose products have a specific rule, as specified in the rule parameter.
			seen (bool): A true/false parameter indicating whether events were read/unread by the user operating the API.
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on.
			strictMode (bool): A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False.
			vendor (str): Specifies a single value for the vendor name. By default, strictMode is false.
			vendors (list): Specifies the list of vendor names. Names must match exactly (strictMode is always true).
			string (list): Specifies the list of vendor names. Names must match exactly (strictMode is always true).
			version (str): Specifies a single value for the version name. By default, strictMode is false.
			versions (list): Specifies the list of versions. Names must match exactly (strictMode is always true).
			string (list): Specifies the list of versions. Names must match exactly (strictMode is always true).
			vulnerabilities (list): Specifies the list of vulnerabilities where the products were seen.
			string (list): Specifies the list of vulnerabilities where the products were seen.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_products", locals())

		url = '/management-rest/comm-control/list-products'
		url_params = []
		if action:
			url_params.append('action=' + action)
		if collectorGroups:
			url_params.append('collectorGroups=' + ",".join(str(collectorGroups)))
		if cveIdentifier:
			url_params.append('cveIdentifier=' + cveIdentifier)
		if destinationIp:
			url_params.append('destinationIp=' + ",".join(str(destinationIp)))
		if devices:
			url_params.append('devices=' + ",".join(str(devices)))
		if firstConnectionTimeEnd:
			url_params.append('firstConnectionTimeEnd=' + firstConnectionTimeEnd)
		if firstConnectionTimeStart:
			url_params.append('firstConnectionTimeStart=' + firstConnectionTimeStart)
		if handled:
			url_params.append('handled=' + handled)
		if includeStatistics:
			url_params.append('includeStatistics=' + includeStatistics)
		if ips:
			url_params.append('ips=' + ",".join(str(ips)))
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if lastConnectionTimeEnd:
			url_params.append('lastConnectionTimeEnd=' + lastConnectionTimeEnd)
		if lastConnectionTimeStart:
			url_params.append('lastConnectionTimeStart=' + lastConnectionTimeStart)
		if organization:
			url_params.append('organization=' + organization)
		if os:
			url_params.append('os=' + ",".join(str(os)))
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if policies:
			url_params.append('policies=' + ",".join(str(policies)))
		if processHash:
			url_params.append('processHash=' + processHash)
		if processes:
			url_params.append('processes=' + ",".join(str(processes)))
		if product:
			url_params.append('product=' + product)
		if products:
			url_params.append('products=' + ",".join(str(products)))
		if reputation:
			url_params.append('reputation=' + ",".join(str(reputation)))
		if rule:
			url_params.append('rule=' + rule)
		if rulePolicy:
			url_params.append('rulePolicy=' + rulePolicy)
		if seen:
			url_params.append('seen=' + seen)
		if sorting:
			url_params.append('sorting=' + sorting)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		if vendor:
			url_params.append('vendor=' + vendor)
		if vendors:
			url_params.append('vendors=' + ",".join(str(vendors)))
		if version:
			url_params.append('version=' + version)
		if versions:
			url_params.append('versions=' + ",".join(str(versions)))
		if vulnerabilities:
			url_params.append('vulnerabilities=' + ",".join(str(vulnerabilities)))
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def resolve_applications(self, applyNested: bool = None, comment: str = None, organization: str = None, products: list = None, resolve: bool = None, signed: bool = None, vendors: list = None, versions: list = None) -> tuple[bool, None]:
		'''
		Class CommunicationControl
		Description: Enable resolving/unresolving applications.
        
		Args:
			applyNested (bool): A true/false parameter indicating updating inherited.
			comment (str): Specifies a user-defined string to attach to the policy.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.
			products (list): Specifies the list of product names. Names must match exactly (strictMode is always true).
			string (list): Specifies the list of product names. Names must match exactly (strictMode is always true).
			resolve (bool): A true/false parameter indicating update the application resolve/unresolve.
			signed (bool): A true/false parameter indicating if the policy is signed.
			vendors (list): Specifies the list of vendor names. Names must match exactly (strictMode is always true).
			string (list): Specifies the list of vendor names. Names must match exactly (strictMode is always true).
			versions (list): Specifies the list of versions. Names must match exactly (strictMode is always true).
			string (list): Specifies the list of versions. Names must match exactly (strictMode is always true).

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("resolve_applications", locals())

		url = '/management-rest/comm-control/resolve-applications'
		url_params = []
		if applyNested:
			url_params.append('applyNested=' + applyNested)
		if comment:
			url_params.append('comment=' + comment)
		if organization:
			url_params.append('organization=' + organization)
		if products:
			url_params.append('products=' + ",".join(str(products)))
		if resolve:
			url_params.append('resolve=' + resolve)
		if signed:
			url_params.append('signed=' + signed)
		if vendors:
			url_params.append('vendors=' + ",".join(str(vendors)))
		if versions:
			url_params.append('versions=' + ",".join(str(versions)))
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def set_policy_mode(self, mode: str, policyNames: list, organization: str = None) -> tuple[bool, None]:
		'''
		Class CommunicationControl
		Description: Set policy to simulation/prevention.
        
		Args:
			mode (str): Operation mode.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.
			policyNames (list): Specifies the list of policies.
			string (list): Specifies the list of policies.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("set_policy_mode", locals())

		url = '/management-rest/comm-control/set-policy-mode'
		url_params = []
		if mode:
			url_params.append('mode=' + mode)
		if organization:
			url_params.append('organization=' + organization)
		if policyNames:
			url_params.append('policyNames=' + ",".join(str(policyNames)))
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def set_policy_permission(self, decision: str, policies: list, applyNested: bool = None, organization: str = None, products: list = None, signed: bool = None, vendors: list = None, versions: list = None) -> tuple[bool, None]:
		'''
		Class CommunicationControl
		Description: Set the application allow/deny.
        
		Args:
			applyNested (bool): A true/false parameter indicating updating inherited.
			decision (str): Indicates the action.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.
			policies (list): Specifies the list of policies names.
			string (list): Specifies the list of policies names.
			products (list): Specifies the list of product names. Names must match exactly (strictMode is always true).
			string (list): Specifies the list of product names. Names must match exactly (strictMode is always true).
			signed (bool): A true/false parameter indicating if the policy is signed.
			vendors (list): Specifies the list of vendor names. Names must match exactly (strictMode is always true).
			string (list): Specifies the list of vendor names. Names must match exactly (strictMode is always true).
			versions (list): Specifies the list of versions. Names must match exactly (strictMode is always true).
			string (list): Specifies the list of versions. Names must match exactly (strictMode is always true).

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("set_policy_permission", locals())

		url = '/management-rest/comm-control/set-policy-permission'
		url_params = []
		if applyNested:
			url_params.append('applyNested=' + applyNested)
		if decision:
			url_params.append('decision=' + decision)
		if organization:
			url_params.append('organization=' + organization)
		if policies:
			url_params.append('policies=' + ",".join(str(policies)))
		if products:
			url_params.append('products=' + ",".join(str(products)))
		if signed:
			url_params.append('signed=' + signed)
		if vendors:
			url_params.append('vendors=' + ",".join(str(vendors)))
		if versions:
			url_params.append('versions=' + ",".join(str(versions)))
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def set_policy_rule_state(self, policyName: str, ruleName: str, state: str, organization: str = None) -> tuple[bool, None]:
		'''
		Class CommunicationControl
		Description: Set rule in policy to enable/disable.
        
		Args:
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.
			policyName (str): Specifies policy name.
			ruleName (str): Specifies rule name.
			state (str): Policy rule state.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("set_policy_rule_state", locals())

		url = '/management-rest/comm-control/set-policy-rule-state'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		if policyName:
			url_params.append('policyName=' + policyName)
		if ruleName:
			url_params.append('ruleName=' + ruleName)
		if state:
			url_params.append('state=' + state)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

class Events:
	'''This API call outputs all the events in the system that match the condition(s) you specify in the call. An AND relationship exists when specifying multiple input parameters. When no input parameters are matched, an empty result set is returned'''

	def insert_events(self, actions: list = None, applicationControl: bool = None, archived: bool = None, classifications: list = None, collectorGroups: list = None, destinations: list = None, device: str = None, deviceControl: bool = None, deviceIps: list = None, eventIds: list = None, eventType: list = None, expired: bool = None, fileHash: str = None, firstSeen: str = None, firstSeenFrom: str = None, firstSeenTo: str = None, handled: bool = None, itemsPerPage: int = None, lastSeen: str = None, lastSeenFrom: str = None, lastSeenTo: str = None, loggedUser: str = None, macAddresses: list = None, muted: bool = None, operatingSystems: list = None, organization: str = None, pageNumber: int = None, paths: list = None, process: str = None, rule: str = None, seen: bool = None, severities: list = None, signed: bool = None, sorting: str = None, strictMode: bool = None, archive: bool = None, classification: str = None, comment: str = None, familyName: str = None, forceUnmute: bool = None, handle: bool = None, malwareType: str = None, mute: bool = None, muteDuration: str = None, read: bool = None, threatName: str = None) -> tuple[bool, None]:
		'''
		Class Events
		Description: This API call updates the read/unread, handled/unhandled or archived/unarchived state of an event. The output of this call is a message indicating whether the update succeeded or failed.
        
		Args:
			actions (list): Specifies the action of the event.
			string (list): Specifies the action of the event.
			applicationControl (bool): A true/false parameter indicating whether to include only application control events.
			archived (bool): A true/false parameter indicating whether to include only archived events.
			classifications (list): Specifies the classification of the event.
			string (list): Specifies the classification of the event.
			collectorGroups (list): Specifies the collector groups whose collector reported the events.
			string (list): Specifies the collector groups whose collector reported the events.
			destinations (list): Specifies the connection destination(s) of the events.
			string (list): Specifies the connection destination(s) of the events.
			device (str): Specifies the device name where the events occurred.
			deviceControl (bool): A true/false parameter indicating whether to include only device control events.
			deviceIps (list): Specifies the IPs of the devices where the event occurred.
			string (list): Specifies the IPs of the devices where the event occurred.
			eventIds (list): Specifies the required event IDs.
			integer (list): Specifies the required event IDs.
			eventType (list): Specifies the type of the event.
			string (list): Specifies the type of the event.
			expired (bool): A true/false parameter indicating whether to include only expired events.
			fileHash (str): Specifies the hash signature of the main process of the event.
			firstSeen (str):  Specifies the date when the event was first seen (Deprecated).
			firstSeenFrom (str): Specifies the from date when the event was first seen.
			firstSeenTo (str): Specifies the to date when the event was first seen.
			handled (bool):  A true/false parameter indicating whether events were handled/unhandled.
			itemsPerPage (int): An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000.
			lastSeen (str):  Specifies the date when the event was last seen (Deprecated).
			lastSeenFrom (str): Specifies the from date when the event was last seen.
			lastSeenTo (str): Specifies the to date when the event was last seen.
			loggedUser (str): Specifies the logged user.
			macAddresses (list): Specifies the mac addresses where the event occurred.
			string (list): Specifies the mac addresses where the event occurred.
			muted (bool): A true/false parameter indicating if the event is muted.
			operatingSystems (list): Specifies the operating system of the devices where the events occurred.
			string (list): Specifies the operating system of the devices where the events occurred.
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations..
			pageNumber (int): An integer used for paging that indicates the required page number.
			paths (list): Specifies the paths of the processes related to the event.
			string (list): Specifies the paths of the processes related to the event.
			process (str): Specifies the main process of the event.
			rule (str): Specifies the short rule name of the rule that triggered the events.
			seen (bool): A true/false parameter indicating whether events were read/unread by the user operating the API.
			severities (list): Specifies the severity of the event (Deprecated).
			string (list): Specifies the severity of the event (Deprecated).
			signed (bool): A true/false parameter indicating if the event is signed.
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on.
			strictMode (bool): A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False.
			updateEventsRequest (Object): Check 'updateEventsRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("insert_events", locals())

		url = '/management-rest/events'
		url_params = []
		if actions:
			url_params.append('actions=' + ",".join(str(actions)))
		if applicationControl:
			url_params.append('applicationControl=' + applicationControl)
		if archived:
			url_params.append('archived=' + archived)
		if classifications:
			url_params.append('classifications=' + ",".join(str(classifications)))
		if collectorGroups:
			url_params.append('collectorGroups=' + ",".join(str(collectorGroups)))
		if destinations:
			url_params.append('destinations=' + ",".join(str(destinations)))
		if device:
			url_params.append('device=' + device)
		if deviceControl:
			url_params.append('deviceControl=' + deviceControl)
		if deviceIps:
			url_params.append('deviceIps=' + ",".join(str(deviceIps)))
		if eventIds:
			url_params.append('eventIds=' + ",".join(map(str, eventIds)))
		if eventType:
			url_params.append('eventType=' + ",".join(str(eventType)))
		if expired:
			url_params.append('expired=' + expired)
		if fileHash:
			url_params.append('fileHash=' + fileHash)
		if firstSeen:
			url_params.append('firstSeen=' + firstSeen)
		if firstSeenFrom:
			url_params.append('firstSeenFrom=' + firstSeenFrom)
		if firstSeenTo:
			url_params.append('firstSeenTo=' + firstSeenTo)
		if handled:
			url_params.append('handled=' + handled)
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if lastSeen:
			url_params.append('lastSeen=' + lastSeen)
		if lastSeenFrom:
			url_params.append('lastSeenFrom=' + lastSeenFrom)
		if lastSeenTo:
			url_params.append('lastSeenTo=' + lastSeenTo)
		if loggedUser:
			url_params.append('loggedUser=' + loggedUser)
		if macAddresses:
			url_params.append('macAddresses=' + ",".join(str(macAddresses)))
		if muted:
			url_params.append('muted=' + muted)
		if operatingSystems:
			url_params.append('operatingSystems=' + ",".join(str(operatingSystems)))
		if organization:
			url_params.append('organization=' + organization)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if paths:
			url_params.append('paths=' + ",".join(str(paths)))
		if process:
			url_params.append('process=' + process)
		if rule:
			url_params.append('rule=' + rule)
		if seen:
			url_params.append('seen=' + seen)
		if severities:
			url_params.append('severities=' + ",".join(str(severities)))
		if signed:
			url_params.append('signed=' + signed)
		if sorting:
			url_params.append('sorting=' + sorting)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		url += '?' + '&'.join(url_params)

		updateEventsRequest = {}
		if archive: updateEventsRequest["archive"] = archive
		if classification: updateEventsRequest["classification"] = classification
		if comment: updateEventsRequest["comment"] = comment
		if familyName: updateEventsRequest["familyName"] = familyName
		if forceUnmute: updateEventsRequest["forceUnmute"] = forceUnmute
		if handle: updateEventsRequest["handle"] = handle
		if malwareType: updateEventsRequest["malwareType"] = malwareType
		if mute: updateEventsRequest["mute"] = mute
		if muteDuration: updateEventsRequest["muteDuration"] = muteDuration
		if read: updateEventsRequest["read"] = read
		if threatName: updateEventsRequest["threatName"] = threatName

		return fortiedr_connection.insert(url, updateEventsRequest)

	def delete_events(self, actions: list = None, applicationControl: bool = None, archived: bool = None, classifications: list = None, collectorGroups: list = None, deleteAll: bool = None, destinations: list = None, device: str = None, deviceControl: bool = None, deviceIps: list = None, eventIds: list = None, eventType: list = None, expired: bool = None, fileHash: str = None, firstSeen: str = None, firstSeenFrom: str = None, firstSeenTo: str = None, handled: bool = None, itemsPerPage: int = None, lastSeen: str = None, lastSeenFrom: str = None, lastSeenTo: str = None, loggedUser: str = None, macAddresses: list = None, muted: bool = None, operatingSystems: list = None, organization: str = None, pageNumber: int = None, paths: list = None, process: str = None, rule: str = None, seen: bool = None, severities: list = None, signed: bool = None, sorting: str = None, strictMode: bool = None) -> tuple[bool, None]:
		'''
		Class Events
		Description: This API call delete events.
        
		Args:
			actions (list): Specifies the action of the event.
			string (list): Specifies the action of the event.
			applicationControl (bool): A true/false parameter indicating whether to include only application control events.
			archived (bool): A true/false parameter indicating whether to include only archived events.
			classifications (list): Specifies the classification of the event.
			string (list): Specifies the classification of the event.
			collectorGroups (list): Specifies the collector groups whose collector reported the events.
			string (list): Specifies the collector groups whose collector reported the events.
			deleteAll (bool): A true/false parameter indicating if all events should be deleted.
			destinations (list): Specifies the connection destination(s) of the events.
			string (list): Specifies the connection destination(s) of the events.
			device (str): Specifies the device name where the events occurred.
			deviceControl (bool): A true/false parameter indicating whether to include only device control events.
			deviceIps (list): Specifies the IPs of the devices where the event occurred.
			string (list): Specifies the IPs of the devices where the event occurred.
			eventIds (list): Specifies the required event IDs.
			integer (list): Specifies the required event IDs.
			eventType (list): Specifies the type of the event.
			string (list): Specifies the type of the event.
			expired (bool): A true/false parameter indicating whether to include only expired events.
			fileHash (str): Specifies the hash signature of the main process of the event.
			firstSeen (str):  Specifies the date when the event was first seen (Deprecated).
			firstSeenFrom (str): Specifies the from date when the event was first seen.
			firstSeenTo (str): Specifies the to date when the event was first seen.
			handled (bool):  A true/false parameter indicating whether events were handled/unhandled.
			itemsPerPage (int): An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000.
			lastSeen (str):  Specifies the date when the event was last seen (Deprecated).
			lastSeenFrom (str): Specifies the from date when the event was last seen.
			lastSeenTo (str): Specifies the to date when the event was last seen.
			loggedUser (str): Specifies the logged user.
			macAddresses (list): Specifies the mac addresses where the event occurred.
			string (list): Specifies the mac addresses where the event occurred.
			muted (bool): A true/false parameter indicating if the event is muted.
			operatingSystems (list): Specifies the operating system of the devices where the events occurred.
			string (list): Specifies the operating system of the devices where the events occurred.
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations..
			pageNumber (int): An integer used for paging that indicates the required page number.
			paths (list): Specifies the paths of the processes related to the event.
			string (list): Specifies the paths of the processes related to the event.
			process (str): Specifies the main process of the event.
			rule (str): Specifies the short rule name of the rule that triggered the events.
			seen (bool): A true/false parameter indicating whether events were read/unread by the user operating the API.
			severities (list): Specifies the severity of the event (Deprecated).
			string (list): Specifies the severity of the event (Deprecated).
			signed (bool): A true/false parameter indicating if the event is signed.
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on.
			strictMode (bool): A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_events", locals())

		url = '/management-rest/events'
		url_params = []
		if actions:
			url_params.append('actions=' + ",".join(str(actions)))
		if applicationControl:
			url_params.append('applicationControl=' + applicationControl)
		if archived:
			url_params.append('archived=' + archived)
		if classifications:
			url_params.append('classifications=' + ",".join(str(classifications)))
		if collectorGroups:
			url_params.append('collectorGroups=' + ",".join(str(collectorGroups)))
		if deleteAll:
			url_params.append('deleteAll=' + deleteAll)
		if destinations:
			url_params.append('destinations=' + ",".join(str(destinations)))
		if device:
			url_params.append('device=' + device)
		if deviceControl:
			url_params.append('deviceControl=' + deviceControl)
		if deviceIps:
			url_params.append('deviceIps=' + ",".join(str(deviceIps)))
		if eventIds:
			url_params.append('eventIds=' + ",".join(map(str, eventIds)))
		if eventType:
			url_params.append('eventType=' + ",".join(str(eventType)))
		if expired:
			url_params.append('expired=' + expired)
		if fileHash:
			url_params.append('fileHash=' + fileHash)
		if firstSeen:
			url_params.append('firstSeen=' + firstSeen)
		if firstSeenFrom:
			url_params.append('firstSeenFrom=' + firstSeenFrom)
		if firstSeenTo:
			url_params.append('firstSeenTo=' + firstSeenTo)
		if handled:
			url_params.append('handled=' + handled)
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if lastSeen:
			url_params.append('lastSeen=' + lastSeen)
		if lastSeenFrom:
			url_params.append('lastSeenFrom=' + lastSeenFrom)
		if lastSeenTo:
			url_params.append('lastSeenTo=' + lastSeenTo)
		if loggedUser:
			url_params.append('loggedUser=' + loggedUser)
		if macAddresses:
			url_params.append('macAddresses=' + ",".join(str(macAddresses)))
		if muted:
			url_params.append('muted=' + muted)
		if operatingSystems:
			url_params.append('operatingSystems=' + ",".join(str(operatingSystems)))
		if organization:
			url_params.append('organization=' + organization)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if paths:
			url_params.append('paths=' + ",".join(str(paths)))
		if process:
			url_params.append('process=' + process)
		if rule:
			url_params.append('rule=' + rule)
		if seen:
			url_params.append('seen=' + seen)
		if severities:
			url_params.append('severities=' + ",".join(str(severities)))
		if signed:
			url_params.append('signed=' + signed)
		if sorting:
			url_params.append('sorting=' + sorting)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def count_events(self, actions: list = None, applicationControl: bool = None, archived: bool = None, classifications: list = None, collectorGroups: list = None, destinations: list = None, device: str = None, deviceControl: bool = None, deviceIps: list = None, eventIds: list = None, eventType: list = None, expired: bool = None, fileHash: str = None, firstSeen: str = None, firstSeenFrom: str = None, firstSeenTo: str = None, handled: bool = None, itemsPerPage: int = None, lastSeen: str = None, lastSeenFrom: str = None, lastSeenTo: str = None, loggedUser: str = None, macAddresses: list = None, muted: bool = None, operatingSystems: list = None, organization: str = None, pageNumber: int = None, paths: list = None, process: str = None, rule: str = None, seen: bool = None, severities: list = None, signed: bool = None, sorting: str = None, strictMode: bool = None) -> tuple[bool, int]:
		'''
		Class Events
		Description: Count Events.
        
		Args:
			actions (list): Specifies the action of the event.
			string (list): Specifies the action of the event.
			applicationControl (bool): A true/false parameter indicating whether to include only application control events.
			archived (bool): A true/false parameter indicating whether to include only archived events.
			classifications (list): Specifies the classification of the event.
			string (list): Specifies the classification of the event.
			collectorGroups (list): Specifies the collector groups whose collector reported the events.
			string (list): Specifies the collector groups whose collector reported the events.
			destinations (list): Specifies the connection destination(s) of the events.
			string (list): Specifies the connection destination(s) of the events.
			device (str): Specifies the device name where the events occurred.
			deviceControl (bool): A true/false parameter indicating whether to include only device control events.
			deviceIps (list): Specifies the IPs of the devices where the event occurred.
			string (list): Specifies the IPs of the devices where the event occurred.
			eventIds (list): Specifies the required event IDs.
			integer (list): Specifies the required event IDs.
			eventType (list): Specifies the type of the event.
			string (list): Specifies the type of the event.
			expired (bool): A true/false parameter indicating whether to include only expired events.
			fileHash (str): Specifies the hash signature of the main process of the event.
			firstSeen (str):  Specifies the date when the event was first seen (Deprecated).
			firstSeenFrom (str): Specifies the from date when the event was first seen.
			firstSeenTo (str): Specifies the to date when the event was first seen.
			handled (bool):  A true/false parameter indicating whether events were handled/unhandled.
			itemsPerPage (int): An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000.
			lastSeen (str):  Specifies the date when the event was last seen (Deprecated).
			lastSeenFrom (str): Specifies the from date when the event was last seen.
			lastSeenTo (str): Specifies the to date when the event was last seen.
			loggedUser (str): Specifies the logged user.
			macAddresses (list): Specifies the mac addresses where the event occurred.
			string (list): Specifies the mac addresses where the event occurred.
			muted (bool): A true/false parameter indicating if the event is muted.
			operatingSystems (list): Specifies the operating system of the devices where the events occurred.
			string (list): Specifies the operating system of the devices where the events occurred.
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations..
			pageNumber (int): An integer used for paging that indicates the required page number.
			paths (list): Specifies the paths of the processes related to the event.
			string (list): Specifies the paths of the processes related to the event.
			process (str): Specifies the main process of the event.
			rule (str): Specifies the short rule name of the rule that triggered the events.
			seen (bool): A true/false parameter indicating whether events were read/unread by the user operating the API.
			severities (list): Specifies the severity of the event (Deprecated).
			string (list): Specifies the severity of the event (Deprecated).
			signed (bool): A true/false parameter indicating if the event is signed.
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on.
			strictMode (bool): A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False.

		Returns:
			bool: Status of the request (True or False). 
			int
		'''
		validate_params("count_events", locals())

		url = '/management-rest/events/count-events'
		url_params = []
		if actions:
			url_params.append('actions=' + ",".join(str(actions)))
		if applicationControl:
			url_params.append('applicationControl=' + applicationControl)
		if archived:
			url_params.append('archived=' + archived)
		if classifications:
			url_params.append('classifications=' + ",".join(str(classifications)))
		if collectorGroups:
			url_params.append('collectorGroups=' + ",".join(str(collectorGroups)))
		if destinations:
			url_params.append('destinations=' + ",".join(str(destinations)))
		if device:
			url_params.append('device=' + device)
		if deviceControl:
			url_params.append('deviceControl=' + deviceControl)
		if deviceIps:
			url_params.append('deviceIps=' + ",".join(str(deviceIps)))
		if eventIds:
			url_params.append('eventIds=' + ",".join(map(str, eventIds)))
		if eventType:
			url_params.append('eventType=' + ",".join(str(eventType)))
		if expired:
			url_params.append('expired=' + expired)
		if fileHash:
			url_params.append('fileHash=' + fileHash)
		if firstSeen:
			url_params.append('firstSeen=' + firstSeen)
		if firstSeenFrom:
			url_params.append('firstSeenFrom=' + firstSeenFrom)
		if firstSeenTo:
			url_params.append('firstSeenTo=' + firstSeenTo)
		if handled:
			url_params.append('handled=' + handled)
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if lastSeen:
			url_params.append('lastSeen=' + lastSeen)
		if lastSeenFrom:
			url_params.append('lastSeenFrom=' + lastSeenFrom)
		if lastSeenTo:
			url_params.append('lastSeenTo=' + lastSeenTo)
		if loggedUser:
			url_params.append('loggedUser=' + loggedUser)
		if macAddresses:
			url_params.append('macAddresses=' + ",".join(str(macAddresses)))
		if muted:
			url_params.append('muted=' + muted)
		if operatingSystems:
			url_params.append('operatingSystems=' + ",".join(str(operatingSystems)))
		if organization:
			url_params.append('organization=' + organization)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if paths:
			url_params.append('paths=' + ",".join(str(paths)))
		if process:
			url_params.append('process=' + process)
		if rule:
			url_params.append('rule=' + rule)
		if seen:
			url_params.append('seen=' + seen)
		if severities:
			url_params.append('severities=' + ",".join(str(severities)))
		if signed:
			url_params.append('signed=' + signed)
		if sorting:
			url_params.append('sorting=' + sorting)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def create_exception(self, allCollectorGroups: bool = None, allDestinations: bool = None, allOrganizations: bool = None, allUsers: bool = None, collectorGroups: list = None, comment: str = None, destinations: list = None, eventId: int = None, exceptionId: int = None, useAnyPath: object = None, useInException: object = None, wildcardFiles: object = None, wildcardPaths: object = None, forceCreate: bool = None, organization: str = None, users: list = None) -> tuple[bool, str]:
		'''
		Class Events
		Description: This API call adds an exception to a specific event. The output of this call is a message indicating whether the creation of the exception .
        
		Args:
			allCollectorGroups (bool): A true/false parameter indicating whether the exception should be applied to all collector groups. When not used, all collector groups are selected.
			allDestinations (bool): A true/false parameter indicating whether the exception should be applied to all destinations. When not used, all destinations are selected.
			allOrganizations (bool): A true/false parameter indicating whether the exception should be applied to all the organizations (tenants). This parameter is only relevant in multi-tenancy environment. This parameter is only allowed for user with Hoster privilege (general admin).
			allUsers (bool): A true/false parameter indicating whether the exception should be applied to all users. When not used, all users are selected.
			collectorGroups (list): Specifies the list of all the collector groups to which the exception should be applied. When not used, all collector groups are selected.
			string (list): Specifies the list of all the collector groups to which the exception should be applied. When not used, all collector groups are selected.
			comment (str): Specifies a user-defined string to attach to the exception.
			destinations (list): A list of IPs to which the exception applies and/or the value all internal destinations.
			string (list): A list of IPs to which the exception applies and/or the value all internal destinations.
			eventId (int): Specifies the event ID on which to create the exception.
			exceptionId (int): Specifies the exception ID to edit.
			exceptionRequest (Object): Check 'exceptionRequest' in the API documentation for further information.
			forceCreate (bool): A true/false parameter indicating whether to create the exception, even if there are already exceptions that cover this given event.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.
			users (list): A list of users to which the exception.
			string (list): A list of users to which the exception.

		Returns:
			bool: Status of the request (True or False). 
			str
		'''
		validate_params("create_exception", locals())

		url = '/management-rest/events/create-exception'
		url_params = []
		if allCollectorGroups:
			url_params.append('allCollectorGroups=' + allCollectorGroups)
		if allDestinations:
			url_params.append('allDestinations=' + allDestinations)
		if allOrganizations:
			url_params.append('allOrganizations=' + allOrganizations)
		if allUsers:
			url_params.append('allUsers=' + allUsers)
		if collectorGroups:
			url_params.append('collectorGroups=' + ",".join(str(collectorGroups)))
		if comment:
			url_params.append('comment=' + comment)
		if destinations:
			url_params.append('destinations=' + ",".join(str(destinations)))
		if eventId:
			url_params.append('eventId=' + eventId)
		if exceptionId:
			url_params.append('exceptionId=' + exceptionId)
		if forceCreate:
			url_params.append('forceCreate=' + forceCreate)
		if organization:
			url_params.append('organization=' + organization)
		if users:
			url_params.append('users=' + ",".join(str(users)))
		url += '?' + '&'.join(url_params)

		exceptionRequest = {}
		if useAnyPath: exceptionRequest["useAnyPath"] = useAnyPath
		if useInException: exceptionRequest["useInException"] = useInException
		if wildcardFiles: exceptionRequest["wildcardFiles"] = wildcardFiles
		if wildcardPaths: exceptionRequest["wildcardPaths"] = wildcardPaths

		return fortiedr_connection.send(url, exceptionRequest)

	def export_raw_data_items_json(self, organization: str = None, rawItemIds: str = None) -> tuple[bool, None]:
		'''
		Class Events
		Description: Get event as Json format.
        
		Args:
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.
			rawItemIds (str): Specifies the raw data item event IDs.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("export_raw_data_items_json", locals())

		url = '/management-rest/events/export-raw-data-items-json'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		if rawItemIds:
			url_params.append('rawItemIds=' + rawItemIds)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def list_events(self, actions: list = None, applicationControl: bool = None, archived: bool = None, classifications: list = None, collectorGroups: list = None, destinations: list = None, device: str = None, deviceControl: bool = None, deviceIps: list = None, eventIds: list = None, eventType: list = None, expired: bool = None, fileHash: str = None, firstSeen: str = None, firstSeenFrom: str = None, firstSeenTo: str = None, handled: bool = None, itemsPerPage: int = None, lastSeen: str = None, lastSeenFrom: str = None, lastSeenTo: str = None, loggedUser: str = None, macAddresses: list = None, muted: bool = None, operatingSystems: list = None, organization: str = None, pageNumber: int = None, paths: list = None, process: str = None, rule: str = None, seen: bool = None, severities: list = None, signed: bool = None, sorting: str = None, strictMode: bool = None) -> tuple[bool, list]:
		'''
		Class Events
		Description: List Events.
        
		Args:
			actions (list): Specifies the action of the event.
			string (list): Specifies the action of the event.
			applicationControl (bool): A true/false parameter indicating whether to include only application control events.
			archived (bool): A true/false parameter indicating whether to include only archived events.
			classifications (list): Specifies the classification of the event.
			string (list): Specifies the classification of the event.
			collectorGroups (list): Specifies the collector groups whose collector reported the events.
			string (list): Specifies the collector groups whose collector reported the events.
			destinations (list): Specifies the connection destination(s) of the events.
			string (list): Specifies the connection destination(s) of the events.
			device (str): Specifies the device name where the events occurred.
			deviceControl (bool): A true/false parameter indicating whether to include only device control events.
			deviceIps (list): Specifies the IPs of the devices where the event occurred.
			string (list): Specifies the IPs of the devices where the event occurred.
			eventIds (list): Specifies the required event IDs.
			integer (list): Specifies the required event IDs.
			eventType (list): Specifies the type of the event.
			string (list): Specifies the type of the event.
			expired (bool): A true/false parameter indicating whether to include only expired events.
			fileHash (str): Specifies the hash signature of the main process of the event.
			firstSeen (str):  Specifies the date when the event was first seen (Deprecated).
			firstSeenFrom (str): Specifies the from date when the event was first seen.
			firstSeenTo (str): Specifies the to date when the event was first seen.
			handled (bool):  A true/false parameter indicating whether events were handled/unhandled.
			itemsPerPage (int): An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000.
			lastSeen (str):  Specifies the date when the event was last seen (Deprecated).
			lastSeenFrom (str): Specifies the from date when the event was last seen.
			lastSeenTo (str): Specifies the to date when the event was last seen.
			loggedUser (str): Specifies the logged user.
			macAddresses (list): Specifies the mac addresses where the event occurred.
			string (list): Specifies the mac addresses where the event occurred.
			muted (bool): A true/false parameter indicating if the event is muted.
			operatingSystems (list): Specifies the operating system of the devices where the events occurred.
			string (list): Specifies the operating system of the devices where the events occurred.
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations..
			pageNumber (int): An integer used for paging that indicates the required page number.
			paths (list): Specifies the paths of the processes related to the event.
			string (list): Specifies the paths of the processes related to the event.
			process (str): Specifies the main process of the event.
			rule (str): Specifies the short rule name of the rule that triggered the events.
			seen (bool): A true/false parameter indicating whether events were read/unread by the user operating the API.
			severities (list): Specifies the severity of the event (Deprecated).
			string (list): Specifies the severity of the event (Deprecated).
			signed (bool): A true/false parameter indicating if the event is signed.
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on.
			strictMode (bool): A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_events", locals())

		url = '/management-rest/events/list-events'
		url_params = []
		if actions:
			url_params.append('actions=' + ",".join(str(actions)))
		if applicationControl:
			url_params.append('applicationControl=' + applicationControl)
		if archived:
			url_params.append('archived=' + archived)
		if classifications:
			url_params.append('classifications=' + ",".join(str(classifications)))
		if collectorGroups:
			url_params.append('collectorGroups=' + ",".join(str(collectorGroups)))
		if destinations:
			url_params.append('destinations=' + ",".join(str(destinations)))
		if device:
			url_params.append('device=' + device)
		if deviceControl:
			url_params.append('deviceControl=' + deviceControl)
		if deviceIps:
			url_params.append('deviceIps=' + ",".join(str(deviceIps)))
		if eventIds:
			url_params.append('eventIds=' + ",".join(map(str, eventIds)))
		if eventType:
			url_params.append('eventType=' + ",".join(str(eventType)))
		if expired:
			url_params.append('expired=' + expired)
		if fileHash:
			url_params.append('fileHash=' + fileHash)
		if firstSeen:
			url_params.append('firstSeen=' + firstSeen)
		if firstSeenFrom:
			url_params.append('firstSeenFrom=' + firstSeenFrom)
		if firstSeenTo:
			url_params.append('firstSeenTo=' + firstSeenTo)
		if handled:
			url_params.append('handled=' + handled)
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if lastSeen:
			url_params.append('lastSeen=' + lastSeen)
		if lastSeenFrom:
			url_params.append('lastSeenFrom=' + lastSeenFrom)
		if lastSeenTo:
			url_params.append('lastSeenTo=' + lastSeenTo)
		if loggedUser:
			url_params.append('loggedUser=' + loggedUser)
		if macAddresses:
			url_params.append('macAddresses=' + ",".join(str(macAddresses)))
		if muted:
			url_params.append('muted=' + muted)
		if operatingSystems:
			url_params.append('operatingSystems=' + ",".join(str(operatingSystems)))
		if organization:
			url_params.append('organization=' + organization)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if paths:
			url_params.append('paths=' + ",".join(str(paths)))
		if process:
			url_params.append('process=' + process)
		if rule:
			url_params.append('rule=' + rule)
		if seen:
			url_params.append('seen=' + seen)
		if severities:
			url_params.append('severities=' + ",".join(str(severities)))
		if signed:
			url_params.append('signed=' + signed)
		if sorting:
			url_params.append('sorting=' + sorting)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def list_raw_data_items(self, eventId: int, collectorGroups: list = None, destinations: list = None, device: str = None, deviceIps: list = None, firstSeen: str = None, firstSeenFrom: str = None, firstSeenTo: str = None, fullDataRequested: bool = None, itemsPerPage: int = None, lastSeen: str = None, lastSeenFrom: str = None, lastSeenTo: str = None, loggedUser: str = None, organization: str = None, pageNumber: int = None, rawEventIds: list = None, sorting: str = None, strictMode: bool = None) -> tuple[bool, list]:
		'''
		Class Events
		Description: List raw data items.
        
		Args:
			collectorGroups (list): Specifies the collector groups whose collector reported the raw events.
			string (list): Specifies the collector groups whose collector reported the raw events.
			destinations (list): Specifies the connection destination(s) of the events.
			string (list): Specifies the connection destination(s) of the events.
			device (str): Specifies the name of the device where the raw event occurred.
			deviceIps (list): Specifies the IPs of the devices where the event occurred.
			string (list): Specifies the IPs of the devices where the event occurred.
			eventId (int): Specifies the ID of the event that holds the raw data items.
			firstSeen (str): Specifies the date when the raw data item was first seen (Deprecated).
			firstSeenFrom (str): Specifies the from date when the raw data item was first seen.
			firstSeenTo (str): Specifies the to date when the raw data item was first seen.
			fullDataRequested (bool): A true/false parameter indicating whether to include the event internal information.
			itemsPerPage (int): An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000.
			lastSeen (str): Specifies the date when the raw data item was last seen (Deprecated).
			lastSeenFrom (str): Specifies the from date when the raw data item was last seen.
			lastSeenTo (str): Specifies the to date when the raw data item was last seen.
			loggedUser (str): Specifies the logged user.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.
			pageNumber (int): An integer used for paging that indicates the required page number.
			rawEventIds (list): Specifies the list of raw data item event IDs.
			integer (list): Specifies the list of raw data item event IDs.
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on.
			strictMode (bool): A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_raw_data_items", locals())

		url = '/management-rest/events/list-raw-data-items'
		url_params = []
		if collectorGroups:
			url_params.append('collectorGroups=' + ",".join(str(collectorGroups)))
		if destinations:
			url_params.append('destinations=' + ",".join(str(destinations)))
		if device:
			url_params.append('device=' + device)
		if deviceIps:
			url_params.append('deviceIps=' + ",".join(str(deviceIps)))
		if eventId:
			url_params.append('eventId=' + eventId)
		if firstSeen:
			url_params.append('firstSeen=' + firstSeen)
		if firstSeenFrom:
			url_params.append('firstSeenFrom=' + firstSeenFrom)
		if firstSeenTo:
			url_params.append('firstSeenTo=' + firstSeenTo)
		if fullDataRequested:
			url_params.append('fullDataRequested=' + fullDataRequested)
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if lastSeen:
			url_params.append('lastSeen=' + lastSeen)
		if lastSeenFrom:
			url_params.append('lastSeenFrom=' + lastSeenFrom)
		if lastSeenTo:
			url_params.append('lastSeenTo=' + lastSeenTo)
		if loggedUser:
			url_params.append('loggedUser=' + loggedUser)
		if organization:
			url_params.append('organization=' + organization)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if rawEventIds:
			url_params.append('rawEventIds=' + ",".join(map(str, rawEventIds)))
		if sorting:
			url_params.append('sorting=' + sorting)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

class Exceptions:
	'''This API call outputs all exceptions in the system'''

	def create_or_edit_exception(self, confirmEdit: bool = None, exceptionJSON: str = None, organization: str = None) -> tuple[bool, int]:
		'''
		Class Exceptions
		Description: This API call creates a new exception or updates an existing exception based on the given exception JSON body parameter.
        
		Args:
			confirmEdit (bool): Confirm editing an existing exception in case of providing an exception ID in the body JSON. By default confirmEdit is false.
			exceptionJSON (str): exceptionJSON.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.

		Returns:
			bool: Status of the request (True or False). 
			int
		'''
		validate_params("create_or_edit_exception", locals())

		url = '/management-rest/exceptions/create-or-edit-exception'
		url_params = []
		if confirmEdit:
			url_params.append('confirmEdit=' + confirmEdit)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)


		return fortiedr_connection.send(url, exceptionJSON)

	def delete(self, collectorGroups: list = None, comment: str = None, createdAfter: str = None, createdBefore: str = None, deleteAll: bool = None, destination: str = None, exceptionId: int = None, exceptionIds: list = None, organization: str = None, path: str = None, process: str = None, rules: list = None, updatedAfter: str = None, updatedBefore: str = None, user: str = None) -> tuple[bool, None]:
		'''
		Class Exceptions
		Description: Delete exceptions.
        
		Args:
			collectorGroups (list): Specifies the list of all the collector groups to which the exception applied.
			string (list): Specifies the list of all the collector groups to which the exception applied.
			comment (str): Specifies a comment attach to the exception.
			createdAfter (str): Specifies the date after which the exception was created. Specify the date using the yyyy-MM-dd HH:mm:ss format.
			createdBefore (str): Specifies the date before which the exception was created. Specify the date using the yyyy-MM-dd HH:mm:ss format.
			deleteAll (bool): A true/false parameter indicating if all exception should be deleted.
			destination (str): Specifies a destination IP of the exception.
			exceptionId (int): Specifies the required exception ID.
			exceptionIds (list): Specifies a list of exception ids.
			integer (list): Specifies a list of exception ids.
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations..
			path (str): Specifies the path of the exception.
			process (str): Specifies the process of the exception.
			rules (list): Specifies a list of rule names.
			string (list): Specifies a list of rule names.
			updatedAfter (str): Specifies the date after which the exception was updated. Specify the date using the yyyy-MM-dd HH:mm:ss format.
			updatedBefore (str): Specifies the date before which the exception was updated. Specify the date using the yyyy-MM-dd HH:mm:ss format.
			user (str): Specifies a user of the exception.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete", locals())

		url = '/management-rest/exceptions/delete'
		url_params = []
		if collectorGroups:
			url_params.append('collectorGroups=' + ",".join(str(collectorGroups)))
		if comment:
			url_params.append('comment=' + comment)
		if createdAfter:
			url_params.append('createdAfter=' + createdAfter)
		if createdBefore:
			url_params.append('createdBefore=' + createdBefore)
		if deleteAll:
			url_params.append('deleteAll=' + deleteAll)
		if destination:
			url_params.append('destination=' + destination)
		if exceptionId:
			url_params.append('exceptionId=' + exceptionId)
		if exceptionIds:
			url_params.append('exceptionIds=' + ",".join(map(str, exceptionIds)))
		if organization:
			url_params.append('organization=' + organization)
		if path:
			url_params.append('path=' + path)
		if process:
			url_params.append('process=' + process)
		if rules:
			url_params.append('rules=' + ",".join(str(rules)))
		if updatedAfter:
			url_params.append('updatedAfter=' + updatedAfter)
		if updatedBefore:
			url_params.append('updatedBefore=' + updatedBefore)
		if user:
			url_params.append('user=' + user)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def get_event_exceptions(self, eventId: int, organization: str = None) -> tuple[bool, list]:
		'''
		Class Exceptions
		Description: Show exceptions.
        
		Args:
			eventId (int): Specifies the required event ID.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("get_event_exceptions", locals())

		url = '/management-rest/exceptions/get-event-exceptions'
		url_params = []
		if eventId:
			url_params.append('eventId=' + eventId)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def list_exceptions(self, collectorGroups: list = None, comment: str = None, createdAfter: str = None, createdBefore: str = None, destination: str = None, exceptionIds: list = None, organization: str = None, path: str = None, process: str = None, rules: list = None, updatedAfter: str = None, updatedBefore: str = None, user: str = None) -> tuple[bool, list]:
		'''
		Class Exceptions
		Description: List of exceptions.
        
		Args:
			collectorGroups (list): Specifies the list of all the collector groups to which the exception applied.
			string (list): Specifies the list of all the collector groups to which the exception applied.
			comment (str): Specifies a comment attach to the exception.
			createdAfter (str): Specifies the date after which the exception was created. Specify the date using the yyyy-MM-dd HH:mm:ss format.
			createdBefore (str): Specifies the date before which the exception was created. Specify the date using the yyyy-MM-dd HH:mm:ss format.
			destination (str): Specifies a destination IP of the exception.
			exceptionIds (list): Specifies a list of exception ids.
			integer (list): Specifies a list of exception ids.
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations..
			path (str): Specifies the path of the exception.
			process (str): Specifies the process of the exception.
			rules (list): Specifies a list of rule names.
			string (list): Specifies a list of rule names.
			updatedAfter (str): Specifies the date after which the exception was updated. Specify the date using the yyyy-MM-dd HH:mm:ss format.
			updatedBefore (str): Specifies the date before which the exception was updated. Specify the date using the yyyy-MM-dd HH:mm:ss format.
			user (str): Specifies a user of the exception.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_exceptions", locals())

		url = '/management-rest/exceptions/list-exceptions'
		url_params = []
		if collectorGroups:
			url_params.append('collectorGroups=' + ",".join(str(collectorGroups)))
		if comment:
			url_params.append('comment=' + comment)
		if createdAfter:
			url_params.append('createdAfter=' + createdAfter)
		if createdBefore:
			url_params.append('createdBefore=' + createdBefore)
		if destination:
			url_params.append('destination=' + destination)
		if exceptionIds:
			url_params.append('exceptionIds=' + ",".join(map(str, exceptionIds)))
		if organization:
			url_params.append('organization=' + organization)
		if path:
			url_params.append('path=' + path)
		if process:
			url_params.append('process=' + process)
		if rules:
			url_params.append('rules=' + ",".join(str(rules)))
		if updatedAfter:
			url_params.append('updatedAfter=' + updatedAfter)
		if updatedBefore:
			url_params.append('updatedBefore=' + updatedBefore)
		if user:
			url_params.append('user=' + user)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

class Forensics:
	'''The Forensics module facilitates deep analysis into the actual internals of the communicating devices operating system that led up to an event.'''

	def get_event_file(self, rawEventId: int, disk: bool = None, endRange: str = None, filePaths: list = None, memory: bool = None, organization: str = None, processId: int = None, startRange: str = None) -> tuple[bool, None]:
		'''
		Class Forensics
		Description: This API call retrieves a file or memory.
        
		Args:
			disk (bool): A true/false parameter indicating whether find in the disk.
			endRange (str): Specifies the memory end range, in Hexadecimal format.
			filePaths (list): Specifies the list of file paths.
			string (list): Specifies the list of file paths.
			memory (bool): A true/false parameter indicating whether find in the memory.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.
			processId (int): Specifies the ID of the process from which to take a memory image. required for memory base action.
			rawEventId (int): Specifies the ID of the raw event on which to perform the memory retrieval.
			startRange (str): Specifies the memory start range, in Hexadecimal format.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_event_file", locals())

		url = '/management-rest/forensics/get-event-file'
		url_params = []
		if disk:
			url_params.append('disk=' + disk)
		if endRange:
			url_params.append('endRange=' + endRange)
		if filePaths:
			url_params.append('filePaths=' + ",".join(str(filePaths)))
		if memory:
			url_params.append('memory=' + memory)
		if organization:
			url_params.append('organization=' + organization)
		if processId:
			url_params.append('processId=' + processId)
		if rawEventId:
			url_params.append('rawEventId=' + rawEventId)
		if startRange:
			url_params.append('startRange=' + startRange)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def get_file(self, device: str, filePaths: list, type: str, organization: str = None) -> tuple[bool, None]:
		'''
		Class Forensics
		Description: This API call retrieves a file or memory.
        
		Args:
			device (str): Specifies the name or id of the device to remediate.
			filePaths (list): Specifies the list of file paths.
			string (list): Specifies the list of file paths.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.
			type (str): Specifies the device parameter type used in the request : Name or ID.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("get_file", locals())

		url = '/management-rest/forensics/get-file'
		url_params = []
		if device:
			url_params.append('device=' + device)
		if filePaths:
			url_params.append('filePaths=' + ",".join(str(filePaths)))
		if organization:
			url_params.append('organization=' + organization)
		if type:
			url_params.append('type=' + type)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def remediate_device(self, terminatedProcessId: int, device: str = None, deviceId: int = None, executablesToRemove: list = None, organization: str = None, persistenceDataAction: str = None, persistenceDataNewContent: str = None, persistenceDataPath: str = None, persistenceDataValueName: str = None, persistenceDataValueNewType: str = None, processName: str = None, threadId: int = None) -> tuple[bool, None]:
		'''
		Class Forensics
		Description: This API kill process / delete file / clean persistence, File and persistence paths must be specified in a logical format.
        
		Args:
			device (str): Specifies the name of the device to remediate. You must specify a value for either device or deviceId (see below).
			deviceId (int): Specifies the unique identifier (ID) of the device to remediate. You must specify a value for either deviceId or device (see above).
			executablesToRemove (list): Specifies the list of full paths of executable files (*.exe) to delete on the
given device.
			string (list): Specifies the list of full paths of executable files (*.exe) to delete on the
given device.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.
			persistenceDataAction (str): persistence data desired action.
			persistenceDataNewContent (str): persistence data new content.
			persistenceDataPath (str): persistence data path.
			persistenceDataValueName (str): persistence data value name.
			persistenceDataValueNewType (str): persistence data value new type.
			processName (str): Specifies the process name.
			terminatedProcessId (int): Represents the process ID to terminate on the device.
			threadId (int): Specifies the thread ID.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("remediate_device", locals())

		url = '/management-rest/forensics/remediate-device'
		url_params = []
		if device:
			url_params.append('device=' + device)
		if deviceId:
			url_params.append('deviceId=' + deviceId)
		if executablesToRemove:
			url_params.append('executablesToRemove=' + ",".join(str(executablesToRemove)))
		if organization:
			url_params.append('organization=' + organization)
		if persistenceDataAction:
			url_params.append('persistenceDataAction=' + persistenceDataAction)
		if persistenceDataNewContent:
			url_params.append('persistenceDataNewContent=' + persistenceDataNewContent)
		if persistenceDataPath:
			url_params.append('persistenceDataPath=' + persistenceDataPath)
		if persistenceDataValueName:
			url_params.append('persistenceDataValueName=' + persistenceDataValueName)
		if persistenceDataValueNewType:
			url_params.append('persistenceDataValueNewType=' + persistenceDataValueNewType)
		if processName:
			url_params.append('processName=' + processName)
		if terminatedProcessId:
			url_params.append('terminatedProcessId=' + terminatedProcessId)
		if threadId:
			url_params.append('threadId=' + threadId)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

class HashSearch:
	'''The Hash Search API'''

	def search(self, fileHashes: list, organization: str = None) -> tuple[bool, None]:
		'''
		Class HashSearch
		Description: This API enables the user to search a file hash among the current events, threat hunting repository and communicating applications that exist in the system.
        
		Args:
			fileHashes (list): Specifies the list of files hashes.
			string (list): Specifies the list of files hashes.
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations..

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("search", locals())

		url = '/management-rest/hash/search'
		url_params = []
		if fileHashes:
			url_params.append('fileHashes=' + ",".join(str(fileHashes)))
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

class Integrations:
	'''API to create and test connectors.'''

	def connectors_metadata(self, organization: str = None) -> tuple[bool, None]:
		'''
		Class Integrations
		Description: Get connectors metadata, describing the valid values for connector fields definition and on-premise cores..
        
		Args:
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("connectors_metadata", locals())

		url = '/management-rest/integrations/connectors-metadata'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def create_connector(self, apiKey: str = None, connectorActions: list = None, coreId: int = None, enabled: bool = None, host: str = None, name: str = None, organization: str = None, password: str = None, port: str = None, type: str = None, username: str = None, vendor: str = None) -> tuple[bool, None]:
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
		if apiKey: createConnectorRequest["apiKey"] = apiKey
		if connectorActions: createConnectorRequest["connectorActions"] = connectorActions
		if coreId: createConnectorRequest["coreId"] = str(coreId)
		if enabled: createConnectorRequest["enabled"] = enabled
		if host: createConnectorRequest["host"] = host
		if name: createConnectorRequest["name"] = name
		if organization: createConnectorRequest["organization"] = organization
		if password: createConnectorRequest["password"] = password
		if port: createConnectorRequest["port"] = port
		if type: createConnectorRequest["type"] = type
		if username: createConnectorRequest["username"] = username
		if vendor: createConnectorRequest["vendor"] = vendor

		return fortiedr_connection.send(url, createConnectorRequest)

	def delete_connector(self, connectorName: str, connectorType: str, organization: str = None) -> tuple[bool, None]:
		'''
		Class Integrations
		Description: Deletes a connector.
        
		Args:
			connectorName (str): Specifies the connector's name (case sensitive).
			connectorType (str): Specifies the connector's type..
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_connector", locals())

		url = '/management-rest/integrations/delete-connector'
		url_params = []
		if connectorName:
			url_params.append('connectorName=' + connectorName)
		if connectorType:
			url_params.append('connectorType=' + connectorType)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def list_connectors(self, onlyValidConnectors: bool = None, organization: str = None) -> tuple[bool, list]:
		'''
		Class Integrations
		Description: List all organization connectors.
        
		Args:
			onlyValidConnectors (bool): Set to true to retrieve enabled, non-failing connectors..
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_connectors", locals())

		url = '/management-rest/integrations/list-connectors'
		url_params = []
		if onlyValidConnectors:
			url_params.append('onlyValidConnectors=' + onlyValidConnectors)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def test_connector(self, connectorName: str, connectorType: str, organization: str = None) -> tuple[bool, None]:
		'''
		Class Integrations
		Description: Tests a connector.
        
		Args:
			connectorName (str): Specifies the connector's name (case sensitive).
			connectorType (str): Specifies the connector's type..
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("test_connector", locals())

		url = '/management-rest/integrations/test-connector'
		url_params = []
		if connectorName:
			url_params.append('connectorName=' + connectorName)
		if connectorType:
			url_params.append('connectorType=' + connectorType)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def update_connector(self, apiKey: str = None, connectorActions: list = None, coreId: int = None, enabled: bool = None, host: str = None, name: str = None, organization: str = None, password: str = None, port: str = None, type: str = None, username: str = None, vendor: str = None) -> tuple[bool, None]:
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
		if apiKey: updateConnectorRequest["apiKey"] = apiKey
		if connectorActions: updateConnectorRequest["connectorActions"] = connectorActions
		if coreId: updateConnectorRequest["coreId"] = str(coreId)
		if enabled: updateConnectorRequest["enabled"] = enabled
		if host: updateConnectorRequest["host"] = host
		if name: updateConnectorRequest["name"] = name
		if organization: updateConnectorRequest["organization"] = organization
		if password: updateConnectorRequest["password"] = password
		if port: updateConnectorRequest["port"] = port
		if type: updateConnectorRequest["type"] = type
		if username: updateConnectorRequest["username"] = username
		if vendor: updateConnectorRequest["vendor"] = vendor

		return fortiedr_connection.insert(url, updateConnectorRequest)

class SystemInventory:
	'''The System Inventory module enables you to monitor the health of Fortinet Endpoint Protection and Response Platform components and to create Collector Groups.'''

	def aggregator_logs(self, device: str = None, deviceId: int = None, organization: str = None) -> tuple[bool, None]:
		'''
		Class SystemInventory
		Description: This API call retrieves a aggregator logs.
        
		Args:
			device (str): Specifies the name of the device.
			deviceId (int): Specifies the ID of the device.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("aggregator_logs", locals())

		url = '/management-rest/inventory/aggregator-logs'
		url_params = []
		if device:
			url_params.append('device=' + device)
		if deviceId:
			url_params.append('deviceId=' + deviceId)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def check_custom_installer(self, customInstallerID: str, ) -> tuple[bool, None]:
		'''
		Class SystemInventory
		Description: This API call for checking the results for an custom installer request and getting the installer url.
        
		Args:
			customInstallerID (str): customInstallerID.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("check_custom_installer", locals())

		url = '/management-rest/inventory/check-custom-installer'
		url_params = []
		if customInstallerID:
			url_params.append('customInstallerID=' + customInstallerID)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def collector_logs(self, device: str = None, deviceId: int = None, organization: str = None) -> tuple[bool, None]:
		'''
		Class SystemInventory
		Description: This API call retrieves a collector logs.
        
		Args:
			device (str): Specifies the name of the device.
			deviceId (int): Specifies the ID of the device.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("collector_logs", locals())

		url = '/management-rest/inventory/collector-logs'
		url_params = []
		if device:
			url_params.append('device=' + device)
		if deviceId:
			url_params.append('deviceId=' + deviceId)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def core_logs(self, device: str = None, deviceId: int = None, organization: str = None) -> tuple[bool, None]:
		'''
		Class SystemInventory
		Description: This API call retrieves a core logs.
        
		Args:
			device (str): Specifies the name of the device.
			deviceId (int): Specifies the ID of the device.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("core_logs", locals())

		url = '/management-rest/inventory/core-logs'
		url_params = []
		if device:
			url_params.append('device=' + device)
		if deviceId:
			url_params.append('deviceId=' + deviceId)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def create_collector_group(self, name: str, organization: str = None) -> tuple[bool, None]:
		'''
		Class SystemInventory
		Description: This API call create collector group.
        
		Args:
			name (str): Collector group name.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("create_collector_group", locals())

		url = '/management-rest/inventory/create-collector-group'
		url_params = []
		if name:
			url_params.append('name=' + name)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.send(url)

	def delete_collectors(self, cloudAccounts: list = None, cloudProviders: list = None, clusters: list = None, collectorGroups: list = None, collectorGroupsIds: list = None, collectorType: str = None, confirmDeletion: bool = None, deleteAll: bool = None, devices: list = None, devicesIds: list = None, firstSeen: str = None, hasCrashDumps: bool = None, ips: list = None, itemsPerPage: int = None, lastSeenEnd: str = None, lastSeenStart: str = None, loggedUser: str = None, operatingSystems: list = None, organization: str = None, osFamilies: list = None, pageNumber: int = None, showExpired: bool = None, sorting: str = None, states: list = None, strictMode: bool = None, versions: list = None) -> tuple[bool, None]:
		'''
		Class SystemInventory
		Description: This API call deletes a Collector(s).
        
		Args:
			cloudAccounts (list): Specifies the list cloud account names.
			string (list): Specifies the list cloud account names.
			cloudProviders (list): Specifies the list of cloud providers: AWS, Azure, GCP.
			string (list): Specifies the list of cloud providers: AWS, Azure, GCP.
			clusters (list): Specifies the list of cluster.
			string (list): Specifies the list of cluster.
			collectorGroups (list): Specifies the list of collector group names and retrieves collectors under the
given groups.
			string (list): Specifies the list of collector group names and retrieves collectors under the
given groups.
			collectorGroupsIds (list): Specifies the list of collector group Ids and retrieves collectors under the
given groups.
			integer (list): Specifies the list of collector group Ids and retrieves collectors under the
given groups.
			collectorType (str): Specifies the group types of the collectors. Types: All, Collector, Workloads. All by default.
			confirmDeletion (bool): A true/false parameter indicating if to detach/delete relevant exceptions from Collector groups about to be deleted.
			deleteAll (bool): A true/false parameter indicating if all collectors should be deleted.
			devices (list): Specifies the list of device names.
			string (list): Specifies the list of device names.
			devicesIds (list): Specifies the list of device ids.
			integer (list): Specifies the list of device ids.
			firstSeen (str): Retrieves collectors that were first seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss.
			hasCrashDumps (bool): Retrieves collectors that have crash dumps.
			ips (list): Specifies the list of IP values.
			string (list): Specifies the list of IP values.
			itemsPerPage (int): An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000.
			lastSeenEnd (str): Retrieves collectors that were last seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss.
			lastSeenStart (str): Retrieves collectors that were last seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss.
			loggedUser (str): Specifies the user that was logged when the event occurred.
			operatingSystems (list): Specifies the list of specific operating systems. For example, Windows 7 Pro.
			string (list): Specifies the list of specific operating systems. For example, Windows 7 Pro.
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
.
			osFamilies (list): Specifies the list of operating system families: Windows, Windows Server or OS X.
			string (list): Specifies the list of operating system families: Windows, Windows Server or OS X.
			pageNumber (int): An integer used for paging that indicates the required page number.
			showExpired (bool): Specifies whether to include collectors which have been disconnected for more than 30 days (sequentially) and are marked as Expired.
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on.
			states (list): Specifies the list of collector states: Running, Disconnected, Disabled, Degraded, 
Pending Reboot, Isolated, Expired, Migrated or Pending Migration.
			string (list): Specifies the list of collector states: Running, Disconnected, Disabled, Degraded, 
Pending Reboot, Isolated, Expired, Migrated or Pending Migration.
			strictMode (bool): A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False.
			versions (list): Specifies the list of collector versions.
			string (list): Specifies the list of collector versions.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_collectors", locals())

		url = '/management-rest/inventory/delete-collectors'
		url_params = []
		if cloudAccounts:
			url_params.append('cloudAccounts=' + ",".join(str(cloudAccounts)))
		if cloudProviders:
			url_params.append('cloudProviders=' + ",".join(str(cloudProviders)))
		if clusters:
			url_params.append('clusters=' + ",".join(str(clusters)))
		if collectorGroups:
			url_params.append('collectorGroups=' + ",".join(str(collectorGroups)))
		if collectorGroupsIds:
			url_params.append('collectorGroupsIds=' + ",".join(map(str, collectorGroupsIds)))
		if collectorType:
			url_params.append('collectorType=' + collectorType)
		if confirmDeletion:
			url_params.append('confirmDeletion=' + confirmDeletion)
		if deleteAll:
			url_params.append('deleteAll=' + deleteAll)
		if devices:
			url_params.append('devices=' + ",".join(str(devices)))
		if devicesIds:
			url_params.append('devicesIds=' + ",".join(map(str, devicesIds)))
		if firstSeen:
			url_params.append('firstSeen=' + firstSeen)
		if hasCrashDumps:
			url_params.append('hasCrashDumps=' + hasCrashDumps)
		if ips:
			url_params.append('ips=' + ",".join(str(ips)))
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if lastSeenEnd:
			url_params.append('lastSeenEnd=' + lastSeenEnd)
		if lastSeenStart:
			url_params.append('lastSeenStart=' + lastSeenStart)
		if loggedUser:
			url_params.append('loggedUser=' + loggedUser)
		if operatingSystems:
			url_params.append('operatingSystems=' + ",".join(str(operatingSystems)))
		if organization:
			url_params.append('organization=' + organization)
		if osFamilies:
			url_params.append('osFamilies=' + ",".join(str(osFamilies)))
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if showExpired:
			url_params.append('showExpired=' + showExpired)
		if sorting:
			url_params.append('sorting=' + sorting)
		if states:
			url_params.append('states=' + ",".join(str(states)))
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		if versions:
			url_params.append('versions=' + ",".join(str(versions)))
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def isolate_collectors(self, devices: list = None, devicesIds: list = None, organization: str = None) -> tuple[bool, None]:
		'''
		Class SystemInventory
		Description: This API call isolate collector functionality.
        
		Args:
			devices (list): Specifies the list of device names.
			string (list): Specifies the list of device names.
			devicesIds (list): Specifies the list of device ids.
			integer (list): Specifies the list of device ids.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("isolate_collectors", locals())

		url = '/management-rest/inventory/isolate-collectors'
		url_params = []
		if devices:
			url_params.append('devices=' + ",".join(str(devices)))
		if devicesIds:
			url_params.append('devicesIds=' + ",".join(map(str, devicesIds)))
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def list_aggregators(self, ip: str = None, names: list = None, organization: str = None, versions: list = None) -> tuple[bool, list]:
		'''
		Class SystemInventory
		Description: This API call output the list of aggregators.
        
		Args:
			ip (str): IP.
			names (list): List of aggregators names.
			string (list): List of aggregators names.
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations..
			versions (list): List of aggregators versions.
			string (list): List of aggregators versions.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_aggregators", locals())

		url = '/management-rest/inventory/list-aggregators'
		url_params = []
		if ip:
			url_params.append('ip=' + ip)
		if names:
			url_params.append('names=' + ",".join(str(names)))
		if organization:
			url_params.append('organization=' + organization)
		if versions:
			url_params.append('versions=' + ",".join(str(versions)))
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def list_collector_groups(self, organization: str = None) -> tuple[bool, list]:
		'''
		Class SystemInventory
		Description: This API call output the collectors groups.
        
		Args:
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations..

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_collector_groups", locals())

		url = '/management-rest/inventory/list-collector-groups'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def list_collectors(self, cloudAccounts: list = None, cloudProviders: list = None, clusters: list = None, collectorGroups: list = None, collectorGroupsIds: list = None, collectorType: str = None, devices: list = None, devicesIds: list = None, firstSeen: str = None, hasCrashDumps: bool = None, ips: list = None, itemsPerPage: int = None, lastSeenEnd: str = None, lastSeenStart: str = None, loggedUser: str = None, operatingSystems: list = None, organization: str = None, osFamilies: list = None, pageNumber: int = None, showExpired: bool = None, sorting: str = None, states: list = None, strictMode: bool = None, versions: list = None) -> tuple[bool, list]:
		'''
		Class SystemInventory
		Description: This API call outputs a list of the Collectors in the system. Use the input parameters to filter the list.
        
		Args:
			cloudAccounts (list): Specifies the list cloud account names.
			string (list): Specifies the list cloud account names.
			cloudProviders (list): Specifies the list of cloud providers: AWS, Azure, GCP.
			string (list): Specifies the list of cloud providers: AWS, Azure, GCP.
			clusters (list): Specifies the list of cluster.
			string (list): Specifies the list of cluster.
			collectorGroups (list): Specifies the list of collector group names and retrieves collectors under the
given groups.
			string (list): Specifies the list of collector group names and retrieves collectors under the
given groups.
			collectorGroupsIds (list): Specifies the list of collector group Ids and retrieves collectors under the
given groups.
			integer (list): Specifies the list of collector group Ids and retrieves collectors under the
given groups.
			collectorType (str): Specifies the group types of the collectors. Types: All, Collector, Workloads. All by default.
			devices (list): Specifies the list of device names.
			string (list): Specifies the list of device names.
			devicesIds (list): Specifies the list of device ids.
			integer (list): Specifies the list of device ids.
			firstSeen (str): Retrieves collectors that were first seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss.
			hasCrashDumps (bool): Retrieves collectors that have crash dumps.
			ips (list): Specifies the list of IP values.
			string (list): Specifies the list of IP values.
			itemsPerPage (int): An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000.
			lastSeenEnd (str): Retrieves collectors that were last seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss.
			lastSeenStart (str): Retrieves collectors that were last seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss.
			loggedUser (str): Specifies the user that was logged when the event occurred.
			operatingSystems (list): Specifies the list of specific operating systems. For example, Windows 7 Pro.
			string (list): Specifies the list of specific operating systems. For example, Windows 7 Pro.
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
.
			osFamilies (list): Specifies the list of operating system families: Windows, Windows Server or OS X.
			string (list): Specifies the list of operating system families: Windows, Windows Server or OS X.
			pageNumber (int): An integer used for paging that indicates the required page number.
			showExpired (bool): Specifies whether to include collectors which have been disconnected for more than 30 days (sequentially) and are marked as Expired.
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on.
			states (list): Specifies the list of collector states: Running, Disconnected, Disabled, Degraded, 
Pending Reboot, Isolated, Expired, Migrated or Pending Migration.
			string (list): Specifies the list of collector states: Running, Disconnected, Disabled, Degraded, 
Pending Reboot, Isolated, Expired, Migrated or Pending Migration.
			strictMode (bool): A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False.
			versions (list): Specifies the list of collector versions.
			string (list): Specifies the list of collector versions.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_collectors", locals())

		url = '/management-rest/inventory/list-collectors'
		url_params = []
		if cloudAccounts:
			url_params.append('cloudAccounts=' + ",".join(str(cloudAccounts)))
		if cloudProviders:
			url_params.append('cloudProviders=' + ",".join(str(cloudProviders)))
		if clusters:
			url_params.append('clusters=' + ",".join(str(clusters)))
		if collectorGroups:
			url_params.append('collectorGroups=' + ",".join(str(collectorGroups)))
		if collectorGroupsIds:
			url_params.append('collectorGroupsIds=' + ",".join(map(str, collectorGroupsIds)))
		if collectorType:
			url_params.append('collectorType=' + collectorType)
		if devices:
			url_params.append('devices=' + ",".join(str(devices)))
		if devicesIds:
			url_params.append('devicesIds=' + ",".join(map(str, devicesIds)))
		if firstSeen:
			url_params.append('firstSeen=' + firstSeen)
		if hasCrashDumps:
			url_params.append('hasCrashDumps=' + hasCrashDumps)
		if ips:
			url_params.append('ips=' + ",".join(str(ips)))
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if lastSeenEnd:
			url_params.append('lastSeenEnd=' + lastSeenEnd)
		if lastSeenStart:
			url_params.append('lastSeenStart=' + lastSeenStart)
		if loggedUser:
			url_params.append('loggedUser=' + loggedUser)
		if operatingSystems:
			url_params.append('operatingSystems=' + ",".join(str(operatingSystems)))
		if organization:
			url_params.append('organization=' + organization)
		if osFamilies:
			url_params.append('osFamilies=' + ",".join(str(osFamilies)))
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if showExpired:
			url_params.append('showExpired=' + showExpired)
		if sorting:
			url_params.append('sorting=' + sorting)
		if states:
			url_params.append('states=' + ",".join(str(states)))
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		if versions:
			url_params.append('versions=' + ",".join(str(versions)))
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def list_cores(self, deploymentModes: list = None, hasCrashDumps: bool = None, ip: str = None, names: list = None, organization: str = None, versions: list = None) -> tuple[bool, list]:
		'''
		Class SystemInventory
		Description: This API call output the list of cores.
        
		Args:
			deploymentModes (list): List of cores deployments modes.
			string (list): List of cores deployments modes.
			hasCrashDumps (bool): Has crash dumps.
			ip (str): IP.
			names (list): List of cores names.
			string (list): List of cores names.
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations..
			versions (list): List of cores versions.
			string (list): List of cores versions.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_cores", locals())

		url = '/management-rest/inventory/list-cores'
		url_params = []
		if deploymentModes:
			url_params.append('deploymentModes=' + ",".join(str(deploymentModes)))
		if hasCrashDumps:
			url_params.append('hasCrashDumps=' + hasCrashDumps)
		if ip:
			url_params.append('ip=' + ip)
		if names:
			url_params.append('names=' + ",".join(str(names)))
		if organization:
			url_params.append('organization=' + organization)
		if versions:
			url_params.append('versions=' + ",".join(str(versions)))
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
			itemsPerPage (int): An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000.
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations..
			pageNumber (int): An integer used for paging that indicates the required page number.
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on.
			strictMode (bool): A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_unmanaged_devices", locals())

		url = '/management-rest/inventory/list-unmanaged-devices'
		url_params = []
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if organization:
			url_params.append('organization=' + organization)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if sorting:
			url_params.append('sorting=' + sorting)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def move_collectors(self, targetCollectorGroup: str, collectorIds: list = None, collectorSIDs: list = None, collectors: list = None, forceAssign: bool = None, organization: str = None) -> tuple[bool, None]:
		'''
		Class SystemInventory
		Description: This API call move collector between groups.
        
		Args:
			collectorIds (list): value = Array of collectors Ids. To move collectors from one organization to another.
			integer (list): value = Array of collectors Ids. To move collectors from one organization to another.
			collectorSIDs (list): value = Array of collectors SIDS. To move collectors from one organization to another.
			string (list): value = Array of collectors SIDS. To move collectors from one organization to another.
			collectors (list): Array of collectors names. To move collectors from one organization to another, for each collector please add the organization name before the collector name (<organization-name>\\<collector-name>).
			string (list): Array of collectors names. To move collectors from one organization to another, for each collector please add the organization name before the collector name (<organization-name>\\<collector-name>).
			forceAssign (bool): Indicates whether to force the assignment even if the organization of the target Collector group is under migration.
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations..
			targetCollectorGroup (str): Collector group. To move collectors from one organization to another, please add the organization name before the target collector group (<organization-name>\\<collector-group-name>).

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("move_collectors", locals())

		url = '/management-rest/inventory/move-collectors'
		url_params = []
		if collectorIds:
			url_params.append('collectorIds=' + ",".join(map(str, collectorIds)))
		if collectorSIDs:
			url_params.append('collectorSIDs=' + ",".join(str(collectorSIDs)))
		if collectors:
			url_params.append('collectors=' + ",".join(str(collectors)))
		if forceAssign:
			url_params.append('forceAssign=' + forceAssign)
		if organization:
			url_params.append('organization=' + organization)
		if targetCollectorGroup:
			url_params.append('targetCollectorGroup=' + targetCollectorGroup)
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
			cloudAccounts (list): Specifies the list cloud account names.
			string (list): Specifies the list cloud account names.
			cloudProviders (list): Specifies the list of cloud providers: AWS, Azure, GCP.
			string (list): Specifies the list of cloud providers: AWS, Azure, GCP.
			clusters (list): Specifies the list of cluster.
			string (list): Specifies the list of cluster.
			collectorGroups (list): Specifies the list of collector group names and retrieves collectors under the
given groups.
			string (list): Specifies the list of collector group names and retrieves collectors under the
given groups.
			collectorGroupsIds (list): Specifies the list of collector group Ids and retrieves collectors under the
given groups.
			integer (list): Specifies the list of collector group Ids and retrieves collectors under the
given groups.
			collectorType (str): Specifies the group types of the collectors. Types: All, Collector, Workloads. All by default.
			devices (list): Specifies the list of device names.
			string (list): Specifies the list of device names.
			devicesIds (list): Specifies the list of device ids.
			integer (list): Specifies the list of device ids.
			enable (bool): Toggle enable.
			firstSeen (str): Retrieves collectors that were first seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss.
			hasCrashDumps (bool): Retrieves collectors that have crash dumps.
			ips (list): Specifies the list of IP values.
			string (list): Specifies the list of IP values.
			itemsPerPage (int): An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000.
			lastSeenEnd (str): Retrieves collectors that were last seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss.
			lastSeenStart (str): Retrieves collectors that were last seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss.
			loggedUser (str): Specifies the user that was logged when the event occurred.
			operatingSystems (list): Specifies the list of specific operating systems. For example, Windows 7 Pro.
			string (list): Specifies the list of specific operating systems. For example, Windows 7 Pro.
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
.
			osFamilies (list): Specifies the list of operating system families: Windows, Windows Server or OS X.
			string (list): Specifies the list of operating system families: Windows, Windows Server or OS X.
			pageNumber (int): An integer used for paging that indicates the required page number.
			showExpired (bool): Specifies whether to include collectors which have been disconnected for more than 30 days (sequentially) and are marked as Expired.
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on.
			states (list): Specifies the list of collector states: Running, Disconnected, Disabled, Degraded, 
Pending Reboot, Isolated, Expired, Migrated or Pending Migration.
			string (list): Specifies the list of collector states: Running, Disconnected, Disabled, Degraded, 
Pending Reboot, Isolated, Expired, Migrated or Pending Migration.
			strictMode (bool): A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False.
			versions (list): Specifies the list of collector versions.
			string (list): Specifies the list of collector versions.

		Returns:
			bool: Status of the request (True or False). 
			str
		'''
		validate_params("toggle_collectors", locals())

		url = '/management-rest/inventory/toggle-collectors'
		url_params = []
		if cloudAccounts:
			url_params.append('cloudAccounts=' + ",".join(str(cloudAccounts)))
		if cloudProviders:
			url_params.append('cloudProviders=' + ",".join(str(cloudProviders)))
		if clusters:
			url_params.append('clusters=' + ",".join(str(clusters)))
		if collectorGroups:
			url_params.append('collectorGroups=' + ",".join(str(collectorGroups)))
		if collectorGroupsIds:
			url_params.append('collectorGroupsIds=' + ",".join(map(str, collectorGroupsIds)))
		if collectorType:
			url_params.append('collectorType=' + collectorType)
		if devices:
			url_params.append('devices=' + ",".join(str(devices)))
		if devicesIds:
			url_params.append('devicesIds=' + ",".join(map(str, devicesIds)))
		if enable:
			url_params.append('enable=' + enable)
		if firstSeen:
			url_params.append('firstSeen=' + firstSeen)
		if hasCrashDumps:
			url_params.append('hasCrashDumps=' + hasCrashDumps)
		if ips:
			url_params.append('ips=' + ",".join(str(ips)))
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if lastSeenEnd:
			url_params.append('lastSeenEnd=' + lastSeenEnd)
		if lastSeenStart:
			url_params.append('lastSeenStart=' + lastSeenStart)
		if loggedUser:
			url_params.append('loggedUser=' + loggedUser)
		if operatingSystems:
			url_params.append('operatingSystems=' + ",".join(str(operatingSystems)))
		if organization:
			url_params.append('organization=' + organization)
		if osFamilies:
			url_params.append('osFamilies=' + ",".join(str(osFamilies)))
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if showExpired:
			url_params.append('showExpired=' + showExpired)
		if sorting:
			url_params.append('sorting=' + sorting)
		if states:
			url_params.append('states=' + ",".join(str(states)))
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		if versions:
			url_params.append('versions=' + ",".join(str(versions)))
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def unisolate_collectors(self, devices: list = None, devicesIds: list = None, organization: str = None) -> tuple[bool, None]:
		'''
		Class SystemInventory
		Description: This API call isolate collector functionality.
        
		Args:
			devices (list): Specifies the list of device names.
			string (list): Specifies the list of device names.
			devicesIds (list): Specifies the list of device ids.
			integer (list): Specifies the list of device ids.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("unisolate_collectors", locals())

		url = '/management-rest/inventory/unisolate-collectors'
		url_params = []
		if devices:
			url_params.append('devices=' + ",".join(str(devices)))
		if devicesIds:
			url_params.append('devicesIds=' + ",".join(map(str, devicesIds)))
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

class IoT:
	'''The IoT module enables you to monitor the devices found in IoT scans and create/move IoT Groups.'''

	def create_iot_group(self, name: str, organization: str = None) -> tuple[bool, None]:
		'''
		Class IoT
		Description: This API call create IoT group.
        
		Args:
			name (str): IoT group name.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("create_iot_group", locals())

		url = '/management-rest/iot/create-iot-group'
		url_params = []
		if name:
			url_params.append('name=' + name)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.send(url)

	def delete_devices(self, categories: list = None, devices: list = None, devicesIds: list = None, firstSeenEnd: str = None, firstSeenStart: str = None, internalIps: list = None, iotGroups: list = None, iotGroupsIds: list = None, itemsPerPage: int = None, lastSeenEnd: str = None, lastSeenStart: str = None, locations: list = None, macAddresses: list = None, models: list = None, organization: str = None, pageNumber: int = None, showExpired: bool = None, sorting: str = None, strictMode: bool = None, vendors: list = None) -> tuple[bool, None]:
		'''
		Class IoT
		Description: This API call deletes a IoT device(s).
        
		Args:
			categories (list): Specifies the list of categories values.
			string (list): Specifies the list of categories values.
			devices (list): Specifies the list of device names.
			string (list): Specifies the list of device names.
			devicesIds (list): Specifies the list of device ids.
			integer (list): Specifies the list of device ids.
			firstSeenEnd (str): Retrieves IoT devices that were first seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss.
			firstSeenStart (str): Retrieves IoT devices that were first seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss.
			internalIps (list): Specifies the list of IP values.
			string (list): Specifies the list of IP values.
			iotGroups (list): Specifies the list of collector group names and retrieves collectors under the given groups.
			string (list): Specifies the list of collector group names and retrieves collectors under the given groups.
			iotGroupsIds (list): Specifies the list of collector group ids and retrieves collectors under the given groups.
			integer (list): Specifies the list of collector group ids and retrieves collectors under the given groups.
			itemsPerPage (int): An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000.
			lastSeenEnd (str): Retrieves IoT devices that were last seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss.
			lastSeenStart (str): Retrieves IoT devices that were last seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss.
			locations (list): Specifies the list of locations values.
			string (list): Specifies the list of locations values.
			macAddresses (list): Specifies the list of mac address values.
			string (list): Specifies the list of mac address values.
			models (list): Specifies the list of models values.
			string (list): Specifies the list of models values.
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
.
			pageNumber (int): An integer used for paging that indicates the required page number.
			showExpired (bool): Specifies whether to include IoT devices which have been disconnected for more than 3 days (sequentially) and are marked as Expired.
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on.
			strictMode (bool): A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False.
			vendors (list): Specifies the list of vendors values.
			string (list): Specifies the list of vendors values.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_devices", locals())

		url = '/management-rest/iot/delete-devices'
		url_params = []
		if categories:
			url_params.append('categories=' + ",".join(str(categories)))
		if devices:
			url_params.append('devices=' + ",".join(str(devices)))
		if devicesIds:
			url_params.append('devicesIds=' + ",".join(map(str, devicesIds)))
		if firstSeenEnd:
			url_params.append('firstSeenEnd=' + firstSeenEnd)
		if firstSeenStart:
			url_params.append('firstSeenStart=' + firstSeenStart)
		if internalIps:
			url_params.append('internalIps=' + ",".join(str(internalIps)))
		if iotGroups:
			url_params.append('iotGroups=' + ",".join(str(iotGroups)))
		if iotGroupsIds:
			url_params.append('iotGroupsIds=' + ",".join(map(str, iotGroupsIds)))
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if lastSeenEnd:
			url_params.append('lastSeenEnd=' + lastSeenEnd)
		if lastSeenStart:
			url_params.append('lastSeenStart=' + lastSeenStart)
		if locations:
			url_params.append('locations=' + ",".join(str(locations)))
		if macAddresses:
			url_params.append('macAddresses=' + ",".join(str(macAddresses)))
		if models:
			url_params.append('models=' + ",".join(str(models)))
		if organization:
			url_params.append('organization=' + organization)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if showExpired:
			url_params.append('showExpired=' + showExpired)
		if sorting:
			url_params.append('sorting=' + sorting)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		if vendors:
			url_params.append('vendors=' + ",".join(str(vendors)))
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def export_iot_json(self, iotDeviceIds: list, organization: str = None) -> tuple[bool, None]:
		'''
		Class IoT
		Description: This API call outputs a list of the IoT devices info.
        
		Args:
			iotDeviceIds (list): Specifies the list of device ids.
			integer (list): Specifies the list of device ids.
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations..

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("export_iot_json", locals())

		url = '/management-rest/iot/export-iot-json'
		url_params = []
		if iotDeviceIds:
			url_params.append('iotDeviceIds=' + ",".join(map(str, iotDeviceIds)))
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def list_iot_devices(self, categories: list = None, devices: list = None, devicesIds: list = None, firstSeenEnd: str = None, firstSeenStart: str = None, internalIps: list = None, iotGroups: list = None, iotGroupsIds: list = None, itemsPerPage: int = None, lastSeenEnd: str = None, lastSeenStart: str = None, locations: list = None, macAddresses: list = None, models: list = None, organization: str = None, pageNumber: int = None, showExpired: bool = None, sorting: str = None, strictMode: bool = None, vendors: list = None) -> tuple[bool, list]:
		'''
		Class IoT
		Description: This API call outputs a list of the IoT devices in the system. Use the input parameters to filter the list.
        
		Args:
			categories (list): Specifies the list of categories values.
			string (list): Specifies the list of categories values.
			devices (list): Specifies the list of device names.
			string (list): Specifies the list of device names.
			devicesIds (list): Specifies the list of device ids.
			integer (list): Specifies the list of device ids.
			firstSeenEnd (str): Retrieves IoT devices that were first seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss.
			firstSeenStart (str): Retrieves IoT devices that were first seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss.
			internalIps (list): Specifies the list of IP values.
			string (list): Specifies the list of IP values.
			iotGroups (list): Specifies the list of collector group names and retrieves collectors under the given groups.
			string (list): Specifies the list of collector group names and retrieves collectors under the given groups.
			iotGroupsIds (list): Specifies the list of collector group ids and retrieves collectors under the given groups.
			integer (list): Specifies the list of collector group ids and retrieves collectors under the given groups.
			itemsPerPage (int): An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000.
			lastSeenEnd (str): Retrieves IoT devices that were last seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss.
			lastSeenStart (str): Retrieves IoT devices that were last seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss.
			locations (list): Specifies the list of locations values.
			string (list): Specifies the list of locations values.
			macAddresses (list): Specifies the list of mac address values.
			string (list): Specifies the list of mac address values.
			models (list): Specifies the list of models values.
			string (list): Specifies the list of models values.
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
.
			pageNumber (int): An integer used for paging that indicates the required page number.
			showExpired (bool): Specifies whether to include IoT devices which have been disconnected for more than 3 days (sequentially) and are marked as Expired.
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on.
			strictMode (bool): A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False.
			vendors (list): Specifies the list of vendors values.
			string (list): Specifies the list of vendors values.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_iot_devices", locals())

		url = '/management-rest/iot/list-iot-devices'
		url_params = []
		if categories:
			url_params.append('categories=' + ",".join(str(categories)))
		if devices:
			url_params.append('devices=' + ",".join(str(devices)))
		if devicesIds:
			url_params.append('devicesIds=' + ",".join(map(str, devicesIds)))
		if firstSeenEnd:
			url_params.append('firstSeenEnd=' + firstSeenEnd)
		if firstSeenStart:
			url_params.append('firstSeenStart=' + firstSeenStart)
		if internalIps:
			url_params.append('internalIps=' + ",".join(str(internalIps)))
		if iotGroups:
			url_params.append('iotGroups=' + ",".join(str(iotGroups)))
		if iotGroupsIds:
			url_params.append('iotGroupsIds=' + ",".join(map(str, iotGroupsIds)))
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if lastSeenEnd:
			url_params.append('lastSeenEnd=' + lastSeenEnd)
		if lastSeenStart:
			url_params.append('lastSeenStart=' + lastSeenStart)
		if locations:
			url_params.append('locations=' + ",".join(str(locations)))
		if macAddresses:
			url_params.append('macAddresses=' + ",".join(str(macAddresses)))
		if models:
			url_params.append('models=' + ",".join(str(models)))
		if organization:
			url_params.append('organization=' + organization)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if showExpired:
			url_params.append('showExpired=' + showExpired)
		if sorting:
			url_params.append('sorting=' + sorting)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		if vendors:
			url_params.append('vendors=' + ",".join(str(vendors)))
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def list_iot_groups(self, organization: str = None) -> tuple[bool, list]:
		'''
		Class IoT
		Description: This API call output the IoT devices groups.
        
		Args:
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations..

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_iot_groups", locals())

		url = '/management-rest/iot/list-iot-groups'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def move_iot_devices(self, iotDeviceIds: list, targetIotGroup: str, organization: str = None) -> tuple[bool, None]:
		'''
		Class IoT
		Description: This API call move IoT devices between groups.
        
		Args:
			iotDeviceIds (list): Array of IoT device ids.
			integer (list): Array of IoT device ids.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.
			targetIotGroup (str): IoT target group name.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("move_iot_devices", locals())

		url = '/management-rest/iot/move-iot-devices'
		url_params = []
		if iotDeviceIds:
			url_params.append('iotDeviceIds=' + ",".join(map(str, iotDeviceIds)))
		if organization:
			url_params.append('organization=' + organization)
		if targetIotGroup:
			url_params.append('targetIotGroup=' + targetIotGroup)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def rescan_iot_device_details(self, categories: list = None, devices: list = None, devicesIds: list = None, firstSeenEnd: str = None, firstSeenStart: str = None, internalIps: list = None, iotGroups: list = None, iotGroupsIds: list = None, itemsPerPage: int = None, lastSeenEnd: str = None, lastSeenStart: str = None, locations: list = None, macAddresses: list = None, models: list = None, organization: str = None, pageNumber: int = None, showExpired: bool = None, sorting: str = None, strictMode: bool = None, vendors: list = None) -> tuple[bool, str]:
		'''
		Class IoT
		Description: This API call device details scan on IoT device(s).
        
		Args:
			categories (list): Specifies the list of categories values.
			string (list): Specifies the list of categories values.
			devices (list): Specifies the list of device names.
			string (list): Specifies the list of device names.
			devicesIds (list): Specifies the list of device ids.
			integer (list): Specifies the list of device ids.
			firstSeenEnd (str): Retrieves IoT devices that were first seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss.
			firstSeenStart (str): Retrieves IoT devices that were first seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss.
			internalIps (list): Specifies the list of IP values.
			string (list): Specifies the list of IP values.
			iotGroups (list): Specifies the list of collector group names and retrieves collectors under the given groups.
			string (list): Specifies the list of collector group names and retrieves collectors under the given groups.
			iotGroupsIds (list): Specifies the list of collector group ids and retrieves collectors under the given groups.
			integer (list): Specifies the list of collector group ids and retrieves collectors under the given groups.
			itemsPerPage (int): An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000.
			lastSeenEnd (str): Retrieves IoT devices that were last seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss.
			lastSeenStart (str): Retrieves IoT devices that were last seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss.
			locations (list): Specifies the list of locations values.
			string (list): Specifies the list of locations values.
			macAddresses (list): Specifies the list of mac address values.
			string (list): Specifies the list of mac address values.
			models (list): Specifies the list of models values.
			string (list): Specifies the list of models values.
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
.
			pageNumber (int): An integer used for paging that indicates the required page number.
			showExpired (bool): Specifies whether to include IoT devices which have been disconnected for more than 3 days (sequentially) and are marked as Expired.
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on.
			strictMode (bool): A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False.
			vendors (list): Specifies the list of vendors values.
			string (list): Specifies the list of vendors values.

		Returns:
			bool: Status of the request (True or False). 
			str
		'''
		validate_params("rescan_iot_device_details", locals())

		url = '/management-rest/iot/rescan-iot-device-details'
		url_params = []
		if categories:
			url_params.append('categories=' + ",".join(str(categories)))
		if devices:
			url_params.append('devices=' + ",".join(str(devices)))
		if devicesIds:
			url_params.append('devicesIds=' + ",".join(map(str, devicesIds)))
		if firstSeenEnd:
			url_params.append('firstSeenEnd=' + firstSeenEnd)
		if firstSeenStart:
			url_params.append('firstSeenStart=' + firstSeenStart)
		if internalIps:
			url_params.append('internalIps=' + ",".join(str(internalIps)))
		if iotGroups:
			url_params.append('iotGroups=' + ",".join(str(iotGroups)))
		if iotGroupsIds:
			url_params.append('iotGroupsIds=' + ",".join(map(str, iotGroupsIds)))
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if lastSeenEnd:
			url_params.append('lastSeenEnd=' + lastSeenEnd)
		if lastSeenStart:
			url_params.append('lastSeenStart=' + lastSeenStart)
		if locations:
			url_params.append('locations=' + ",".join(str(locations)))
		if macAddresses:
			url_params.append('macAddresses=' + ",".join(str(macAddresses)))
		if models:
			url_params.append('models=' + ",".join(str(models)))
		if organization:
			url_params.append('organization=' + organization)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if showExpired:
			url_params.append('showExpired=' + showExpired)
		if sorting:
			url_params.append('sorting=' + sorting)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		if vendors:
			url_params.append('vendors=' + ",".join(str(vendors)))
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

class IPsets:
	'''API to define IPs sets and use them for exceptions'''

	def create_ip_set(self, description: str = None, exclude: list = None, include: list = None, name: str = None, organization: str = None) -> tuple[bool, None]:
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
		if description: ipGroupsRequest["description"] = description
		if exclude: ipGroupsRequest["exclude"] = exclude
		if include: ipGroupsRequest["include"] = include
		if name: ipGroupsRequest["name"] = name
		if organization: ipGroupsRequest["organization"] = organization

		return fortiedr_connection.send(url, ipGroupsRequest)

	def delete_ip_set(self, ipSets: list, organization: str = None) -> tuple[bool, None]:
		'''
		Class IPsets
		Description: This API delete IP sets from the system. Use the input parameters to filter organization.
        
		Args:
			ipSets (list): Specifies the list of IP name to delete.
			string (list): Specifies the list of IP name to delete.
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations..

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_ip_set", locals())

		url = '/management-rest/ip-sets/delete-ip-set'
		url_params = []
		if ipSets:
			url_params.append('ipSets=' + ",".join(str(ipSets)))
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def list_ip_sets(self, ip: str = None, organization: str = None) -> tuple[bool, list]:
		'''
		Class IPsets
		Description: This API call outputs a list of the IP sets in the system. Use the input parameters to filter the list.
        
		Args:
			ip (str): Specifies the IP of the requested sets.
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations..

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_ip_sets", locals())

		url = '/management-rest/ip-sets/list-ip-sets'
		url_params = []
		if ip:
			url_params.append('ip=' + ip)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def update_ip_set(self, description: str = None, exclude: list = None, include: list = None, name: str = None, organization: str = None) -> tuple[bool, None]:
		'''
		Class IPsets
		Description: This API update IP sets in the system. Use the input parameters to filter organization.
        
		Args:
			ipGroupsRequest (Object): Check 'ipGroupsRequest' in the API documentation for further information.
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non-shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
���	each ��� Indicates that the operation applies independently to each organization. For example, let's assume that the same user exists in multiple organizations. When each is specified in the organization parameter, then each organization can update this user separately..

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("update_ip_set", locals())

		url = '/management-rest/ip-sets/update-ip-set'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)

		ipGroupsRequest = {}
		if description: ipGroupsRequest["description"] = description
		if exclude: ipGroupsRequest["exclude"] = exclude
		if include: ipGroupsRequest["include"] = include
		if name: ipGroupsRequest["name"] = name

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
		if eXtendedDetection: createAccountRequest["eXtendedDetection"] = eXtendedDetection
		if edr: createAccountRequest["edr"] = edr
		if edrAddOnsAllocated: createAccountRequest["edrAddOnsAllocated"] = str(edrAddOnsAllocated)
		if edrBackupEnabled: createAccountRequest["edrBackupEnabled"] = edrBackupEnabled
		if edrEnabled: createAccountRequest["edrEnabled"] = edrEnabled
		if edrNumberOfShards: createAccountRequest["edrNumberOfShards"] = str(edrNumberOfShards)
		if edrStorageAllocatedInMb: createAccountRequest["edrStorageAllocatedInMb"] = str(edrStorageAllocatedInMb)
		if expirationDate: createAccountRequest["expirationDate"] = expirationDate
		if forensics: createAccountRequest["forensics"] = forensics
		if iotAllocated: createAccountRequest["iotAllocated"] = str(iotAllocated)
		if name: createAccountRequest["name"] = name
		if password: createAccountRequest["password"] = password
		if passwordConfirmation: createAccountRequest["passwordConfirmation"] = passwordConfirmation
		if requestPolicyEngineLibUpdates: createAccountRequest["requestPolicyEngineLibUpdates"] = requestPolicyEngineLibUpdates
		if serialNumber: createAccountRequest["serialNumber"] = serialNumber
		if serversAllocated: createAccountRequest["serversAllocated"] = str(serversAllocated)
		if vulnerabilityAndIoT: createAccountRequest["vulnerabilityAndIoT"] = vulnerabilityAndIoT
		if workstationsAllocated: createAccountRequest["workstationsAllocated"] = str(workstationsAllocated)

		return fortiedr_connection.send(url, createAccountRequest)

	def delete_organization(self, organization: str = None) -> tuple[bool, None]:
		'''
		Class Organizations
		Description: This API delete organization in the system (only for Admin role).
        
		Args:
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_organization", locals())

		url = '/management-rest/organizations/delete-organization'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def export_organization(self, destinationName: str = None, organization: str = None) -> tuple[bool, None]:
		'''
		Class Organizations
		Description: Export organization data as zip file.
        
		Args:
			destinationName (str): The organization destination name.
			organization (str): Organization to export.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("export_organization", locals())

		url = '/management-rest/organizations/export-organization'
		url_params = []
		if destinationName:
			url_params.append('destinationName=' + destinationName)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def import_organization(self, file: BinaryIO = None) -> tuple[bool, None]:
		'''
		Class Organizations
		Description: Import organization.
        
		Args:
			file (BinaryIO): Export zip file.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("import_organization", locals())

		url = '/management-rest/organizations/import-organization'
		if file:
			file = {'file': file}


		return fortiedr_connection.upload(url, file)

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

	def transfer_collectors(self, aggregatorsMap: list = None, sourceOrganization: str = None, targetOrganization: str = None, verificationCode: str = None) -> tuple[bool, None]:
		'''
		Class Organizations
		Description: Transfer collectors from aggregator to aggregator as the organization migration process.
        
		Args:
			transferCollectorRequests (Object): Check 'transferCollectorRequests' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("transfer_collectors", locals())

		url = '/management-rest/organizations/transfer-collectors'

		transferCollectorRequests = {}
		if aggregatorsMap: transferCollectorRequests["aggregatorsMap"] = aggregatorsMap
		if sourceOrganization: transferCollectorRequests["sourceOrganization"] = sourceOrganization
		if targetOrganization: transferCollectorRequests["targetOrganization"] = targetOrganization
		if verificationCode: transferCollectorRequests["verificationCode"] = verificationCode

		return fortiedr_connection.send(url, transferCollectorRequests)

	def transfer_collectors_stop(self, organization: str = None) -> tuple[bool, None]:
		'''
		Class Organizations
		Description: Transfer collector stop.
        
		Args:
			organization (str): Specifies the organization which the migration process should stop.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("transfer_collectors_stop", locals())

		url = '/management-rest/organizations/transfer-collectors-stop'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.send(url)

	def update_organization(self, eXtendedDetection: bool = None, edr: bool = None, edrAddOnsAllocated: int = None, edrBackupEnabled: bool = None, edrEnabled: bool = None, edrNumberOfShards: int = None, edrStorageAllocatedInMb: int = None, expirationDate: str = None, forensics: bool = None, iotAllocated: int = None, name: str = None, requestPolicyEngineLibUpdates: bool = None, serialNumber: str = None, serversAllocated: int = None, vulnerabilityAndIoT: bool = None, workstationsAllocated: int = None, organization: str = None) -> tuple[bool, None]:
		'''
		Class Organizations
		Description: This API update organization in the system (only for Admin role).
        
		Args:
			accountRequest (Object): Check 'accountRequest' in the API documentation for further information.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("update_organization", locals())

		url = '/management-rest/organizations/update-organization'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)

		accountRequest = {}
		if eXtendedDetection: accountRequest["eXtendedDetection"] = eXtendedDetection
		if edr: accountRequest["edr"] = edr
		if edrAddOnsAllocated: accountRequest["edrAddOnsAllocated"] = str(edrAddOnsAllocated)
		if edrBackupEnabled: accountRequest["edrBackupEnabled"] = edrBackupEnabled
		if edrEnabled: accountRequest["edrEnabled"] = edrEnabled
		if edrNumberOfShards: accountRequest["edrNumberOfShards"] = str(edrNumberOfShards)
		if edrStorageAllocatedInMb: accountRequest["edrStorageAllocatedInMb"] = str(edrStorageAllocatedInMb)
		if expirationDate: accountRequest["expirationDate"] = expirationDate
		if forensics: accountRequest["forensics"] = forensics
		if iotAllocated: accountRequest["iotAllocated"] = str(iotAllocated)
		if name: accountRequest["name"] = name
		if requestPolicyEngineLibUpdates: accountRequest["requestPolicyEngineLibUpdates"] = requestPolicyEngineLibUpdates
		if serialNumber: accountRequest["serialNumber"] = serialNumber
		if serversAllocated: accountRequest["serversAllocated"] = str(serversAllocated)
		if vulnerabilityAndIoT: accountRequest["vulnerabilityAndIoT"] = vulnerabilityAndIoT
		if workstationsAllocated: accountRequest["workstationsAllocated"] = str(workstationsAllocated)

		return fortiedr_connection.insert(url, accountRequest)

class Playbookspolicies:
	'''Playbooks-policies API'''

	def assign_collector_group(self, collectorGroupNames: list, policyName: str, forceAssign: bool = None, organization: str = None) -> tuple[bool, None]:
		'''
		Class Playbookspolicies
		Description: Assign collector group to air policy.
        
		Args:
			collectorGroupNames (list): Specifies the list of collector group names.
			string (list): Specifies the list of collector group names.
			forceAssign (bool): Indicates whether to force the assignment even if the group is assigned to similar policies.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.
			policyName (str): Specifies policy name.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("assign_collector_group", locals())

		url = '/management-rest/playbooks-policies/assign-collector-group'
		url_params = []
		if collectorGroupNames:
			url_params.append('collectorGroupNames=' + ",".join(str(collectorGroupNames)))
		if forceAssign:
			url_params.append('forceAssign=' + forceAssign)
		if organization:
			url_params.append('organization=' + organization)
		if policyName:
			url_params.append('policyName=' + policyName)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def clone(self, newPolicyName: str, sourcePolicyName: str, organization: str = None) -> tuple[bool, None]:
		'''
		Class Playbookspolicies
		Description: clone policy.
        
		Args:
			newPolicyName (str): Specifies security policy target name..
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.
			sourcePolicyName (str): Specifies security policy source name.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("clone", locals())

		url = '/management-rest/playbooks-policies/clone'
		url_params = []
		if newPolicyName:
			url_params.append('newPolicyName=' + newPolicyName)
		if organization:
			url_params.append('organization=' + organization)
		if sourcePolicyName:
			url_params.append('sourcePolicyName=' + sourcePolicyName)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.send(url)

	def list_policies(self, organization: str = None) -> tuple[bool, list]:
		'''
		Class Playbookspolicies
		Description: List policies.
        
		Args:
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations..

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_policies", locals())

		url = '/management-rest/playbooks-policies/list-policies'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def map_connectors_to_actions(self, customActionsToConnectorsMaps: list = None, fortinetActionsToConnectorsMaps: list = None, policyName: str = None, organization: str = None) -> tuple[bool, None]:
		'''
		Class Playbookspolicies
		Description: Assign policy actions with connectors..
        
		Args:
			assignAIRActionsWithConnectorsRequest (Object): Check 'assignAIRActionsWithConnectorsRequest' in the API documentation for further information.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("map_connectors_to_actions", locals())

		url = '/management-rest/playbooks-policies/map-connectors-to-actions'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)

		assignAIRActionsWithConnectorsRequest = {}
		if customActionsToConnectorsMaps: assignAIRActionsWithConnectorsRequest["customActionsToConnectorsMaps"] = customActionsToConnectorsMaps
		if fortinetActionsToConnectorsMaps: assignAIRActionsWithConnectorsRequest["fortinetActionsToConnectorsMaps"] = fortinetActionsToConnectorsMaps
		if policyName: assignAIRActionsWithConnectorsRequest["policyName"] = policyName

		return fortiedr_connection.insert(url, assignAIRActionsWithConnectorsRequest)

	def set_action_classification(self, organization: str = None, customActionsToClassificationMaps: list = None, fortinetActionsToClassificationMaps: list = None, policyName: str = None) -> tuple[bool, None]:
		'''
		Class Playbookspolicies
		Description: Set the air policy actions' classifications..
        
		Args:
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.
			setActionsClassificationRequest (Object): Check 'setActionsClassificationRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("set_action_classification", locals())

		url = '/management-rest/playbooks-policies/set-action-classification'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)

		setActionsClassificationRequest = {}
		if customActionsToClassificationMaps: setActionsClassificationRequest["customActionsToClassificationMaps"] = customActionsToClassificationMaps
		if fortinetActionsToClassificationMaps: setActionsClassificationRequest["fortinetActionsToClassificationMaps"] = fortinetActionsToClassificationMaps
		if policyName: setActionsClassificationRequest["policyName"] = policyName

		return fortiedr_connection.insert(url, setActionsClassificationRequest)

	def set_mode(self, mode: str, policyName: str, organization: str = None) -> tuple[bool, None]:
		'''
		Class Playbookspolicies
		Description: Set playbook to simulation/prevention.
        
		Args:
			mode (str): Operation mode.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.
			policyName (str): Specifies security policy name.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("set_mode", locals())

		url = '/management-rest/playbooks-policies/set-mode'
		url_params = []
		if mode:
			url_params.append('mode=' + mode)
		if organization:
			url_params.append('organization=' + organization)
		if policyName:
			url_params.append('policyName=' + policyName)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

class Policies:
	'''Policies API'''

	def assign_collector_group(self, collectorsGroupName: list, policyName: str, forceAssign: bool = None, organization: str = None) -> tuple[bool, None]:
		'''
		Class Policies
		Description: Assign collector group to policy.
        
		Args:
			collectorsGroupName (list): Specifies the list of collector group names.
			string (list): Specifies the list of collector group names.
			forceAssign (bool): Indicates whether to force the assignment even if the group is assigned to similar policies.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.
			policyName (str): Specifies security policy name.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("assign_collector_group", locals())

		url = '/management-rest/policies/assign-collector-group'
		url_params = []
		if collectorsGroupName:
			url_params.append('collectorsGroupName=' + ",".join(str(collectorsGroupName)))
		if forceAssign:
			url_params.append('forceAssign=' + forceAssign)
		if organization:
			url_params.append('organization=' + organization)
		if policyName:
			url_params.append('policyName=' + policyName)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def clone(self, newPolicyName: str, sourcePolicyName: str, organization: str = None) -> tuple[bool, None]:
		'''
		Class Policies
		Description: clone policy.
        
		Args:
			newPolicyName (str): Specifies security policy target name..
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.
			sourcePolicyName (str): Specifies security policy source name.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("clone", locals())

		url = '/management-rest/policies/clone'
		url_params = []
		if newPolicyName:
			url_params.append('newPolicyName=' + newPolicyName)
		if organization:
			url_params.append('organization=' + organization)
		if sourcePolicyName:
			url_params.append('sourcePolicyName=' + sourcePolicyName)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.send(url)

	def list_policies(self, organization: str = None) -> tuple[bool, list]:
		'''
		Class Policies
		Description: List policies.
        
		Args:
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations..

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_policies", locals())

		url = '/management-rest/policies/list-policies'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def scan_files(self, applyRecursiveScan: bool, executableFilesOnly: bool, origin: str, scanBy: str, filePaths: list = None, organization: str = None, scanSelection: list = None) -> tuple[bool, None]:
		'''
		Class Policies
		Description: Scan Files.
        
		Args:
			applyRecursiveScan (bool): Specifies if execution includes recursive scan.
			executableFilesOnly (bool): Specifies if execution includes only files.
			filePaths (list): Specifies file path.
			string (list): Specifies file path.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.
			origin (str): Specifies scan origin.
			scanBy (str): Specifies scan by choice.
			scanSelection (list): Specifies scan selection.
			string (list): Specifies scan selection.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("scan_files", locals())

		url = '/management-rest/policies/scan-files'
		url_params = []
		if applyRecursiveScan:
			url_params.append('applyRecursiveScan=' + applyRecursiveScan)
		if executableFilesOnly:
			url_params.append('executableFilesOnly=' + executableFilesOnly)
		if filePaths:
			url_params.append('filePaths=' + ",".join(str(filePaths)))
		if organization:
			url_params.append('organization=' + organization)
		if origin:
			url_params.append('origin=' + origin)
		if scanBy:
			url_params.append('scanBy=' + scanBy)
		if scanSelection:
			url_params.append('scanSelection=' + ",".join(str(scanSelection)))
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.send(url)

	def set_mode(self, mode: str, policyName: str, organization: str = None) -> tuple[bool, None]:
		'''
		Class Policies
		Description: Set policy to simulation/prevention.
        
		Args:
			mode (str): Operation mode.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.
			policyName (str): Specifies security policy name.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("set_mode", locals())

		url = '/management-rest/policies/set-mode'
		url_params = []
		if mode:
			url_params.append('mode=' + mode)
		if organization:
			url_params.append('organization=' + organization)
		if policyName:
			url_params.append('policyName=' + policyName)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def set_policy_rule_action(self, action: str, policyName: str, ruleName: str, organization: str = None) -> tuple[bool, None]:
		'''
		Class Policies
		Description: Set rule in policy to block/log.
        
		Args:
			action (str): Specifies the policy action.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.
			policyName (str): Specifies security policy name.
			ruleName (str): Specifies rule name.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("set_policy_rule_action", locals())

		url = '/management-rest/policies/set-policy-rule-action'
		url_params = []
		if action:
			url_params.append('action=' + action)
		if organization:
			url_params.append('organization=' + organization)
		if policyName:
			url_params.append('policyName=' + policyName)
		if ruleName:
			url_params.append('ruleName=' + ruleName)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def set_policy_rule_state(self, policyName: str, ruleName: str, state: str, organization: str = None) -> tuple[bool, None]:
		'''
		Class Policies
		Description: Set rule in policy to enable/disable.
        
		Args:
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.
			policyName (str): Specifies security policy name.
			ruleName (str): Specifies rule name.
			state (str): Policy rule state.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("set_policy_rule_state", locals())

		url = '/management-rest/policies/set-policy-rule-state'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		if policyName:
			url_params.append('policyName=' + policyName)
		if ruleName:
			url_params.append('ruleName=' + ruleName)
		if state:
			url_params.append('state=' + state)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

class SendableEntities:
	'''API to create and test sendable entities'''

	def set_mail_format(self, format: str, organization: str = None) -> tuple[bool, None]:
		'''
		Class SendableEntities
		Description: set mail format.
        
		Args:
			format (str): Specifies email format type.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("set_mail_format", locals())

		url = '/management-rest/sendable-entities/set-mail-format'
		url_params = []
		if format:
			url_params.append('format=' + format)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

	def syslog(self, organization: str = None, certificateBlob: str = None, host: str = None, name: str = None, port: int = None, privateKeyFile: str = None, privateKeyPassword: str = None, protocol: str = None, syslogFormat: str = None, useClientCertificate: bool = None, useSSL: bool = None) -> tuple[bool, None]:
		'''
		Class SendableEntities
		Description: This API creates syslog.
        
		Args:
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non-shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	each ��� Indicates that the operation applies independently to each organization. For example, let's assume that the same user exists in multiple organizations. When each is specified in the organization parameter, then each organization can update this user separately..
			syslogRequest (Object): Check 'syslogRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("syslog", locals())

		url = '/management-rest/sendable-entities/syslog'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)

		syslogRequest = {}
		if certificateBlob: syslogRequest["certificateBlob"] = certificateBlob
		if host: syslogRequest["host"] = host
		if name: syslogRequest["name"] = name
		if port: syslogRequest["port"] = str(port)
		if privateKeyFile: syslogRequest["privateKeyFile"] = privateKeyFile
		if privateKeyPassword: syslogRequest["privateKeyPassword"] = privateKeyPassword
		if protocol: syslogRequest["protocol"] = protocol
		if syslogFormat: syslogRequest["syslogFormat"] = syslogFormat
		if useClientCertificate: syslogRequest["useClientCertificate"] = useClientCertificate
		if useSSL: syslogRequest["useSSL"] = useSSL

		return fortiedr_connection.send(url, syslogRequest)

class SystemEvents:
	'''System Events API'''

	def list_system_events(self, componentNames: list = None, componentTypes: list = None, fromDate: str = None, itemsPerPage: int = None, organization: str = None, pageNumber: int = None, sorting: str = None, strictMode: bool = None, toDate: str = None) -> tuple[bool, list]:
		'''
		Class SystemEvents
		Description: Retrieve system events.
        
		Args:
			componentNames (list):  Specifies one or more names. The name is the customer name for license-related system events and the device name for all others events.
			string (list):  Specifies one or more names. The name is the customer name for license-related system events and the device name for all others events.
			componentTypes (list): Specifies one or more component type.
			string (list): Specifies one or more component type.
			fromDate (str): Searches for system events that occurred after this date.
			itemsPerPage (int): An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000.
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations..
			pageNumber (int): An integer used for paging that indicates the required page number.
			sorting (str): Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on.
			strictMode (bool): A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False.
			toDate (str): Searches for system events that occurred before this date.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_system_events", locals())

		url = '/management-rest/system-events/list-system-events'
		url_params = []
		if componentNames:
			url_params.append('componentNames=' + ",".join(str(componentNames)))
		if componentTypes:
			url_params.append('componentTypes=' + ",".join(str(componentTypes)))
		if fromDate:
			url_params.append('fromDate=' + fromDate)
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if organization:
			url_params.append('organization=' + organization)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if sorting:
			url_params.append('sorting=' + sorting)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		if toDate:
			url_params.append('toDate=' + toDate)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

class ThreatHuntingExclusions:
	'''API to create Threat Hunting exclusions.'''

	def send_exclusion(self, exclusionListName: str = None, exclusions: list = None, organization: str = None) -> tuple[bool, list]:
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
		if exclusionListName: createExclusionsRequest["exclusionListName"] = exclusionListName
		if exclusions: createExclusionsRequest["exclusions"] = exclusions
		if organization: createExclusionsRequest["organization"] = organization

		return fortiedr_connection.send(url, createExclusionsRequest)

	def insert_exclusions(self, exclusionListName: str = None, exclusions: list = None, organization: str = None) -> tuple[bool, list]:
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
		if exclusionListName: updateExclusionsRequest["exclusionListName"] = exclusionListName
		if exclusions: updateExclusionsRequest["exclusions"] = exclusions
		if organization: updateExclusionsRequest["organization"] = organization

		return fortiedr_connection.insert(url, updateExclusionsRequest)

	def delete_exclusion(self, exclusionIds: list = None, organization: str = None) -> tuple[bool, str]:
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
		if exclusionIds: deleteExclusionsRequest["exclusionIds"] = exclusionIds
		if organization: deleteExclusionsRequest["organization"] = organization

		return fortiedr_connection.delete(url, deleteExclusionsRequest)

	def get_exclusions_list(self, organization: str, ) -> tuple[bool, list]:
		'''
		Class ThreatHuntingExclusions
		Description: Get the list of Exclusions lists..
        
		Args:
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("get_exclusions_list", locals())

		url = '/management-rest/threat-hunting-exclusions/exclusions-list'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def send_exclusions_list(self, collectorGroupIds: list = None, name: str = None, organization: str = None) -> tuple[bool, None]:
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
		if collectorGroupIds: createExclusionListRequest["collectorGroupIds"] = collectorGroupIds
		if name: createExclusionListRequest["name"] = name
		if organization: createExclusionListRequest["organization"] = organization

		return fortiedr_connection.send(url, createExclusionListRequest)

	def insert_exclusions_list(self, collectorGroupIds: list = None, listName: str = None, newName: str = None, organization: str = None) -> tuple[bool, None]:
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
		if collectorGroupIds: updateExclusionListRequest["collectorGroupIds"] = collectorGroupIds
		if listName: updateExclusionListRequest["listName"] = listName
		if newName: updateExclusionListRequest["newName"] = newName
		if organization: updateExclusionListRequest["organization"] = organization

		return fortiedr_connection.insert(url, updateExclusionListRequest)

	def delete_exclusions_list(self, listName: str, organization: str, ) -> tuple[bool, None]:
		'''
		Class ThreatHuntingExclusions
		Description: Deletes an exclusions list..
        
		Args:
			listName (str): Exclusions list name..
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_exclusions_list", locals())

		url = '/management-rest/threat-hunting-exclusions/exclusions-list'
		url_params = []
		if listName:
			url_params.append('listName=' + listName)
		if organization:
			url_params.append('organization=' + organization)
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

	def exclusions_search(self, searchText: str, organization: str = None, os: list = None) -> tuple[bool, list]:
		'''
		Class ThreatHuntingExclusions
		Description: Free-text search of exclusions.
        
		Args:
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.
			os (list): OS identifiers list..
			string (list): OS identifiers list..
			searchText (str): The free text search string. The API will return every exclusion list that contains this string, or contains an exclusion with any field that contains it..

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("exclusions_search", locals())

		url = '/management-rest/threat-hunting-exclusions/exclusions-search'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		if os:
			url_params.append('os=' + ",".join(str(os)))
		if searchText:
			url_params.append('searchText=' + searchText)
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

	def get_threat_hunting_profile(self, organization: str, ) -> tuple[bool, list]:
		'''
		Class ThreatHuntingSettings
		Description: Get the list of Threat Hunting Setting profiles..
        
		Args:
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("get_threat_hunting_profile", locals())

		url = '/management-rest/threat-hunting-settings/threat-hunting-profile'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def send_threat_hunting_profile(self, associatedCollectorGroupIds: list = None, name: str = None, newName: str = None, organization: str = None, threatHuntingCategoryList: list = None) -> tuple[bool, None]:
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
		if associatedCollectorGroupIds: threatHuntingUpdateRequest["associatedCollectorGroupIds"] = associatedCollectorGroupIds
		if name: threatHuntingUpdateRequest["name"] = name
		if newName: threatHuntingUpdateRequest["newName"] = newName
		if organization: threatHuntingUpdateRequest["organization"] = organization
		if threatHuntingCategoryList: threatHuntingUpdateRequest["threatHuntingCategoryList"] = threatHuntingCategoryList

		return fortiedr_connection.send(url, threatHuntingUpdateRequest)

	def delete_threat_hunting_profile(self, name: str, organization: str, ) -> tuple[bool, None]:
		'''
		Class ThreatHuntingSettings
		Description: Deletes a Threat Hunting profile..
        
		Args:
			name (str): To be deleted profile's name..
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_threat_hunting_profile", locals())

		url = '/management-rest/threat-hunting-settings/threat-hunting-profile'
		url_params = []
		if name:
			url_params.append('name=' + name)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def threat_hunting_profile_clone(self, cloneProfileName: str, existingProfileName: str, organization: str, ) -> tuple[bool, None]:
		'''
		Class ThreatHuntingSettings
		Description: Clone a Threat Hunting Settings profile..
        
		Args:
			cloneProfileName (str): Cloned profile name..
			existingProfileName (str): Existing profile name..
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("threat_hunting_profile_clone", locals())

		url = '/management-rest/threat-hunting-settings/threat-hunting-profile-clone'
		url_params = []
		if cloneProfileName:
			url_params.append('cloneProfileName=' + cloneProfileName)
		if existingProfileName:
			url_params.append('existingProfileName=' + existingProfileName)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.send(url)

	def threat_hunting_profile_assign_collector_groups(self, associatedCollectorGroupIds: list = None, name: str = None, organization: str = None) -> tuple[bool, list]:
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
		if associatedCollectorGroupIds: threatHuntingAssignGroupsRequest["associatedCollectorGroupIds"] = associatedCollectorGroupIds
		if name: threatHuntingAssignGroupsRequest["name"] = name
		if organization: threatHuntingAssignGroupsRequest["organization"] = organization

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
		if accountId: edrRequest["accountId"] = str(accountId)
		if category: edrRequest["category"] = category
		if devices: edrRequest["devices"] = devices
		if filters: edrRequest["filters"] = filters
		if fromTime: edrRequest["fromTime"] = fromTime
		if itemsPerPage: edrRequest["itemsPerPage"] = str(itemsPerPage)
		if organization: edrRequest["organization"] = organization
		if pageNumber: edrRequest["pageNumber"] = str(pageNumber)
		if query: edrRequest["query"] = query
		if sorting: edrRequest["sorting"] = sorting
		if time: edrRequest["time"] = time
		if toTime: edrRequest["toTime"] = toTime

		return fortiedr_connection.send(url, edrRequest)

	def create_or_edit_tag(self, newTagName: str = None, organization: str = None, tagId: int = None, tagName: str = None) -> tuple[bool, None]:
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
		if newTagName: createOrEditTagRequest["newTagName"] = newTagName
		if organization: createOrEditTagRequest["organization"] = organization
		if tagId: createOrEditTagRequest["tagId"] = str(tagId)
		if tagName: createOrEditTagRequest["tagName"] = tagName

		return fortiedr_connection.send(url, createOrEditTagRequest)

	def customize_fortinet_query(self, id: int = None, dayOfMonth: int = None, dayOfWeek: int = None, forceSaving: bool = None, frequency: int = None, frequencyUnit: str = None, fromTime: str = None, hour: int = None, organization: str = None, scheduled: bool = None, state: bool = None, time: str = None, toTime: str = None, queryToEdit: str = None) -> tuple[bool, None]:
		'''
		Class ThreatHunting
		Description: This API customizes the scheduling properties of a Fortinet query.
        
		Args:
			id (int): Specifies the query ID to edit.
			ootbQueryCustomizeRequest (Object): Check 'ootbQueryCustomizeRequest' in the API documentation for further information.
			queryToEdit (str): Specifies the query name to edit.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("customize_fortinet_query", locals())

		url = '/management-rest/threat-hunting/customize-fortinet-query'
		url_params = []
		if id:
			url_params.append('id=' + id)
		if queryToEdit:
			url_params.append('queryToEdit=' + queryToEdit)
		url += '?' + '&'.join(url_params)

		ootbQueryCustomizeRequest = {}
		if dayOfMonth: ootbQueryCustomizeRequest["dayOfMonth"] = str(dayOfMonth)
		if dayOfWeek: ootbQueryCustomizeRequest["dayOfWeek"] = str(dayOfWeek)
		if forceSaving: ootbQueryCustomizeRequest["forceSaving"] = forceSaving
		if frequency: ootbQueryCustomizeRequest["frequency"] = str(frequency)
		if frequencyUnit: ootbQueryCustomizeRequest["frequencyUnit"] = frequencyUnit
		if fromTime: ootbQueryCustomizeRequest["fromTime"] = fromTime
		if hour: ootbQueryCustomizeRequest["hour"] = str(hour)
		if organization: ootbQueryCustomizeRequest["organization"] = organization
		if scheduled: ootbQueryCustomizeRequest["scheduled"] = scheduled
		if state: ootbQueryCustomizeRequest["state"] = state
		if time: ootbQueryCustomizeRequest["time"] = time
		if toTime: ootbQueryCustomizeRequest["toTime"] = toTime

		return fortiedr_connection.send(url, ootbQueryCustomizeRequest)

	def delete_saved_queries(self, deleteAll: bool = None, deleteFromCommunity: bool = None, organization: str = None, queryIds: list = None, queryNames: list = None, scheduled: bool = None, source: list = None) -> tuple[bool, None]:
		'''
		Class ThreatHunting
		Description: This API deletes the saved queries.
        
		Args:
			deleteAll (bool): A true/false parameter indicating whether all queries should be deleted. False by default.
			deleteFromCommunity (bool): A true/false parameter indicating if whether to delete a query from the FortiEDR Community also.
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations..
			queryIds (list): Specifies the query IDs list.
			integer (list): Specifies the query IDs list.
			queryNames (list): Specifies the query names list.
			string (list): Specifies the query names list.
			scheduled (bool): A true/false parameter indicating whether the query is scheduled.
			source (list): Specifies the query source list.
			string (list): Specifies the query source list.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_saved_queries", locals())

		url = '/management-rest/threat-hunting/delete-saved-queries'
		url_params = []
		if deleteAll:
			url_params.append('deleteAll=' + deleteAll)
		if deleteFromCommunity:
			url_params.append('deleteFromCommunity=' + deleteFromCommunity)
		if organization:
			url_params.append('organization=' + organization)
		if queryIds:
			url_params.append('queryIds=' + ",".join(map(str, queryIds)))
		if queryNames:
			url_params.append('queryNames=' + ",".join(str(queryNames)))
		if scheduled:
			url_params.append('scheduled=' + scheduled)
		if source:
			url_params.append('source=' + ",".join(str(source)))
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def delete_tags(self, organization: str = None, tagIds: list = None, tagNames: list = None) -> tuple[bool, None]:
		'''
		Class ThreatHunting
		Description: This API deletes the saved queries tags.
        
		Args:
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations..
			tagIds (list): Specifies the tag ID list.
			integer (list): Specifies the tag ID list.
			tagNames (list): Specifies the tag name list.
			string (list): Specifies the tag name list.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_tags", locals())

		url = '/management-rest/threat-hunting/delete-tags'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		if tagIds:
			url_params.append('tagIds=' + ",".join(map(str, tagIds)))
		if tagNames:
			url_params.append('tagNames=' + ",".join(str(tagNames)))
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def facets(self, accountId: int = None, category: str = None, devices: list = None, facets: list = None, filters: list = None, fromTime: str = None, itemsPerPage: int = None, organization: str = None, pageNumber: int = None, query: str = None, sorting: list = None, time: str = None, toTime: str = None) -> tuple[bool, list]:
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
		if accountId: facetsRequest["accountId"] = str(accountId)
		if category: facetsRequest["category"] = category
		if devices: facetsRequest["devices"] = devices
		if facets: facetsRequest["facets"] = facets
		if filters: facetsRequest["filters"] = filters
		if fromTime: facetsRequest["fromTime"] = fromTime
		if itemsPerPage: facetsRequest["itemsPerPage"] = str(itemsPerPage)
		if organization: facetsRequest["organization"] = organization
		if pageNumber: facetsRequest["pageNumber"] = str(pageNumber)
		if query: facetsRequest["query"] = query
		if sorting: facetsRequest["sorting"] = sorting
		if time: facetsRequest["time"] = time
		if toTime: facetsRequest["toTime"] = toTime

		return fortiedr_connection.send(url, facetsRequest)

	def list_saved_queries(self, organization: str = None, scheduled: bool = None, source: list = None) -> tuple[bool, list]:
		'''
		Class ThreatHunting
		Description: This API retrieves the existing saved queries list.
        
		Args:
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations..
			scheduled (bool): A true/false parameter indicating whether the query is scheduled.
			source (list): Specifies the query source list.
			string (list): Specifies the query source list.

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_saved_queries", locals())

		url = '/management-rest/threat-hunting/list-saved-queries'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		if scheduled:
			url_params.append('scheduled=' + scheduled)
		if source:
			url_params.append('source=' + ",".join(str(source)))
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def list_tags(self, organization: str = None) -> tuple[bool, list]:
		'''
		Class ThreatHunting
		Description: This API retrieves the existing saved queries tag list.
        
		Args:
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations..

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_tags", locals())

		url = '/management-rest/threat-hunting/list-tags'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def save_query(self, id: int = None, queryToEdit: str = None, category: str = None, classification: str = None, collectorNames: list = None, community: bool = None, dayOfMonth: int = None, dayOfWeek: int = None, description: str = None, forceSaving: bool = None, frequency: int = None, frequencyUnit: str = None, fromTime: str = None, hour: int = None, name: str = None, organization: str = None, query: str = None, scheduled: bool = None, state: bool = None, tagIds: list = None, tagNames: list = None, time: str = None, toTime: str = None) -> tuple[bool, None]:
		'''
		Class ThreatHunting
		Description: This API saves the query.
        
		Args:
			id (int): Specifies the query ID to edit.
			queryToEdit (str): Specifies the query name to edit.
			saveQueryRequest (Object): Check 'saveQueryRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("save_query", locals())

		url = '/management-rest/threat-hunting/save-query'
		url_params = []
		if id:
			url_params.append('id=' + id)
		if queryToEdit:
			url_params.append('queryToEdit=' + queryToEdit)
		url += '?' + '&'.join(url_params)

		saveQueryRequest = {}
		if category: saveQueryRequest["category"] = category
		if classification: saveQueryRequest["classification"] = classification
		if collectorNames: saveQueryRequest["collectorNames"] = collectorNames
		if community: saveQueryRequest["community"] = community
		if dayOfMonth: saveQueryRequest["dayOfMonth"] = str(dayOfMonth)
		if dayOfWeek: saveQueryRequest["dayOfWeek"] = str(dayOfWeek)
		if description: saveQueryRequest["description"] = description
		if forceSaving: saveQueryRequest["forceSaving"] = forceSaving
		if frequency: saveQueryRequest["frequency"] = str(frequency)
		if frequencyUnit: saveQueryRequest["frequencyUnit"] = frequencyUnit
		if fromTime: saveQueryRequest["fromTime"] = fromTime
		if hour: saveQueryRequest["hour"] = str(hour)
		if name: saveQueryRequest["name"] = name
		if organization: saveQueryRequest["organization"] = organization
		if query: saveQueryRequest["query"] = query
		if scheduled: saveQueryRequest["scheduled"] = scheduled
		if state: saveQueryRequest["state"] = state
		if tagIds: saveQueryRequest["tagIds"] = tagIds
		if tagNames: saveQueryRequest["tagNames"] = tagNames
		if time: saveQueryRequest["time"] = time
		if toTime: saveQueryRequest["toTime"] = toTime

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
		if accountId: edrRequest["accountId"] = str(accountId)
		if category: edrRequest["category"] = category
		if devices: edrRequest["devices"] = devices
		if filters: edrRequest["filters"] = filters
		if fromTime: edrRequest["fromTime"] = fromTime
		if itemsPerPage: edrRequest["itemsPerPage"] = str(itemsPerPage)
		if organization: edrRequest["organization"] = organization
		if pageNumber: edrRequest["pageNumber"] = str(pageNumber)
		if query: edrRequest["query"] = query
		if sorting: edrRequest["sorting"] = sorting
		if time: edrRequest["time"] = time
		if toTime: edrRequest["toTime"] = toTime

		return fortiedr_connection.send(url, edrRequest)

	def set_query_state(self, state: bool, markAll: bool = None, organization: str = None, queryIds: list = None, queryNames: list = None, source: list = None) -> tuple[bool, None]:
		'''
		Class ThreatHunting
		Description: This API updates the scheduled saved query state.
        
		Args:
			markAll (bool): A true/false parameter indicating whether all queries should be marked with the same value as 'state' property. False by default.
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations..
			queryIds (list): Specifies the query ID list.
			integer (list): Specifies the query ID list.
			queryNames (list): Specifies the query name list.
			string (list): Specifies the query name list.
			source (list): Specifies the query source list.
			string (list): Specifies the query source list.
			state (bool): A true/false parameter indicating whether to save the query as enabled.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("set_query_state", locals())

		url = '/management-rest/threat-hunting/set-query-state'
		url_params = []
		if markAll:
			url_params.append('markAll=' + markAll)
		if organization:
			url_params.append('organization=' + organization)
		if queryIds:
			url_params.append('queryIds=' + ",".join(map(str, queryIds)))
		if queryNames:
			url_params.append('queryNames=' + ",".join(str(queryNames)))
		if source:
			url_params.append('source=' + ",".join(str(source)))
		if state:
			url_params.append('state=' + state)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

class Users:
	'''API to define user'''

	def create_user(self, organization: str = None, confirmPassword: str = None, customScript: bool = None, email: str = None, firstName: str = None, lastName: str = None, password: str = None, remoteShell: bool = None, restApi: bool = None, role: str = None, title: str = None, username: str = None) -> tuple[bool, None]:
		'''
		Class Users
		Description: This API create user in the system. (only for Admin role.
        
		Args:
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non-shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	each ��� Indicates that the operation applies independently to each organization. For example, let's assume that the same user exists in multiple organizations. When each is specified in the organization parameter, then each organization can update this user separately..
			userRequest (Object): Check 'userRequest' in the API documentation for further information.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("create_user", locals())

		url = '/management-rest/users/create-user'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)

		userRequest = {}
		if confirmPassword: userRequest["confirmPassword"] = confirmPassword
		if customScript: userRequest["customScript"] = customScript
		if email: userRequest["email"] = email
		if firstName: userRequest["firstName"] = firstName
		if lastName: userRequest["lastName"] = lastName
		if password: userRequest["password"] = password
		if remoteShell: userRequest["remoteShell"] = remoteShell
		if restApi: userRequest["restApi"] = restApi
		if role: userRequest["role"] = role
		if title: userRequest["title"] = title
		if username: userRequest["username"] = username

		return fortiedr_connection.send(url, userRequest)

	def delete_saml_settings(self, organizationNameRequest: str, ) -> tuple[bool, None]:
		'''
		Class Users
		Description: Delete SAML authentication settings per organization.
        
		Args:
			organizationNameRequest (str): organizationNameRequest.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_saml_settings", locals())

		url = '/management-rest/users/delete-saml-settings'
		url_params = []
		if organizationNameRequest:
			url_params.append('organizationNameRequest=' + organizationNameRequest)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def delete_user(self, username: str, organization: str = None) -> tuple[bool, None]:
		'''
		Class Users
		Description: This API delete user from the system. Use the input parameters to filter organization.
        
		Args:
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.
			username (str): Specifies the name of the user.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("delete_user", locals())

		url = '/management-rest/users/delete-user'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		if username:
			url_params.append('username=' + username)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)

	def get_sp_metadata(self, organization: str, ) -> tuple[bool, str]:
		'''
		Class Users
		Description: This API call retrieve the FortiEdr metadata by organization.
        
		Args:
			organization (str): organization.

		Returns:
			bool: Status of the request (True or False). 
			str
		'''
		validate_params("get_sp_metadata", locals())

		url = '/management-rest/users/get-sp-metadata'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def list_users(self, organization: str = None) -> tuple[bool, list]:
		'''
		Class Users
		Description: This API call outputs a list of the users in the system. Use the input parameters to filter the list.
        
		Args:
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations..

		Returns:
			bool: Status of the request (True or False). 
			list
		'''
		validate_params("list_users", locals())

		url = '/management-rest/users/list-users'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def reset_password(self, username: str, organization: str = None, confirmPassword: str = None, password: str = None) -> tuple[bool, None]:
		'''
		Class Users
		Description: This API reset user password. Use the input parameters to filter organization.
        
		Args:
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly.
			userRequest (Object): Check 'userRequest' in the API documentation for further information.
			username (str): Specifies the name of the user.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("reset_password", locals())

		url = '/management-rest/users/reset-password'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		if username:
			url_params.append('username=' + username)
		url += '?' + '&'.join(url_params)

		userRequest = {}
		if confirmPassword: userRequest["confirmPassword"] = confirmPassword
		if password: userRequest["password"] = password

		return fortiedr_connection.insert(url, userRequest)

	def update_saml_settings(self, idpMetadataFile: BinaryIO, ) -> tuple[bool, None]:
		'''
		Class Users
		Description: Create / Update SAML authentication settings per organization.
        
		Args:
			idpMetadataFile (BinaryIO): idpMetadataFile.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("update_saml_settings", locals())

		url = '/management-rest/users/update-saml-settings'
		if idpMetadataFile:
			idpMetadataFile = {'idpMetadataFile': idpMetadataFile}


		return fortiedr_connection.upload(url, idpMetadataFile)

	def update_user(self, username: str, organization: str = None, customScript: bool = None, email: str = None, firstName: str = None, lastName: str = None, remoteShell: bool = None, restApi: bool = None, role: str = None, title: str = None) -> tuple[bool, None]:
		'''
		Class Users
		Description: This API update user in the system. Use the input parameters to filter organization.
        
		Args:
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non-shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
���	Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.
���	each ��� Indicates that the operation applies independently to each organization. For example, let's assume that the same user exists in multiple organizations. When each is specified in the organization parameter, then each organization can update this user separately..
			userRequest (Object): Check 'userRequest' in the API documentation for further information.
			username (str): Specifies the name of the user.

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("update_user", locals())

		url = '/management-rest/users/update-user'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		if username:
			url_params.append('username=' + username)
		url += '?' + '&'.join(url_params)

		userRequest = {}
		if customScript: userRequest["customScript"] = customScript
		if email: userRequest["email"] = email
		if firstName: userRequest["firstName"] = firstName
		if lastName: userRequest["lastName"] = lastName
		if remoteShell: userRequest["remoteShell"] = remoteShell
		if restApi: userRequest["restApi"] = restApi
		if role: userRequest["role"] = role
		if title: userRequest["title"] = title
		if username: userRequest["username"] = username

		return fortiedr_connection.insert(url, userRequest)


debug = None
ssl_enabled = True
organization = None
api_json_params = None

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
		'list': list,
		'NoneType': None,
		'BinaryIO': bytes,
	}
	json_params = api_json_params[function_name]
	for key, value in local_params.items():
		if key == "self" or value is None: continue
		# print(json_params[key])
		t = data_types[json_params[key]]
		r = str(type(value))
		if not isinstance(value, t):
			print(f"Error on defined params!\nParam '{key}' should be defined as type '{json_params[key]}', not {r}")
			exit()
                        
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
