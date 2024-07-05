
import re
import os
import json
from typing import BinaryIO
from fortiedr.auth import Auth as fedrAuth
from fortiedr.connector import FortiEDR_API_GW

version = '3.8'

fortiedr_connection = None

class ApplicationControl:
	'''Application Control Rest Api Controller'''

	def get_applications(self, currentPage: int, organization: str, fileName: str = None, path: str = None, signer: str = None, enabled: bool = None, hash: str = None, operatingSystem: str = None, policyIds: list = None, tag: str = None) -> tuple[bool, None]:
		'''
		Class ApplicationControl
		Description: Get application controls.
        
		Args:
			fileName (str): Specifies the file name, if contains special characters - encode to HTML URL Encoding
			path (str): Specifies the path, if contains special characters - encode to HTML URL Encoding
			signer (str): Specifies the value, if contains special characters - encode to HTML URL Encoding
			currentPage (int): Specifies the current page
			enabled (bool): Specifies the state of the application control
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
		if applicationControls:
			applicationControlSaveRequest["applicationControls"] = f"{applicationControls}"
		if organization:
			applicationControlSaveRequest["organization"] = f"{organization}"

		return fortiedr_connection.send(url, applicationControlSaveRequest)

	def insert_applications(self, appIds: list, organization: str, enabled: bool = None, groupIds: list = None, isOverridePolicies: bool = None, policyIds: list = None, tagId: int = None) -> tuple[bool, list]:
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
		if name:
			applicationControlTagCreateRequest["name"] = f"{name}"
		if organization:
			applicationControlTagCreateRequest["organization"] = f"{organization}"

		return fortiedr_connection.send(url, applicationControlTagCreateRequest)

class Administrator:
	'''The Administrator module enables administrators to perform administrative operations, such as handling licenses and users.'''

	def set_enable_default_application_control_state(self, isEnableDefaultApplicationControl: bool = None, organization: str = None) -> tuple[bool, None]:
		'''
		Class Administrator
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

	def set_tray_notification_settings(self, enabledPopup: bool = None, enabledTrayNotification: bool = None, message: str = None, organization: str = None) -> tuple[bool, None]:
		'''
		Class Administrator
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
		if enabledPopup:
			adminSetTrayNotificationSettingsRequest["enabledPopup"] = f"{enabledPopup}"
		if enabledTrayNotification:
			adminSetTrayNotificationSettingsRequest["enabledTrayNotification"] = f"{enabledTrayNotification}"
		if message:
			adminSetTrayNotificationSettingsRequest["message"] = f"{message}"
		if organization:
			adminSetTrayNotificationSettingsRequest["organization"] = f"{organization}"

		return fortiedr_connection.send(url, adminSetTrayNotificationSettingsRequest)

	def list_collector_installers(self, organization: str = None) -> tuple[bool, None]:
		'''
		Class Administrator
		Description: This API call output the available collectors installers.
        
		Args:
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.

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
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.

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
		if organization:
			organizationRequest["organization"] = f"{organization}"

		return fortiedr_connection.get(url, organizationRequest)

	def previous_registration_passwords(self, passwordId: int, organization: str = None) -> tuple[bool, str]:
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
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.

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
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
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

	def upload_content(self, file: BinaryIO, ) -> tuple[bool, str]:
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
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
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

	def assign_collector_group(self, collectorGroups: list, policyName: str, forceAssign: bool = None, organization: str = None) -> tuple[bool, None]:
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

	def clone_policy(self, newPolicyName: str, sourcePolicyName: str, organization: str = None) -> tuple[bool, None]:
		'''
		Class CommunicationControl
		Description: application clone policy.
        
		Args:
			newPolicyName (str): Specifies security policy target name.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			sourcePolicyName (str): Specifies security policy source name

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
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

	def resolve_applications(self, applyNested: bool = None, comment: str = None, organization: str = None, products: list = None, resolve: bool = None, signed: bool = None, vendors: list = None, versions: list = None) -> tuple[bool, None]:
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

	def set_policy_mode(self, mode: str, policyNames: list, organization: str = None) -> tuple[bool, None]:
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

	def set_policy_permission(self, decision: str, policies: list, applyNested: bool = None, organization: str = None, products: list = None, signed: bool = None, vendors: list = None, versions: list = None) -> tuple[bool, None]:
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

	def set_policy_rule_state(self, policyName: str, ruleName: str, state: str, organization: str = None) -> tuple[bool, None]:
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

	def insert_events(self, actions: list = None, applicationControl: bool = None, archived: bool = None, classifications: list = None, collectorGroups: list = None, destinations: list = None, device: str = None, deviceControl: bool = None, deviceIps: list = None, eventIds: list = None, eventType: list = None, expired: bool = None, fileHash: str = None, firstSeen: str = None, firstSeenFrom: str = None, firstSeenTo: str = None, handled: bool = None, itemsPerPage: int = None, lastSeen: str = None, lastSeenFrom: str = None, lastSeenTo: str = None, loggedUser: str = None, macAddresses: list = None, muted: bool = None, operatingSystems: list = None, organization: str = None, pageNumber: int = None, paths: list = None, process: str = None, rule: str = None, seen: bool = None, severities: list = None, signed: bool = None, sorting: str = None, strictMode: bool = None, archive: bool = None, classification: str = None, comment: str = None, familyName: str = None, forceUnmute: bool = None, handle: bool = None, malwareType: str = None, mute: bool = None, muteDuration: str = None, read: bool = None, threatName: str = None) -> tuple[bool, None]:
		'''
		Class Events
		Description: This API call updates the read/unread, handled/unhandled or archived/unarchived state of an event. The output of this call is a message indicating whether the update succeeded or failed.
        
		Args:
			actions (list): Specifies the action of the event
			applicationControl (bool): A true/false parameter indicating whether to include only application control events
			archived (bool): A true/false parameter indicating whether to include only archived events
			classifications (list): Specifies the classification of the event
			collectorGroups (list): Specifies the collector groups whose collector reported the events
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
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
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

	def delete_events(self, actions: list = None, applicationControl: bool = None, archived: bool = None, classifications: list = None, collectorGroups: list = None, deleteAll: bool = None, destinations: list = None, device: str = None, deviceControl: bool = None, deviceIps: list = None, eventIds: list = None, eventType: list = None, expired: bool = None, fileHash: str = None, firstSeen: str = None, firstSeenFrom: str = None, firstSeenTo: str = None, handled: bool = None, itemsPerPage: int = None, lastSeen: str = None, lastSeenFrom: str = None, lastSeenTo: str = None, loggedUser: str = None, macAddresses: list = None, muted: bool = None, operatingSystems: list = None, organization: str = None, pageNumber: int = None, paths: list = None, process: str = None, rule: str = None, seen: bool = None, severities: list = None, signed: bool = None, sorting: str = None, strictMode: bool = None) -> tuple[bool, None]:
		'''
		Class Events
		Description: This API call delete events.
        
		Args:
			actions (list): Specifies the action of the event
			applicationControl (bool): A true/false parameter indicating whether to include only application control events
			archived (bool): A true/false parameter indicating whether to include only archived events
			classifications (list): Specifies the classification of the event
			collectorGroups (list): Specifies the collector groups whose collector reported the events
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
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
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

	def count_events(self, actions: list = None, applicationControl: bool = None, archived: bool = None, classifications: list = None, collectorGroups: list = None, destinations: list = None, device: str = None, deviceControl: bool = None, deviceIps: list = None, eventIds: list = None, eventType: list = None, expired: bool = None, fileHash: str = None, firstSeen: str = None, firstSeenFrom: str = None, firstSeenTo: str = None, handled: bool = None, itemsPerPage: int = None, lastSeen: str = None, lastSeenFrom: str = None, lastSeenTo: str = None, loggedUser: str = None, macAddresses: list = None, muted: bool = None, operatingSystems: list = None, organization: str = None, pageNumber: int = None, paths: list = None, process: str = None, rule: str = None, seen: bool = None, severities: list = None, signed: bool = None, sorting: str = None, strictMode: bool = None) -> tuple[bool, int]:
		'''
		Class Events
		Description: Count Events.
        
		Args:
			actions (list): Specifies the action of the event
			applicationControl (bool): A true/false parameter indicating whether to include only application control events
			archived (bool): A true/false parameter indicating whether to include only archived events
			classifications (list): Specifies the classification of the event
			collectorGroups (list): Specifies the collector groups whose collector reported the events
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
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
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

	def create_exception(self, allCollectorGroups: bool = None, allDestinations: bool = None, allOrganizations: bool = None, allUsers: bool = None, collectorGroups: list = None, comment: str = None, destinations: list = None, eventId: int = None, exceptionId: int = None, useAnyPath: object = None, useInException: object = None, wildcardFiles: object = None, wildcardPaths: object = None, forceCreate: bool = None, organization: str = None, users: list = None) -> tuple[bool, str]:
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
			exceptionRequest (Object): Check 'exceptionRequest' in the API documentation for further information.
			forceCreate (bool): A true/false parameter indicating whether to create the exception, even if there are already exceptions that cover this given event
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
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
		if organization != None:
			url_params.append(f'organization={organization}')
		if users != None:
			users = ",".join(users) if isinstance(users, list) else users
			url_params.append(f'users={users}')
		url += '?' + '&'.join(url_params)

		exceptionRequest = {}
		if useAnyPath:
			exceptionRequest["useAnyPath"] = f"{useAnyPath}"
		if useInException:
			exceptionRequest["useInException"] = f"{useInException}"
		if wildcardFiles:
			exceptionRequest["wildcardFiles"] = f"{wildcardFiles}"
		if wildcardPaths:
			exceptionRequest["wildcardPaths"] = f"{wildcardPaths}"

		return fortiedr_connection.send(url, exceptionRequest)

	def export_raw_data_items_json(self, organization: str = None, rawItemIds: str = None) -> tuple[bool, None]:
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
		return fortiedr_connection.get(url)

	def list_events(self, actions: list = None, applicationControl: bool = None, archived: bool = None, classifications: list = None, collectorGroups: list = None, destinations: list = None, device: str = None, deviceControl: bool = None, deviceIps: list = None, eventIds: list = None, eventType: list = None, expired: bool = None, fileHash: str = None, firstSeen: str = None, firstSeenFrom: str = None, firstSeenTo: str = None, handled: bool = None, itemsPerPage: int = None, lastSeen: str = None, lastSeenFrom: str = None, lastSeenTo: str = None, loggedUser: str = None, macAddresses: list = None, muted: bool = None, operatingSystems: list = None, organization: str = None, pageNumber: int = None, paths: list = None, process: str = None, rule: str = None, seen: bool = None, severities: list = None, signed: bool = None, sorting: str = None, strictMode: bool = None) -> tuple[bool, list]:
		'''
		Class Events
		Description: List Events.
        
		Args:
			actions (list): Specifies the action of the event
			applicationControl (bool): A true/false parameter indicating whether to include only application control events
			archived (bool): A true/false parameter indicating whether to include only archived events
			classifications (list): Specifies the classification of the event
			collectorGroups (list): Specifies the collector groups whose collector reported the events
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
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
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

	def create_or_edit_exception(self, confirmEdit: bool = None, exceptionJSON: str = None, organization: str = None) -> tuple[bool, int]:
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
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
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

	def get_event_exceptions(self, eventId: int, organization: str = None) -> tuple[bool, list]:
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
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
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

class Forensics:
	'''The Forensics module facilitates deep analysis into the actual internals of the communicating devices operating system that led up to an event.'''

	def get_event_file(self, rawEventId: int, disk: bool = None, endRange: str = None, filePaths: list = None, memory: bool = None, organization: str = None, processId: int = None, startRange: str = None) -> tuple[bool, None]:
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
		return fortiedr_connection.get(url)

	def get_file(self, device: str, filePaths: list, type: str, organization: str = None) -> tuple[bool, None]:
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
		return fortiedr_connection.get(url)

	def remediate_device(self, terminatedProcessId: int, device: str = None, deviceId: int = None, executablesToRemove: list = None, organization: str = None, persistenceDataAction: str = None, persistenceDataNewContent: str = None, persistenceDataPath: str = None, persistenceDataValueName: str = None, persistenceDataValueNewType: str = None, processName: str = None, threadId: int = None) -> tuple[bool, None]:
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
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.

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
	'''API to create and test connectors.'''

	def connectors_metadata(self, organization: str = None) -> tuple[bool, None]:
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
		if apiKey:
			createConnectorRequest["apiKey"] = f"{apiKey}"
		if connectorActions:
			createConnectorRequest["connectorActions"] = f"{connectorActions}"
		if coreId != None:
			createConnectorRequest["coreId"] = coreId
		if enabled:
			createConnectorRequest["enabled"] = f"{enabled}"
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

	def delete_connector(self, connectorName: str, connectorType: str, organization: str = None) -> tuple[bool, None]:
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

	def list_connectors(self, onlyValidConnectors: bool = None, organization: str = None) -> tuple[bool, list]:
		'''
		Class Integrations
		Description: List all organization connectors.
        
		Args:
			onlyValidConnectors (bool): Set to true to retrieve enabled, non-failing connectors.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly

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
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def test_connector(self, connectorName: str, connectorType: str, organization: str = None) -> tuple[bool, None]:
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
		if apiKey:
			updateConnectorRequest["apiKey"] = f"{apiKey}"
		if connectorActions:
			updateConnectorRequest["connectorActions"] = f"{connectorActions}"
		if coreId != None:
			updateConnectorRequest["coreId"] = f"{coreId}"
		if enabled:
			updateConnectorRequest["enabled"] = f"{enabled}"
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

	def aggregator_logs(self, device: str = None, deviceId: int = None, organization: str = None) -> tuple[bool, None]:
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

	def collector_logs(self, device: str = None, deviceId: int = None, organization: str = None) -> tuple[bool, None]:
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

	def core_logs(self, device: str = None, deviceId: int = None, organization: str = None) -> tuple[bool, None]:
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

	def create_collector_group(self, name: str, organization: str = None) -> tuple[bool, None]:
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
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			
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

	def isolate_collectors(self, devices: list = None, devicesIds: list = None, organization: str = None) -> tuple[bool, None]:
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
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
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
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.

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
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			
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
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
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
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
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
			collectors (list): Array of collectors names. To move collectors from one organization to another, for each collector please add the organization name before the collector name (<organization-name>\\<collector-name>)
			forceAssign (bool): Indicates whether to force the assignment even if the organization of the target Collector group is under migration
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			targetCollectorGroup (str): Collector group. To move collectors from one organization to another, please add the organization name before the target collector group (<organization-name>\\<collector-group-name>)

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
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			
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

	def unisolate_collectors(self, devices: list = None, devicesIds: list = None, organization: str = None) -> tuple[bool, None]:
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

class IoT:
	'''The IoT module enables you to monitor the devices found in IoT scans and create/move IoT Groups.'''

	def create_iot_group(self, name: str, organization: str = None) -> tuple[bool, None]:
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
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			
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
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.

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
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			
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
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.

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

	def move_iot_devices(self, iotDeviceIds: list, targetIotGroup: str, organization: str = None) -> tuple[bool, None]:
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
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
			
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
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.

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
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.

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

	def update_ip_set(self, description: str = None, exclude: list = None, include: list = None, name: str = None, organization: str = None) -> tuple[bool, None]:
		'''
		Class IPsets
		Description: This API update IP sets in the system. Use the input parameters to filter organization.
        
		Args:
			ipGroupsRequest (Object): Check 'ipGroupsRequest' in the API documentation for further information.
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non-shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
				each  Indicates that the operation applies independently to each organization. For example, let's assume that the same user exists in multiple organizations. When each is specified in the organization parameter, then each organization can update this user separately.

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
		if expirationDate:
			createAccountRequest["expirationDate"] = f"{expirationDate}"
		if forensics:
			createAccountRequest["forensics"] = f"{forensics}"
		if iotAllocated != None:
			createAccountRequest["iotAllocated"] = f"{iotAllocated}"
		if name:
			createAccountRequest["name"] = f"{name}"
		if password:
			createAccountRequest["password"] = f"{password}"
		if passwordConfirmation:
			createAccountRequest["passwordConfirmation"] = f"{passwordConfirmation}"
		if requestPolicyEngineLibUpdates:
			createAccountRequest["requestPolicyEngineLibUpdates"] = f"{requestPolicyEngineLibUpdates}"
		if serialNumber:
			createAccountRequest["serialNumber"] = f"{serialNumber}"
		if serversAllocated != None:
			createAccountRequest["serversAllocated"] = f"{serversAllocated}"
		if vulnerabilityAndIoT:
			createAccountRequest["vulnerabilityAndIoT"] = f"{vulnerabilityAndIoT}"
		if workstationsAllocated != None:
			createAccountRequest["workstationsAllocated"] = f"{workstationsAllocated}"

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

	def export_organization(self, destinationName: str = None, organization: str = None) -> tuple[bool, None]:
		'''
		Class Organizations
		Description: Export organization data as zip file.
        
		Args:
			destinationName (str): The organization destination name
			organization (str): Organization to export

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("export_organization", locals())

		url = '/management-rest/organizations/export-organization'
		url_params = []
		if destinationName != None:
			url_params.append(f'destinationName={destinationName}')
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def import_organization(self, file: BinaryIO = None) -> tuple[bool, None]:
		'''
		Class Organizations
		Description: Import organization.
        
		Args:
			file (BinaryIO): Export zip file

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
		if aggregatorsMap:
			transferCollectorRequests["aggregatorsMap"] = f"{aggregatorsMap}"
		if sourceOrganization:
			transferCollectorRequests["sourceOrganization"] = f"{sourceOrganization}"
		if targetOrganization:
			transferCollectorRequests["targetOrganization"] = f"{targetOrganization}"
		if verificationCode:
			transferCollectorRequests["verificationCode"] = f"{verificationCode}"

		return fortiedr_connection.send(url, transferCollectorRequests)

	def transfer_collectors_stop(self, organization: str = None) -> tuple[bool, None]:
		'''
		Class Organizations
		Description: Transfer collector stop.
        
		Args:
			organization (str): Specifies the organization which the migration process should stop

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
		'''
		validate_params("transfer_collectors_stop", locals())

		url = '/management-rest/organizations/transfer-collectors-stop'
		url_params = []
		if organization != None:
			url_params.append(f'organization={organization}')
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.send(url)

	def update_organization(self, eXtendedDetection: bool = None, edr: bool = None, edrAddOnsAllocated: int = None, edrBackupEnabled: bool = None, edrEnabled: bool = None, edrNumberOfShards: int = None, edrStorageAllocatedInMb: int = None, expirationDate: str = None, forensics: bool = None, iotAllocated: int = None, name: str = None, requestPolicyEngineLibUpdates: bool = None, serialNumber: str = None, serversAllocated: int = None, vulnerabilityAndIoT: bool = None, workstationsAllocated: int = None, organization: str = None) -> tuple[bool, None]:
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
		if expirationDate:
			accountRequest["expirationDate"] = f"{expirationDate}"
		if forensics:
			accountRequest["forensics"] = f"{forensics}"
		if iotAllocated != None:
			accountRequest["iotAllocated"] = f"{iotAllocated}"
		if name:
			accountRequest["name"] = f"{name}"
		if requestPolicyEngineLibUpdates:
			accountRequest["requestPolicyEngineLibUpdates"] = f"{requestPolicyEngineLibUpdates}"
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

	def assign_collector_group(self, collectorGroupNames: list, policyName: str, forceAssign: bool = None, organization: str = None) -> tuple[bool, None]:
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

	def clone(self, newPolicyName: str, sourcePolicyName: str, organization: str = None) -> tuple[bool, None]:
		'''
		Class Playbookspolicies
		Description: clone policy.
        
		Args:
			newPolicyName (str): Specifies security policy target name.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			sourcePolicyName (str): Specifies security policy source name

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
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
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.

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

	def map_connectors_to_actions(self, customActionsToConnectorsMaps: list = None, fortinetActionsToConnectorsMaps: list = None, policyName: str = None, organization: str = None) -> tuple[bool, None]:
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

	def set_action_classification(self, organization: str = None, customActionsToClassificationMaps: list = None, fortinetActionsToClassificationMaps: list = None, policyName: str = None) -> tuple[bool, None]:
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

	def set_mode(self, mode: str, policyName: str, organization: str = None) -> tuple[bool, None]:
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

	def assign_collector_group(self, collectorsGroupName: list, policyName: str, forceAssign: bool = None, organization: str = None) -> tuple[bool, None]:
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

	def clone(self, newPolicyName: str, sourcePolicyName: str, organization: str = None) -> tuple[bool, None]:
		'''
		Class Policies
		Description: clone policy.
        
		Args:
			newPolicyName (str): Specifies security policy target name.
			organization (str): Specifies the name of a specific organization. The value that you specify here must match exactly
			sourcePolicyName (str): Specifies security policy source name

		Returns:
			bool: Status of the request (True or False). 
			None: This function does not return any data.
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
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.

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

	def scan_files(self, applyRecursiveScan: bool, executableFilesOnly: bool, origin: str, scanBy: str, filePaths: list = None, organization: str = None, scanSelection: list = None) -> tuple[bool, None]:
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

	def set_mode(self, mode: str, policyName: str, organization: str = None) -> tuple[bool, None]:
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

	def set_policy_rule_action(self, action: str, policyName: str, ruleName: str, organization: str = None) -> tuple[bool, None]:
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

	def set_policy_rule_state(self, policyName: str, ruleName: str, state: str, organization: str = None) -> tuple[bool, None]:
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

	def set_mail_format(self, format: str, organization: str = None) -> tuple[bool, None]:
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

	def syslog(self, organization: str = None, certificateBlob: str = None, host: str = None, name: str = None, port: int = None, privateKeyFile: str = None, privateKeyPassword: str = None, protocol: str = None, syslogFormat: str = None, useClientCertificate: bool = None, useSSL: bool = None) -> tuple[bool, None]:
		'''
		Class SendableEntities
		Description: This API creates syslog.
        
		Args:
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non-shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				each  Indicates that the operation applies independently to each organization. For example, let's assume that the same user exists in multiple organizations. When each is specified in the organization parameter, then each organization can update this user separately.
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
		if host:
			syslogRequest["host"] = f"{host}"
		if name:
			syslogRequest["name"] = f"{name}"
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
		if useClientCertificate:
			syslogRequest["useClientCertificate"] = f"{useClientCertificate}"
		if useSSL:
			syslogRequest["useSSL"] = f"{useSSL}"

		return fortiedr_connection.send(url, syslogRequest)

class SystemEvents:
	'''System Events API'''

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
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
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
		if exclusionListName:
			createExclusionsRequest["exclusionListName"] = f"{exclusionListName}"
		if exclusions:
			createExclusionsRequest["exclusions"] = f"{exclusions}"
		if organization:
			createExclusionsRequest["organization"] = f"{organization}"

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
		if exclusionListName:
			updateExclusionsRequest["exclusionListName"] = f"{exclusionListName}"
		if exclusions:
			updateExclusionsRequest["exclusions"] = f"{exclusions}"
		if organization:
			updateExclusionsRequest["organization"] = f"{organization}"

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
		if exclusionIds:
			deleteExclusionsRequest["exclusionIds"] = f"{exclusionIds}"
		if organization:
			deleteExclusionsRequest["organization"] = f"{organization}"

		return fortiedr_connection.delete(url, deleteExclusionsRequest)

	def get_exclusions_list(self, organization: str, ) -> tuple[bool, list]:
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
		if collectorGroupIds:
			createExclusionListRequest["collectorGroupIds"] = f"{collectorGroupIds}"
		if name:
			createExclusionListRequest["name"] = f"{name}"
		if organization:
			createExclusionListRequest["organization"] = f"{organization}"

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
		if collectorGroupIds:
			updateExclusionListRequest["collectorGroupIds"] = f"{collectorGroupIds}"
		if listName:
			updateExclusionListRequest["listName"] = f"{listName}"
		if newName:
			updateExclusionListRequest["newName"] = f"{newName}"
		if organization:
			updateExclusionListRequest["organization"] = f"{organization}"

		return fortiedr_connection.insert(url, updateExclusionListRequest)

	def delete_exclusions_list(self, listName: str, organization: str, ) -> tuple[bool, None]:
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

	def exclusions_search(self, searchText: str, organization: str = None, os: list = None) -> tuple[bool, list]:
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

	def get_threat_hunting_profile(self, organization: str, ) -> tuple[bool, list]:
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

	def delete_threat_hunting_profile(self, name: str, organization: str, ) -> tuple[bool, None]:
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

	def threat_hunting_profile_clone(self, cloneProfileName: str, existingProfileName: str, organization: str, ) -> tuple[bool, None]:
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
		if newTagName:
			createOrEditTagRequest["newTagName"] = f"{newTagName}"
		if organization:
			createOrEditTagRequest["organization"] = f"{organization}"
		if tagId != None:
			createOrEditTagRequest["tagId"] = f"{tagId}"
		if tagName:
			createOrEditTagRequest["tagName"] = f"{tagName}"

		return fortiedr_connection.send(url, createOrEditTagRequest)

	def customize_fortinet_query(self, id: int = None, dayOfMonth: int = None, dayOfWeek: int = None, forceSaving: bool = None, frequency: int = None, frequencyUnit: str = None, fromTime: str = None, hour: int = None, organization: str = None, scheduled: bool = None, state: bool = None, time: str = None, toTime: str = None, queryToEdit: str = None) -> tuple[bool, None]:
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
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
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

	def delete_tags(self, organization: str = None, tagIds: list = None, tagNames: list = None) -> tuple[bool, None]:
		'''
		Class ThreatHunting
		Description: This API deletes the saved queries tags.
        
		Args:
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
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

	def list_saved_queries(self, organization: str = None, scheduled: bool = None, source: list = None) -> tuple[bool, list]:
		'''
		Class ThreatHunting
		Description: This API retrieves the existing saved queries list.
        
		Args:
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
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
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.

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

	def save_query(self, id: int = None, queryToEdit: str = None, category: str = None, classification: str = None, collectorNames: list = None, community: bool = None, dayOfMonth: int = None, dayOfWeek: int = None, description: str = None, forceSaving: bool = None, frequency: int = None, frequencyUnit: str = None, fromTime: str = None, hour: int = None, name: str = None, organization: str = None, query: str = None, scheduled: bool = None, state: bool = None, tagIds: list = None, tagNames: list = None, time: str = None, toTime: str = None) -> tuple[bool, None]:
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
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.
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

class Users:
	'''API to define user'''

	def create_user(self, organization: str = None, confirmPassword: str = None, customScript: bool = None, email: str = None, firstName: str = None, lastName: str = None, password: str = None, remoteShell: bool = None, restApi: bool = None, role: str = None, title: str = None, username: str = None) -> tuple[bool, None]:
		'''
		Class Users
		Description: This API create user in the system. (only for Admin role.
        
		Args:
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non-shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				each  Indicates that the operation applies independently to each organization. For example, let's assume that the same user exists in multiple organizations. When each is specified in the organization parameter, then each organization can update this user separately.
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

	def delete_saml_settings(self, organizationNameRequest: str, ) -> tuple[bool, None]:
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

	def delete_user(self, username: str, organization: str = None) -> tuple[bool, None]:
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

	def get_sp_metadata(self, organization: str, ) -> tuple[bool, str]:
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
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				All organizations  Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.

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

	def reset_password(self, username: str, organization: str = None, confirmPassword: str = None, password: str = None) -> tuple[bool, None]:
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

	def update_saml_settings(self, idpMetadataFile: BinaryIO, ) -> tuple[bool, None]:
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

	def update_user(self, username: str, organization: str = None, customScript: bool = None, email: str = None, firstName: str = None, lastName: str = None, remoteShell: bool = None, restApi: bool = None, role: str = None, title: str = None) -> tuple[bool, None]:
		'''
		Class Users
		Description: This API update user in the system. Use the input parameters to filter organization.
        
		Args:
			organization (str): Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non-shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:
				Exact organization name  Specifies the name of a specific organization. The value that you specify here must match exactly.
				each  Indicates that the operation applies independently to each organization. For example, let's assume that the same user exists in multiple organizations. When each is specified in the organization parameter, then each organization can update this user separately.
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
		if json_params[key] == 'list': continue

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
