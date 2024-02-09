from typing import BinaryIO
from fortiedr.auth import Auth as fedrAuth
from fortiedr.connector import FortiEDR_API_GW

fortiedr_connection = None

class Administrator:

	def list_collector_installers(self, organization :str = None) -> tuple[bool, None]:

		'''
		class Administrator
		Description: This API call output the available collectors installers.

		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/admin/list-collector-installers'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)


	def list_system_summary(self, addLicenseBlob :bool = None, organization :str = None) -> tuple[bool, None]:

		'''
		class Administrator
		Description: Get System Summary.

		:param addLicenseBlob: Indicates whether to put license blob to response. By default addLicenseBlob is false. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/admin/list-system-summary'
		url_params = []
		if addLicenseBlob:
			url_params.append('addLicenseBlob=' + addLicenseBlob)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)


	def previous_registration_passwords(self, organization: str = None) -> tuple[bool, dict]:

		'''
		class Administrator
		Description: This API retrieve previous registration passwords for given organization.

		:param organizationRequest: organizationRequest. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 

		return: 
			Status of the request (True or False). 
			dict

		'''
		url = '/management-rest/admin/previous-registration-passwords'
		url_params = []
		url += '?' + '&'.join(url_params)
		organizationRequest = {
			'organization': organization
		}
		return fortiedr_connection.get(url, organizationRequest)


	def previous_registration_passwords(self, passwordId : int, organization: str = None) -> tuple[bool, str]:

		'''
		class Administrator
		Description: This API deletes previous registration password for given id.

		:param organizationRequest: organizationRequest. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param passwordId: passwordId. 

		return: 
			Status of the request (True or False). 
			str

		'''
		url = '/management-rest/admin/previous-registration-passwords/{passwordId}'
		url_params = []
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)


	def ready(self) -> tuple[bool, None]:

		'''
		class Administrator
		Description: Get System Readiness.

		:param organizationRequest: organizationRequest. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param passwordId: passwordId. 

		'''
		url = '/management-rest/admin/ready'
		return fortiedr_connection.get(url)


	def registration_password(self, password: str, organization: str = None) -> tuple[bool, None]:

		'''
		class Administrator
		Description: This API creates new registration password for given organization.

		:param request: request. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param password: New Registration Password. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/admin/registration-password'
		url_params = []
		url += '?' + '&'.join(url_params)
		request = {
			'organization': organization,
			'password': password
		}
		return fortiedr_connection.send(url, request)


	def set_system_mode(self, mode : str, forceAll :bool = None, organization :str = None) -> tuple[bool, None]:

		'''
		class Administrator
		Description: Set system modeThis API call enables you to switch the system to Simulation mode.

		:param forceAll: Indicates whether to force set all the policies in 'Prevention' mode. 
		:param mode: Operation mode. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
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


	def update_collector_installer(self, collectorGroupIds :dict = None, collectorGroups :dict = None, organization :str = None, updateVersions: dict = None) -> tuple[bool, None]:

		'''
		class Administrator
		Description: This API update collectors target version for collector groups.

		:param collectorGroupIds: Specifies the list of IDs of all the collector groups which should be updated.. 
		:param collectorGroups: Specifies the list of all the collector groups which should be updated.. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 
		:param requestUpdateData: requestUpdateData. 
		:param updateVersions: List of installer versions that should be applied in the collector groups. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/admin/update-collector-installer'
		url_params = []
		if collectorGroupIds:
			url_params.append('collectorGroupIds=' + collectorGroupIds)
		if collectorGroups:
			url_params.append('collectorGroups=' + collectorGroups)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		requestUpdateData = {
			'updateVersions': updateVersions
		}
		return fortiedr_connection.send(url, requestUpdateData)


	def upload_content(self, file : BinaryIO) -> tuple[bool, str]:

		'''
		class Administrator
		Description: Upload content to the system.

		:param file: file. 

		return: 
			Status of the request (True or False). 
			str

		'''
		url = '/management-rest/admin/upload-content'
		url_params = []
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.send(url)


	def upload_license(self, licenseBlob: str = None) -> tuple[bool, None]:

		'''
		class Administrator
		Description: Upload license to the system.

		:param license: license. 
		:param licenseBlob: License blob. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/admin/upload-license'
		url_params = []
		url += '?' + '&'.join(url_params)
		license = {
			'licenseBlob': licenseBlob
		}
		return fortiedr_connection.insert(url, license)

class Audit:

	def get_audit(self, fromTime :str = None, organization :str = None, toTime :str = None) -> tuple[bool, dict]:

		'''
		class Audit
		Description: This API retrieve the audit between 2 dates.

		:param fromTime: Retrieves audit that were written after the given date. Date Format: yyyy-MM-dd (Default is current date). 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 
		:param toTime: Retrieves audit that were written before the given date. Date Format: yyyy-MM-dd (Default is current date). 

		return: 
			Status of the request (True or False). 
			dict

		'''
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

	def assign_collector_group(self, collectorGroups : dict, policyName : str, forceAssign :bool = None, organization :str = None) -> tuple[bool, None]:

		'''
		class CommunicationControl
		Description: Assign collector group to application policy.

		:param collectorGroups:  Specifies the collector groups whose collector reported the events. 
		:param forceAssign: Indicates whether to force the assignment even if the group is assigned to similar policies. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param policyName: Specifies the list of policies. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/comm-control/assign-collector-group'
		url_params = []
		if collectorGroups:
			url_params.append('collectorGroups=' + collectorGroups)
		if forceAssign:
			url_params.append('forceAssign=' + forceAssign)
		if organization:
			url_params.append('organization=' + organization)
		if policyName:
			url_params.append('policyName=' + policyName)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)


	def clone_policy(self, newPolicyName : str, sourcePolicyName : str, organization :str = None) -> tuple[bool, None]:

		'''
		class CommunicationControl
		Description: application clone policy.

		:param newPolicyName: Specifies security policy target name.. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param sourcePolicyName: Specifies security policy source name. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
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


	def list_policies(self, decisions : dict, itemsPerPage :int = None, organization :str = None, pageNumber :int = None, policies :dict = None, rules :dict = None, sorting :str = None, sources :dict = None, state :str = None, strictMode :bool = None) -> tuple[bool, dict]:

		'''
		class CommunicationControl
		Description: This API call outputs a list of all the communication control policies in the system, and information about each of them.

		:param decisions: Indicates the action. 
		:param itemsPerPage: An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param pageNumber: An integer used for paging that indicates the required page number. 
		:param policies: Specifies the list of policy names. 
		:param rules: Specifies the list of rules. 
		:param sorting: Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on. 
		:param sources: Specifies who created the policy. 
		:param state: Policy rule state. 
		:param strictMode: A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False. 

		return: 
			Status of the request (True or False). 
			dict

		'''
		url = '/management-rest/comm-control/list-policies'
		url_params = []
		if decisions:
			url_params.append('decisions=' + decisions)
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if organization:
			url_params.append('organization=' + organization)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if policies:
			url_params.append('policies=' + policies)
		if rules:
			url_params.append('rules=' + rules)
		if sorting:
			url_params.append('sorting=' + sorting)
		if sources:
			url_params.append('sources=' + sources)
		if state:
			url_params.append('state=' + state)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)


	def list_products(self, action :str = None, collectorGroups :dict = None, cveIdentifier :str = None, destinationIp :dict = None, devices :dict = None, firstConnectionTimeEnd :str = None, firstConnectionTimeStart :str = None, handled :bool = None, includeStatistics :bool = None, ips :dict = None, itemsPerPage :int = None, lastConnectionTimeEnd :str = None, lastConnectionTimeStart :str = None, organization :str = None, os :dict = None, pageNumber :int = None, policies :dict = None, processHash :str = None, processes :dict = None, product :str = None, products :dict = None, reputation :dict = None, rule :str = None, rulePolicy :str = None, seen :bool = None, sorting :str = None, strictMode :bool = None, vendor :str = None, vendors :dict = None, version :str = None, versions :dict = None, vulnerabilities :dict = None) -> tuple[bool, dict]:

		'''
		class CommunicationControl
		Description: This API call outputs a list of all the communicating applications in the system, and information about each of them.

		:param action: Indicates the action: Allow/Deny. This parameter is irrelevant without policies parameter. 
		:param collectorGroups: Specifies the list of collector groups where the products were seen. 
		:param cveIdentifier: Specifies the CVE identifier. 
		:param destinationIp: Destination IPs. 
		:param devices: Specifies the list of device names where the products were seen. 
		:param firstConnectionTimeEnd:  Retrieves products whose first connection time is less than the value assigned to this date. 
		:param firstConnectionTimeStart:  Retrieves products whose first connection time is greater than the value assigned to this date. 
		:param handled: A true/false parameter indicating whether events were handled/unhandled. 
		:param includeStatistics: A true/false parameter indicating including statistics data. 
		:param ips: Specifies the list of IPs where the products were seen. 
		:param itemsPerPage: An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000. 
		:param lastConnectionTimeEnd:  Retrieves products whose last connection time is less than the value assigned to this date. 
		:param lastConnectionTimeStart:  Retrieves products whose last connection time is greater than the value assigned to this date. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param os: Specifies the list of operating system families where the products were seen. 
		:param pageNumber: An integer used for paging that indicates the required page number. 
		:param policies: Specifies the list of policy names whose products have a specific decision, as specified in the action parameter. 
		:param processHash: Specifies the process hash name. 
		:param processes: Specifies the list of process names running alongside the products. 
		:param product: Specifies a single value for the product name. By default, strictMode is false. 
		:param products: Specifies the list of product names. Names must match exactly (strictMode is always true). 
		:param reputation: Specifies the recommendation of the application: Unknown, Known bad, Assumed bad, Contradiction, Assumed good or Known good. 
		:param rule: Indicates the rule. This parameter is irrelevant without rulePolicy parameter. 
		:param rulePolicy: Specifies the policy name whose products have a specific rule, as specified in the rule parameter. 
		:param seen: A true/false parameter indicating whether events were read/unread by the user operating the API. 
		:param sorting: Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on. 
		:param strictMode: A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False. 
		:param vendor: Specifies a single value for the vendor name. By default, strictMode is false. 
		:param vendors: Specifies the list of vendor names. Names must match exactly (strictMode is always true). 
		:param version: Specifies a single value for the version name. By default, strictMode is false. 
		:param versions: Specifies the list of versions. Names must match exactly (strictMode is always true). 
		:param vulnerabilities: Specifies the list of vulnerabilities where the products were seen. 

		return: 
			Status of the request (True or False). 
			dict

		'''
		url = '/management-rest/comm-control/list-products'
		url_params = []
		if action:
			url_params.append('action=' + action)
		if collectorGroups:
			url_params.append('collectorGroups=' + collectorGroups)
		if cveIdentifier:
			url_params.append('cveIdentifier=' + cveIdentifier)
		if destinationIp:
			url_params.append('destinationIp=' + destinationIp)
		if devices:
			url_params.append('devices=' + devices)
		if firstConnectionTimeEnd:
			url_params.append('firstConnectionTimeEnd=' + firstConnectionTimeEnd)
		if firstConnectionTimeStart:
			url_params.append('firstConnectionTimeStart=' + firstConnectionTimeStart)
		if handled:
			url_params.append('handled=' + handled)
		if includeStatistics:
			url_params.append('includeStatistics=' + includeStatistics)
		if ips:
			url_params.append('ips=' + ips)
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if lastConnectionTimeEnd:
			url_params.append('lastConnectionTimeEnd=' + lastConnectionTimeEnd)
		if lastConnectionTimeStart:
			url_params.append('lastConnectionTimeStart=' + lastConnectionTimeStart)
		if organization:
			url_params.append('organization=' + organization)
		if os:
			url_params.append('os=' + os)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if policies:
			url_params.append('policies=' + policies)
		if processHash:
			url_params.append('processHash=' + processHash)
		if processes:
			url_params.append('processes=' + processes)
		if product:
			url_params.append('product=' + product)
		if products:
			url_params.append('products=' + products)
		if reputation:
			url_params.append('reputation=' + reputation)
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
			url_params.append('vendors=' + vendors)
		if version:
			url_params.append('version=' + version)
		if versions:
			url_params.append('versions=' + versions)
		if vulnerabilities:
			url_params.append('vulnerabilities=' + vulnerabilities)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)


	def resolve_applications(self, applyNested :bool = None, comment :str = None, organization :str = None, products :dict = None, resolve :bool = None, signed :bool = None, vendors :dict = None, versions :dict = None) -> tuple[bool, None]:

		'''
		class CommunicationControl
		Description: Enable resolving/unresolving applications.

		:param applyNested: A true/false parameter indicating updating inherited. 
		:param comment: Specifies a user-defined string to attach to the policy. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param products: Specifies the list of product names. Names must match exactly (strictMode is always true). 
		:param resolve: A true/false parameter indicating update the application resolve/unresolve. 
		:param signed: A true/false parameter indicating if the policy is signed. 
		:param vendors: Specifies the list of vendor names. Names must match exactly (strictMode is always true). 
		:param versions: Specifies the list of versions. Names must match exactly (strictMode is always true). 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/comm-control/resolve-applications'
		url_params = []
		if applyNested:
			url_params.append('applyNested=' + applyNested)
		if comment:
			url_params.append('comment=' + comment)
		if organization:
			url_params.append('organization=' + organization)
		if products:
			url_params.append('products=' + products)
		if resolve:
			url_params.append('resolve=' + resolve)
		if signed:
			url_params.append('signed=' + signed)
		if vendors:
			url_params.append('vendors=' + vendors)
		if versions:
			url_params.append('versions=' + versions)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)


	def set_policy_mode(self, mode : str, policyNames : dict, organization :str = None) -> tuple[bool, None]:

		'''
		class CommunicationControl
		Description: Set policy to simulation/prevention.

		:param mode: Operation mode. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param policyNames: Specifies the list of policies. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/comm-control/set-policy-mode'
		url_params = []
		if mode:
			url_params.append('mode=' + mode)
		if organization:
			url_params.append('organization=' + organization)
		if policyNames:
			url_params.append('policyNames=' + policyNames)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)


	def set_policy_permission(self, decision : str, policies : dict, applyNested :bool = None, organization :str = None, products :dict = None, signed :bool = None, vendors :dict = None, versions :dict = None) -> tuple[bool, None]:

		'''
		class CommunicationControl
		Description: Set the application allow/deny.

		:param applyNested: A true/false parameter indicating updating inherited. 
		:param decision: Indicates the action. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param policies: Specifies the list of policies names. 
		:param products: Specifies the list of product names. Names must match exactly (strictMode is always true). 
		:param signed: A true/false parameter indicating if the policy is signed. 
		:param vendors: Specifies the list of vendor names. Names must match exactly (strictMode is always true). 
		:param versions: Specifies the list of versions. Names must match exactly (strictMode is always true). 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/comm-control/set-policy-permission'
		url_params = []
		if applyNested:
			url_params.append('applyNested=' + applyNested)
		if decision:
			url_params.append('decision=' + decision)
		if organization:
			url_params.append('organization=' + organization)
		if policies:
			url_params.append('policies=' + policies)
		if products:
			url_params.append('products=' + products)
		if signed:
			url_params.append('signed=' + signed)
		if vendors:
			url_params.append('vendors=' + vendors)
		if versions:
			url_params.append('versions=' + versions)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)


	def set_policy_rule_state(self, policyName : str, ruleName : str, state : str, organization :str = None) -> tuple[bool, None]:

		'''
		class CommunicationControl
		Description: Set rule in policy to enable/disable.

		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param policyName: Specifies policy name. 
		:param ruleName: Specifies rule name. 
		:param state: Policy rule state. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
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

	def insert_events(self, actions :dict = None, archived :bool = None, classifications :dict = None, collectorGroups :dict = None, destinations :dict = None, device :str = None, deviceControl :bool = None, deviceIps :dict = None, eventIds :dict = None, eventType :dict = None, expired :bool = None, fileHash :str = None, firstSeen :str = None, firstSeenFrom :str = None, firstSeenTo :str = None, handled :bool = None, itemsPerPage :int = None, lastSeen :str = None, lastSeenFrom :str = None, lastSeenTo :str = None, loggedUser :str = None, macAddresses :dict = None, muted :bool = None, operatingSystems :dict = None, organization :str = None, pageNumber :int = None, paths :dict = None, process :str = None, rule :str = None, seen :bool = None, severities :dict = None, signed :bool = None, sorting :str = None, strictMode :bool = None, archive: bool = None, classification: str = None, comment: str = None, familyName: str = None, forceUnmute: bool = None, handle: bool = None, malwareType: str = None, mute: bool = None, muteDuration: str = None, read: bool = None, threatName: str = None) -> tuple[bool, None]:

		'''
		class Events
		Description: This API call updates the read/unread, handled/unhandled or archived/unarchived state of an event. The output of this call is a message indicating whether the update succeeded or failed.

		:param actions: Specifies the action of the event. 
		:param archived: A true/false parameter indicating whether to include only archived events. 
		:param classifications: Specifies the classification of the event. 
		:param collectorGroups: Specifies the collector groups whose collector reported the events. 
		:param destinations: Specifies the connection destination(s) of the events. 
		:param device: Specifies the device name where the events occurred. 
		:param deviceControl: A true/false parameter indicating whether to include only device control events. 
		:param deviceIps: Specifies the IPs of the devices where the event occurred. 
		:param eventIds: Specifies the required event IDs. 
		:param eventType: Specifies the type of the event. 
		:param expired: A true/false parameter indicating whether to include only expired events. 
		:param fileHash: Specifies the hash signature of the main process of the event. 
		:param firstSeen:  Specifies the date when the event was first seen (Deprecated). 
		:param firstSeenFrom: Specifies the from date when the event was first seen. 
		:param firstSeenTo: Specifies the to date when the event was first seen. 
		:param handled:  A true/false parameter indicating whether events were handled/unhandled. 
		:param itemsPerPage: An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000. 
		:param lastSeen:  Specifies the date when the event was last seen (Deprecated). 
		:param lastSeenFrom: Specifies the from date when the event was last seen. 
		:param lastSeenTo: Specifies the to date when the event was last seen. 
		:param loggedUser: Specifies the logged user. 
		:param macAddresses: Specifies the mac addresses where the event occurred. 
		:param muted: A true/false parameter indicating if the event is muted. 
		:param operatingSystems: Specifies the operating system of the devices where the events occurred. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 
		:param pageNumber: An integer used for paging that indicates the required page number. 
		:param paths: Specifies the paths of the processes related to the event. 
		:param process: Specifies the main process of the event. 
		:param rule: Specifies the short rule name of the rule that triggered the events. 
		:param seen: A true/false parameter indicating whether events were read/unread by the user operating the API. 
		:param severities: Specifies the severity of the event (Deprecated). 
		:param signed: A true/false parameter indicating if the event is signed. 
		:param sorting: Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on. 
		:param strictMode: A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False. 
		:param updateEventsRequest: updateEventsRequest. 
		:param archive: A true/false parameter indicating whether to update archived events. 
		:param classification: Specifies the event classification. 
		:param comment: Specifies a user-defined string attached to the event. 
		:param familyName: Specifies the event family name. 
		:param forceUnmute: Indicates whether to force archive even if the event is muted. 
		:param handle: A true/false parameter indicating update the events handled/unhandled. 
		:param malwareType: Specifies the event malware type. 
		:param mute: A true/false parameter indicating whether to mute events. 
		:param muteDuration: Specifies the mute duration time. 
		:param read: A true/false parameter indicating whether the events are read/unread by the user operating the API. 
		:param threatName: Specifies the event threat name. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/events'
		url_params = []
		if actions:
			url_params.append('actions=' + actions)
		if archived:
			url_params.append('archived=' + archived)
		if classifications:
			url_params.append('classifications=' + classifications)
		if collectorGroups:
			url_params.append('collectorGroups=' + collectorGroups)
		if destinations:
			url_params.append('destinations=' + destinations)
		if device:
			url_params.append('device=' + device)
		if deviceControl:
			url_params.append('deviceControl=' + deviceControl)
		if deviceIps:
			url_params.append('deviceIps=' + deviceIps)
		if eventIds:
			url_params.append('eventIds=' + eventIds)
		if eventType:
			url_params.append('eventType=' + eventType)
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
			url_params.append('macAddresses=' + macAddresses)
		if muted:
			url_params.append('muted=' + muted)
		if operatingSystems:
			url_params.append('operatingSystems=' + operatingSystems)
		if organization:
			url_params.append('organization=' + organization)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if paths:
			url_params.append('paths=' + paths)
		if process:
			url_params.append('process=' + process)
		if rule:
			url_params.append('rule=' + rule)
		if seen:
			url_params.append('seen=' + seen)
		if severities:
			url_params.append('severities=' + severities)
		if signed:
			url_params.append('signed=' + signed)
		if sorting:
			url_params.append('sorting=' + sorting)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		url += '?' + '&'.join(url_params)
		updateEventsRequest = {
			'archive': archive,
			'classification': classification,
			'comment': comment,
			'familyName': familyName,
			'forceUnmute': forceUnmute,
			'handle': handle,
			'malwareType': malwareType,
			'mute': mute,
			'muteDuration': muteDuration,
			'read': read,
			'threatName': threatName
		}
		return fortiedr_connection.insert(url, updateEventsRequest)

	def delete_events(self, actions :dict = None, archived :bool = None, classifications :dict = None, collectorGroups :dict = None, deleteAll :bool = None, destinations :dict = None, device :str = None, deviceControl :bool = None, deviceIps :dict = None, eventIds :dict = None, eventType :dict = None, expired :bool = None, fileHash :str = None, firstSeen :str = None, firstSeenFrom :str = None, firstSeenTo :str = None, handled :bool = None, itemsPerPage :int = None, lastSeen :str = None, lastSeenFrom :str = None, lastSeenTo :str = None, loggedUser :str = None, macAddresses :dict = None, muted :bool = None, operatingSystems :dict = None, organization :str = None, pageNumber :int = None, paths :dict = None, process :str = None, rule :str = None, seen :bool = None, severities :dict = None, signed :bool = None, sorting :str = None, strictMode :bool = None) -> tuple[bool, None]:

		'''
		class Events
		Description: This API call updates the read/unread, handled/unhandled or archived/unarchived state of an event. The output of this call is a message indicating whether the update succeeded or failed.

		:param actions: Specifies the action of the event. 
		:param archived: A true/false parameter indicating whether to include only archived events. 
		:param classifications: Specifies the classification of the event. 
		:param collectorGroups: Specifies the collector groups whose collector reported the events. 
		:param deleteAll: A true/false parameter indicating if all events should be deleted. 
		:param destinations: Specifies the connection destination(s) of the events. 
		:param device: Specifies the device name where the events occurred. 
		:param deviceControl: A true/false parameter indicating whether to include only device control events. 
		:param deviceIps: Specifies the IPs of the devices where the event occurred. 
		:param eventIds: Specifies the required event IDs. 
		:param eventType: Specifies the type of the event. 
		:param expired: A true/false parameter indicating whether to include only expired events. 
		:param fileHash: Specifies the hash signature of the main process of the event. 
		:param firstSeen:  Specifies the date when the event was first seen (Deprecated). 
		:param firstSeenFrom: Specifies the from date when the event was first seen. 
		:param firstSeenTo: Specifies the to date when the event was first seen. 
		:param handled:  A true/false parameter indicating whether events were handled/unhandled. 
		:param itemsPerPage: An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000. 
		:param lastSeen:  Specifies the date when the event was last seen (Deprecated). 
		:param lastSeenFrom: Specifies the from date when the event was last seen. 
		:param lastSeenTo: Specifies the to date when the event was last seen. 
		:param loggedUser: Specifies the logged user. 
		:param macAddresses: Specifies the mac addresses where the event occurred. 
		:param muted: A true/false parameter indicating if the event is muted. 
		:param operatingSystems: Specifies the operating system of the devices where the events occurred. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 
		:param pageNumber: An integer used for paging that indicates the required page number. 
		:param paths: Specifies the paths of the processes related to the event. 
		:param process: Specifies the main process of the event. 
		:param rule: Specifies the short rule name of the rule that triggered the events. 
		:param seen: A true/false parameter indicating whether events were read/unread by the user operating the API. 
		:param severities: Specifies the severity of the event (Deprecated). 
		:param signed: A true/false parameter indicating if the event is signed. 
		:param sorting: Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on. 
		:param strictMode: A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/events'
		url_params = []
		if actions:
			url_params.append('actions=' + actions)
		if archived:
			url_params.append('archived=' + archived)
		if classifications:
			url_params.append('classifications=' + classifications)
		if collectorGroups:
			url_params.append('collectorGroups=' + collectorGroups)
		if deleteAll:
			url_params.append('deleteAll=' + deleteAll)
		if destinations:
			url_params.append('destinations=' + destinations)
		if device:
			url_params.append('device=' + device)
		if deviceControl:
			url_params.append('deviceControl=' + deviceControl)
		if deviceIps:
			url_params.append('deviceIps=' + deviceIps)
		if eventIds:
			url_params.append('eventIds=' + eventIds)
		if eventType:
			url_params.append('eventType=' + eventType)
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
			url_params.append('macAddresses=' + macAddresses)
		if muted:
			url_params.append('muted=' + muted)
		if operatingSystems:
			url_params.append('operatingSystems=' + operatingSystems)
		if organization:
			url_params.append('organization=' + organization)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if paths:
			url_params.append('paths=' + paths)
		if process:
			url_params.append('process=' + process)
		if rule:
			url_params.append('rule=' + rule)
		if seen:
			url_params.append('seen=' + seen)
		if severities:
			url_params.append('severities=' + severities)
		if signed:
			url_params.append('signed=' + signed)
		if sorting:
			url_params.append('sorting=' + sorting)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)


	def count_events(self, actions :dict = None, archived :bool = None, classifications :dict = None, collectorGroups :dict = None, destinations :dict = None, device :str = None, deviceControl :bool = None, deviceIps :dict = None, eventIds :dict = None, eventType :dict = None, expired :bool = None, fileHash :str = None, firstSeen :str = None, firstSeenFrom :str = None, firstSeenTo :str = None, handled :bool = None, itemsPerPage :int = None, lastSeen :str = None, lastSeenFrom :str = None, lastSeenTo :str = None, loggedUser :str = None, macAddresses :dict = None, muted :bool = None, operatingSystems :dict = None, organization :str = None, pageNumber :int = None, paths :dict = None, process :str = None, rule :str = None, seen :bool = None, severities :dict = None, signed :bool = None, sorting :str = None, strictMode :bool = None) -> tuple[bool, int]:

		'''
		class Events
		Description: Count Events.

		:param actions: Specifies the action of the event. 
		:param archived: A true/false parameter indicating whether to include only archived events. 
		:param classifications: Specifies the classification of the event. 
		:param collectorGroups: Specifies the collector groups whose collector reported the events. 
		:param destinations: Specifies the connection destination(s) of the events. 
		:param device: Specifies the device name where the events occurred. 
		:param deviceControl: A true/false parameter indicating whether to include only device control events. 
		:param deviceIps: Specifies the IPs of the devices where the event occurred. 
		:param eventIds: Specifies the required event IDs. 
		:param eventType: Specifies the type of the event. 
		:param expired: A true/false parameter indicating whether to include only expired events. 
		:param fileHash: Specifies the hash signature of the main process of the event. 
		:param firstSeen:  Specifies the date when the event was first seen (Deprecated). 
		:param firstSeenFrom: Specifies the from date when the event was first seen. 
		:param firstSeenTo: Specifies the to date when the event was first seen. 
		:param handled:  A true/false parameter indicating whether events were handled/unhandled. 
		:param itemsPerPage: An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000. 
		:param lastSeen:  Specifies the date when the event was last seen (Deprecated). 
		:param lastSeenFrom: Specifies the from date when the event was last seen. 
		:param lastSeenTo: Specifies the to date when the event was last seen. 
		:param loggedUser: Specifies the logged user. 
		:param macAddresses: Specifies the mac addresses where the event occurred. 
		:param muted: A true/false parameter indicating if the event is muted. 
		:param operatingSystems: Specifies the operating system of the devices where the events occurred. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 
		:param pageNumber: An integer used for paging that indicates the required page number. 
		:param paths: Specifies the paths of the processes related to the event. 
		:param process: Specifies the main process of the event. 
		:param rule: Specifies the short rule name of the rule that triggered the events. 
		:param seen: A true/false parameter indicating whether events were read/unread by the user operating the API. 
		:param severities: Specifies the severity of the event (Deprecated). 
		:param signed: A true/false parameter indicating if the event is signed. 
		:param sorting: Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on. 
		:param strictMode: A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False. 

		return: 
			Status of the request (True or False). 
			int

		'''
		url = '/management-rest/events/count-events'
		url_params = []
		if actions:
			url_params.append('actions=' + actions)
		if archived:
			url_params.append('archived=' + archived)
		if classifications:
			url_params.append('classifications=' + classifications)
		if collectorGroups:
			url_params.append('collectorGroups=' + collectorGroups)
		if destinations:
			url_params.append('destinations=' + destinations)
		if device:
			url_params.append('device=' + device)
		if deviceControl:
			url_params.append('deviceControl=' + deviceControl)
		if deviceIps:
			url_params.append('deviceIps=' + deviceIps)
		if eventIds:
			url_params.append('eventIds=' + eventIds)
		if eventType:
			url_params.append('eventType=' + eventType)
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
			url_params.append('macAddresses=' + macAddresses)
		if muted:
			url_params.append('muted=' + muted)
		if operatingSystems:
			url_params.append('operatingSystems=' + operatingSystems)
		if organization:
			url_params.append('organization=' + organization)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if paths:
			url_params.append('paths=' + paths)
		if process:
			url_params.append('process=' + process)
		if rule:
			url_params.append('rule=' + rule)
		if seen:
			url_params.append('seen=' + seen)
		if severities:
			url_params.append('severities=' + severities)
		if signed:
			url_params.append('signed=' + signed)
		if sorting:
			url_params.append('sorting=' + sorting)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)


	def create_exception(self, allCollectorGroups :bool = None, allDestinations :bool = None, allOrganizations :bool = None, allUsers :bool = None, collectorGroups :dict = None, comment :str = None, destinations :dict = None, eventId :int = None, exceptionId :int = None, forceCreate :bool = None, organization :str = None, users :dict = None, useAnyPath: object = None, useInException: object = None, wildcardFiles: object = None, wildcardPaths: object = None) -> tuple[bool, str]:

		'''
		class Events
		Description: This API call adds an exception to a specific event. The output of this call is a message indicating whether the creation of the exception .

		:param allCollectorGroups: A true/false parameter indicating whether the exception should be applied to all collector groups. When not used, all collector groups are selected. 
		:param allDestinations: A true/false parameter indicating whether the exception should be applied to all destinations. When not used, all destinations are selected. 
		:param allOrganizations: A true/false parameter indicating whether the exception should be applied to all the organizations (tenants). This parameter is only relevant in multi-tenancy environment. This parameter is only allowed for user with Hoster privilege (general admin). 
		:param allUsers: A true/false parameter indicating whether the exception should be applied to all users. When not used, all users are selected. 
		:param collectorGroups: Specifies the list of all the collector groups to which the exception should be applied. When not used, all collector groups are selected. 
		:param comment: Specifies a user-defined string to attach to the exception. 
		:param destinations: A list of IPs to which the exception applies and/or the value all internal destinations. 
		:param eventId: Specifies the event ID on which to create the exception. 
		:param exceptionId: Specifies the exception ID to edit. 
		:param exceptionRequest: exceptionRequest. 
		:param useAnyPath: For each relevant process in each relevant rule, the user must indicate true/false to set an exception on the path that was seen in the event or for any path. 
		:param useInException: For each relevant process in each relevant rule, the user must indicate true/false in order to include it in the exception. 
		:param wildcardFiles: For each relevant process in each relevant rule filename, check if pattern matches the file value, and according to action (true/false) attach/remove the exception wildcard field. 
		:param wildcardPaths: For each relevant process in each relevant rule path name, check if pattern matches the file value, and according to action (true/false) attach/remove the exception wildcard field. 
		:param forceCreate: A true/false parameter indicating whether to create the exception, even if there are already exceptions that cover this given event. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param users: A list of users to which the exception. 

		return: 
			Status of the request (True or False). 
			str

		'''
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
			url_params.append('collectorGroups=' + collectorGroups)
		if comment:
			url_params.append('comment=' + comment)
		if destinations:
			url_params.append('destinations=' + destinations)
		if eventId:
			url_params.append('eventId=' + eventId)
		if exceptionId:
			url_params.append('exceptionId=' + exceptionId)
		if forceCreate:
			url_params.append('forceCreate=' + forceCreate)
		if organization:
			url_params.append('organization=' + organization)
		if users:
			url_params.append('users=' + users)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.send(url)


	def export_raw_data_items_json(self, organization :str = None, rawItemIds :str = None) -> tuple[bool, None]:

		'''
		class Events
		Description: Get event as Json format.

		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param rawItemIds: Specifies the raw data item event IDs. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/events/export-raw-data-items-json'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		if rawItemIds:
			url_params.append('rawItemIds=' + rawItemIds)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.download(url, file_format='json')


	def list_events(self, actions :dict = None, archived :bool = None, classifications :dict = None, collectorGroups :dict = None, destinations :dict = None, device :str = None, deviceControl :bool = None, deviceIps :dict = None, eventIds :dict = None, eventType :dict = None, expired :bool = None, fileHash :str = None, firstSeen :str = None, firstSeenFrom :str = None, firstSeenTo :str = None, handled :bool = None, itemsPerPage :int = None, lastSeen :str = None, lastSeenFrom :str = None, lastSeenTo :str = None, loggedUser :str = None, macAddresses :dict = None, muted :bool = None, operatingSystems :dict = None, organization :str = None, pageNumber :int = None, paths :dict = None, process :str = None, rule :str = None, seen :bool = None, severities :dict = None, signed :bool = None, sorting :str = None, strictMode :bool = None) -> tuple[bool, dict]:

		'''
		class Events
		Description: List Events.

		:param actions: Specifies the action of the event. 
		:param archived: A true/false parameter indicating whether to include only archived events. 
		:param classifications: Specifies the classification of the event. 
		:param collectorGroups: Specifies the collector groups whose collector reported the events. 
		:param destinations: Specifies the connection destination(s) of the events. 
		:param device: Specifies the device name where the events occurred. 
		:param deviceControl: A true/false parameter indicating whether to include only device control events. 
		:param deviceIps: Specifies the IPs of the devices where the event occurred. 
		:param eventIds: Specifies the required event IDs. 
		:param eventType: Specifies the type of the event. 
		:param expired: A true/false parameter indicating whether to include only expired events. 
		:param fileHash: Specifies the hash signature of the main process of the event. 
		:param firstSeen:  Specifies the date when the event was first seen (Deprecated). 
		:param firstSeenFrom: Specifies the from date when the event was first seen. 
		:param firstSeenTo: Specifies the to date when the event was first seen. 
		:param handled:  A true/false parameter indicating whether events were handled/unhandled. 
		:param itemsPerPage: An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000. 
		:param lastSeen:  Specifies the date when the event was last seen (Deprecated). 
		:param lastSeenFrom: Specifies the from date when the event was last seen. 
		:param lastSeenTo: Specifies the to date when the event was last seen. 
		:param loggedUser: Specifies the logged user. 
		:param macAddresses: Specifies the mac addresses where the event occurred. 
		:param muted: A true/false parameter indicating if the event is muted. 
		:param operatingSystems: Specifies the operating system of the devices where the events occurred. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 
		:param pageNumber: An integer used for paging that indicates the required page number. 
		:param paths: Specifies the paths of the processes related to the event. 
		:param process: Specifies the main process of the event. 
		:param rule: Specifies the short rule name of the rule that triggered the events. 
		:param seen: A true/false parameter indicating whether events were read/unread by the user operating the API. 
		:param severities: Specifies the severity of the event (Deprecated). 
		:param signed: A true/false parameter indicating if the event is signed. 
		:param sorting: Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on. 
		:param strictMode: A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False. 

		return: 
			Status of the request (True or False). 
			dict

		'''
		url = '/management-rest/events/list-events'
		url_params = []
		if actions:
			url_params.append('actions=' + actions)
		if archived:
			url_params.append('archived=' + archived)
		if classifications:
			url_params.append('classifications=' + classifications)
		if collectorGroups:
			url_params.append('collectorGroups=' + collectorGroups)
		if destinations:
			url_params.append('destinations=' + destinations)
		if device:
			url_params.append('device=' + device)
		if deviceControl:
			url_params.append('deviceControl=' + deviceControl)
		if deviceIps:
			url_params.append('deviceIps=' + deviceIps)
		if eventIds:
			url_params.append('eventIds=' + eventIds)
		if eventType:
			url_params.append('eventType=' + eventType)
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
			url_params.append('macAddresses=' + macAddresses)
		if muted:
			url_params.append('muted=' + muted)
		if operatingSystems:
			url_params.append('operatingSystems=' + operatingSystems)
		if organization:
			url_params.append('organization=' + organization)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if paths:
			url_params.append('paths=' + paths)
		if process:
			url_params.append('process=' + process)
		if rule:
			url_params.append('rule=' + rule)
		if seen:
			url_params.append('seen=' + seen)
		if severities:
			url_params.append('severities=' + severities)
		if signed:
			url_params.append('signed=' + signed)
		if sorting:
			url_params.append('sorting=' + sorting)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)


	def list_raw_data_items(self, eventId : int, collectorGroups :dict = None, destinations :dict = None, device :str = None, deviceIps :dict = None, firstSeen :str = None, firstSeenFrom :str = None, firstSeenTo :str = None, fullDataRequested :bool = None, itemsPerPage :int = None, lastSeen :str = None, lastSeenFrom :str = None, lastSeenTo :str = None, loggedUser :str = None, organization :str = None, pageNumber :int = None, rawEventIds :dict = None, sorting :str = None, strictMode :bool = None) -> tuple[bool, dict]:

		'''
		class Events
		Description: List raw data items.

		:param collectorGroups: Specifies the collector groups whose collector reported the raw events. 
		:param destinations: Specifies the connection destination(s) of the events. 
		:param device: Specifies the name of the device where the raw event occurred. 
		:param deviceIps: Specifies the IPs of the devices where the event occurred. 
		:param eventId: Specifies the ID of the event that holds the raw data items. 
		:param firstSeen: Specifies the date when the raw data item was first seen (Deprecated). 
		:param firstSeenFrom: Specifies the from date when the raw data item was first seen. 
		:param firstSeenTo: Specifies the to date when the raw data item was first seen. 
		:param fullDataRequested: A true/false parameter indicating whether to include the event internal information. 
		:param itemsPerPage: An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000. 
		:param lastSeen: Specifies the date when the raw data item was last seen (Deprecated). 
		:param lastSeenFrom: Specifies the from date when the raw data item was last seen. 
		:param lastSeenTo: Specifies the to date when the raw data item was last seen. 
		:param loggedUser: Specifies the logged user. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param pageNumber: An integer used for paging that indicates the required page number. 
		:param rawEventIds: Specifies the list of raw data item event IDs. 
		:param sorting: Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on. 
		:param strictMode: A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False. 

		return: 
			Status of the request (True or False). 
			dict

		'''
		url = '/management-rest/events/list-raw-data-items'
		url_params = []
		if collectorGroups:
			url_params.append('collectorGroups=' + collectorGroups)
		if destinations:
			url_params.append('destinations=' + destinations)
		if device:
			url_params.append('device=' + device)
		if deviceIps:
			url_params.append('deviceIps=' + deviceIps)
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
			url_params.append('rawEventIds=' + rawEventIds)
		if sorting:
			url_params.append('sorting=' + sorting)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

class Exceptions:

	def create_or_edit_exception(self, confirmEdit :bool = None, exceptionJSON :str = None, organization :str = None) -> tuple[bool, int]:

		'''
		class Exceptions
		Description: This API call creates a new exception or updates an existing exception based on the given exception JSON body parameter.

		:param confirmEdit: Confirm editing an existing exception in case of providing an exception ID in the body JSON. By default confirmEdit is false. 
		:param exceptionJSON: exceptionJSON. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 

		return: 
			Status of the request (True or False). 
			int

		'''
		url = '/management-rest/exceptions/create-or-edit-exception'
		url_params = []
		if confirmEdit:
			url_params.append('confirmEdit=' + confirmEdit)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.send(url)


	def delete(self, collectorGroups :dict = None, comment :str = None, createdAfter :str = None, createdBefore :str = None, deleteAll :bool = None, destination :str = None, exceptionId :int = None, exceptionIds :dict = None, organization :str = None, path :str = None, process :str = None, rules :dict = None, updatedAfter :str = None, updatedBefore :str = None, user :str = None) -> tuple[bool, None]:

		'''
		class Exceptions
		Description: Delete exceptions.

		:param collectorGroups: Specifies the list of all the collector groups to which the exception applied. 
		:param comment: Specifies a comment attach to the exception. 
		:param createdAfter: Specifies the date after which the exception was created. Specify the date using the yyyy-MM-dd HH:mm:ss format. 
		:param createdBefore: Specifies the date before which the exception was created. Specify the date using the yyyy-MM-dd HH:mm:ss format. 
		:param deleteAll: A true/false parameter indicating if all exception should be deleted. 
		:param destination: Specifies a destination IP of the exception. 
		:param exceptionId: Specifies the required exception ID. 
		:param exceptionIds: Specifies a list of exception ids. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 
		:param path: Specifies the path of the exception. 
		:param process: Specifies the process of the exception. 
		:param rules: Specifies a list of rule names. 
		:param updatedAfter: Specifies the date after which the exception was updated. Specify the date using the yyyy-MM-dd HH:mm:ss format. 
		:param updatedBefore: Specifies the date before which the exception was updated. Specify the date using the yyyy-MM-dd HH:mm:ss format. 
		:param user: Specifies a user of the exception. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/exceptions/delete'
		url_params = []
		if collectorGroups:
			url_params.append('collectorGroups=' + collectorGroups)
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
			url_params.append('exceptionIds=' + exceptionIds)
		if organization:
			url_params.append('organization=' + organization)
		if path:
			url_params.append('path=' + path)
		if process:
			url_params.append('process=' + process)
		if rules:
			url_params.append('rules=' + rules)
		if updatedAfter:
			url_params.append('updatedAfter=' + updatedAfter)
		if updatedBefore:
			url_params.append('updatedBefore=' + updatedBefore)
		if user:
			url_params.append('user=' + user)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)


	def get_event_exceptions(self, eventId : int, organization :str = None) -> tuple[bool, dict]:

		'''
		class Exceptions
		Description: Show exceptions.

		:param eventId: Specifies the required event ID. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 

		return: 
			Status of the request (True or False). 
			dict

		'''
		url = '/management-rest/exceptions/get-event-exceptions'
		url_params = []
		if eventId:
			url_params.append('eventId=' + eventId)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)


	def list_exceptions(self, collectorGroups :dict = None, comment :str = None, createdAfter :str = None, createdBefore :str = None, destination :str = None, exceptionIds :dict = None, organization :str = None, path :str = None, process :str = None, rules :dict = None, updatedAfter :str = None, updatedBefore :str = None, user :str = None) -> tuple[bool, dict]:

		'''
		class Exceptions
		Description: List of exceptions.

		:param collectorGroups: Specifies the list of all the collector groups to which the exception applied. 
		:param comment: Specifies a comment attach to the exception. 
		:param createdAfter: Specifies the date after which the exception was created. Specify the date using the yyyy-MM-dd HH:mm:ss format. 
		:param createdBefore: Specifies the date before which the exception was created. Specify the date using the yyyy-MM-dd HH:mm:ss format. 
		:param destination: Specifies a destination IP of the exception. 
		:param exceptionIds: Specifies a list of exception ids. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 
		:param path: Specifies the path of the exception. 
		:param process: Specifies the process of the exception. 
		:param rules: Specifies a list of rule names. 
		:param updatedAfter: Specifies the date after which the exception was updated. Specify the date using the yyyy-MM-dd HH:mm:ss format. 
		:param updatedBefore: Specifies the date before which the exception was updated. Specify the date using the yyyy-MM-dd HH:mm:ss format. 
		:param user: Specifies a user of the exception. 

		return: 
			Status of the request (True or False). 
			dict

		'''
		url = '/management-rest/exceptions/list-exceptions'
		url_params = []
		if collectorGroups:
			url_params.append('collectorGroups=' + collectorGroups)
		if comment:
			url_params.append('comment=' + comment)
		if createdAfter:
			url_params.append('createdAfter=' + createdAfter)
		if createdBefore:
			url_params.append('createdBefore=' + createdBefore)
		if destination:
			url_params.append('destination=' + destination)
		if exceptionIds:
			url_params.append('exceptionIds=' + exceptionIds)
		if organization:
			url_params.append('organization=' + organization)
		if path:
			url_params.append('path=' + path)
		if process:
			url_params.append('process=' + process)
		if rules:
			url_params.append('rules=' + rules)
		if updatedAfter:
			url_params.append('updatedAfter=' + updatedAfter)
		if updatedBefore:
			url_params.append('updatedBefore=' + updatedBefore)
		if user:
			url_params.append('user=' + user)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

class Forensics:

	def get_event_file(self, rawEventId : int, disk :bool = None, endRange :str = None, filePaths :dict = None, memory :bool = None, organization :str = None, processId :int = None, startRange :str = None) -> tuple[bool, None]:

		'''
		class Forensics
		Description: This API call retrieves a file or memory.

		:param disk: A true/false parameter indicating whether find in the disk. 
		:param endRange: Specifies the memory end range, in Hexadecimal format. 
		:param filePaths: Specifies the list of file paths. 
		:param memory: A true/false parameter indicating whether find in the memory. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param processId: Specifies the ID of the process from which to take a memory image. required for memory base action. 
		:param rawEventId: Specifies the ID of the raw event on which to perform the memory retrieval. 
		:param startRange: Specifies the memory start range, in Hexadecimal format. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/forensics/get-event-file'
		url_params = []
		if disk:
			url_params.append('disk=' + disk)
		if endRange:
			url_params.append('endRange=' + endRange)
		if filePaths:
			url_params.append('filePaths=' + filePaths)
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
		return fortiedr_connection.download(url)


	def get_file(self, device : str, filePaths : dict, type : str, organization :str = None) -> tuple[bool, None]:

		'''
		class Forensics
		Description: This API call retrieves a file or memory.

		:param device: Specifies the name or id of the device to remediate. 
		:param filePaths: Specifies the list of file paths. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param type: Specifies the device parameter type used in the request : Name or ID. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/forensics/get-file'
		url_params = []
		if device:
			url_params.append('device=' + device)
		if filePaths:
			url_params.append('filePaths=' + filePaths)
		if organization:
			url_params.append('organization=' + organization)
		if type:
			url_params.append('type=' + type)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.download(url)


	def remediate_device(self, terminatedProcessId : int, device :str = None, deviceId :int = None, executablesToRemove :dict = None, organization :str = None, persistenceDataAction :str = None, persistenceDataNewContent :str = None, persistenceDataPath :str = None, persistenceDataValueName :str = None, persistenceDataValueNewType :str = None, processName :str = None, threadId :int = None) -> tuple[bool, None]:

		'''
		class Forensics
		Description: This API kill process / delete file / clean persistence, File and persistence paths must be specified in a logical format.

		:param device: Specifies the name of the device to remediate. You must specify a value for either device or deviceId (see below). 
		:param deviceId: Specifies the unique identifier (ID) of the device to remediate. You must specify a value for either deviceId or device (see above). 
		:param executablesToRemove: Specifies the list of full paths of executable files (*.exe) to delete on thegiven device. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param persistenceDataAction: persistence data desired action. 
		:param persistenceDataNewContent: persistence data new content. 
		:param persistenceDataPath: persistence data path. 
		:param persistenceDataValueName: persistence data value name. 
		:param persistenceDataValueNewType: persistence data value new type. 
		:param processName: Specifies the process name. 
		:param terminatedProcessId: Represents the process ID to terminate on the device. 
		:param threadId: Specifies the thread ID. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/forensics/remediate-device'
		url_params = []
		if device:
			url_params.append('device=' + device)
		if deviceId:
			url_params.append('deviceId=' + deviceId)
		if executablesToRemove:
			url_params.append('executablesToRemove=' + executablesToRemove)
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

	def search(self, fileHashes : dict, organization :str = None) -> tuple[bool, None]:

		'''
		class HashSearch
		Description: This API enables the user to search a file hash among the current events, threat hunting repository and communicating applications that exist in the system.

		:param fileHashes: Specifies the list of files hashes. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/hash/search'
		url_params = []
		if fileHashes:
			url_params.append('fileHashes=' + fileHashes)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

class IPsets:

	def create_ip_set(self, include: dict, name: str, description: str = None, exclude: dict = None, organization: str = None) -> tuple[bool, None]:

		'''
		class IPsets
		Description: This API create IP sets in the system.
	Use the input parameter organization=All organizations to create for all the organization. (only for Admin role.

		:param ipGroupsRequest: ipGroupsRequest. 
		:param description: Specifies the IP set description. 
		:param exclude: List of IPs, ranges and mask that excluded in the IP set. 
		:param include: Specifies List of IPs, ranges and mask that included in the IP set. 
		:param name: Specifies the IP set name. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non-shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies: ��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly. ��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations. ��� each ��� Indicates that the operation applies independently to each organization. For example, let's assume that the same user exists in multiple organizations. When each is specified in the organization parameter, then each organization can update this user separately.. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/ip-sets/create-ip-set'
		url_params = []
		url += '?' + '&'.join(url_params)
		ipGroupsRequest = {
			'description': description,
			'exclude': exclude,
			'include': include,
			'name': name,
			'organization': organization
		}
		return fortiedr_connection.send(url, ipGroupsRequest)


	def delete_ip_set(self, ipSets : dict, organization :str = None) -> tuple[bool, None]:

		'''
		class IPsets
		Description: This API delete IP sets from the system. Use the input parameters to filter organization.

		:param ipSets: Specifies the list of IP name to delete. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/ip-sets/delete-ip-set'
		url_params = []
		if ipSets:
			url_params.append('ipSets=' + ipSets)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)


	def list_ip_sets(self, ip :str = None, organization :str = None) -> tuple[bool, dict]:

		'''
		class IPsets
		Description: This API call outputs a list of the IP sets in the system. Use the input parameters to filter the list.

		:param ip: Specifies the IP of the requested sets. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 

		return: 
			Status of the request (True or False). 
			dict

		'''
		url = '/management-rest/ip-sets/list-ip-sets'
		url_params = []
		if ip:
			url_params.append('ip=' + ip)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)


	def update_ip_set(self, include: dict, name: str, organization :str = None, description: str = None, exclude: dict = None) -> tuple[bool, None]:

		'''
		class IPsets
		Description: This API update IP sets in the system. Use the input parameters to filter organization.

		:param ipGroupsRequest: ipGroupsRequest. 
		:param description: Specifies the IP set description. 
		:param exclude: List of IPs, ranges and mask that excluded in the IP set. 
		:param include: Specifies List of IPs, ranges and mask that included in the IP set. 
		:param name: Specifies the IP set name. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non-shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.��� each ��� Indicates that the operation applies independently to each organization. For example, let's assume that the same user exists in multiple organizations. When each is specified in the organization parameter, then each organization can update this user separately.. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/ip-sets/update-ip-set'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

class Integrations:

	def connectors_metadata(self, organization :str = None) -> tuple[bool, None]:

		'''
		class Integrations
		Description: Get connectors metadata, describing the valid values for connector fields definition and on-premise cores..

		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/integrations/connectors-metadata'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)


	def create_connector(self, connectorActions: dict, enabled: bool, host: str, name: str, organization: str, port: str, type: str, vendor: str, apiKey: str = None, coreId: int = None, password: str = None, username: str = None) -> tuple[bool, None]:

		'''
		class Integrations
		Description: Creates a new connector. Please note: Creation of Custom connectors/actions is not yet support..

		:param createConnectorRequest: createConnectorRequest. 
		:param apiKey: Specifies the connector's API key (API key authentication mode). Should be empty if username and passwords are used.. 
		:param connectorActions: Specifies the connector's actions' definition. Use connectors-metadata API for supported values. 
		:param coreId: Specifies the ID of the connector's on-premise core. 
		:param enabled: Specifies whether or not the connector is enabled.. Example: enabled=True.
		:param host: Specifies the connector host address.. Example: host=127.0.0.1.
		:param name: Specifies the connector name.. Example: name=Connector Name.
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param password: Specifies the connector's user's password (credentials authentication mode). Should be empty if apiKey is used.. 
		:param port: Specifies the connector port.. Example: port=443.
		:param type: Specifies the connector type. See /connectors-metadata for valid types.. Example: type=Firewall.
		:param username: Specifies the connector's user's username (credentials authentication mode). Should be empty if apiKey is used.. 
		:param vendor: Specifies the connector's vendor. See /connectors-metadata for valid values.. Example: vendor=FortiGate.

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/integrations/create-connector'
		url_params = []
		url += '?' + '&'.join(url_params)
		createConnectorRequest = {
			'apiKey': apiKey,
			'connectorActions': connectorActions,
			'coreId': coreId,
			'enabled': enabled,
			'host': host,
			'name': name,
			'organization': organization,
			'password': password,
			'port': port,
			'type': type,
			'username': username,
			'vendor': vendor
		}
		return fortiedr_connection.send(url, createConnectorRequest)


	def delete_connector(self, connectorName : str, connectorType : str, organization :str = None) -> tuple[bool, None]:

		'''
		class Integrations
		Description: Deletes a connector.

		:param connectorName: Specifies the connector's name (case sensitive). 
		:param connectorType: Specifies the connector's type.. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
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


	def list_connectors(self, onlyValidConnectors :bool = None, organization :str = None) -> tuple[bool, dict]:

		'''
		class Integrations
		Description: List all organization connectors.

		:param onlyValidConnectors: Set to true to retrieve enabled, non-failing connectors.. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 

		return: 
			Status of the request (True or False). 
			dict

		'''
		url = '/management-rest/integrations/list-connectors'
		url_params = []
		if onlyValidConnectors:
			url_params.append('onlyValidConnectors=' + onlyValidConnectors)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)


	def test_connector(self, connectorName : str, connectorType : str, organization :str = None) -> tuple[bool, None]:

		'''
		class Integrations
		Description: Tests a connector.

		:param connectorName: Specifies the connector's name (case sensitive). 
		:param connectorType: Specifies the connector's type.. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
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


	def update_connector(self, connectorActions: dict, enabled: bool, host: str, name: str, organization: str, port: str, type: str, vendor: str, apiKey: str = None, coreId: int = None, password: str = None, username: str = None) -> tuple[bool, None]:

		'''
		class Integrations
		Description: Updates an existing connector based on (name, type, organization). Please note: Modification of Custom connectors/actions is not yet support..

		:param updateConnectorRequest: updateConnectorRequest. 
		:param apiKey: Specifies the connector's API key (API key authentication mode). Should be empty if username and passwords are used.. 
		:param connectorActions: Specifies the connector's actions' definition. Use connectors-metadata API for supported values. 
		:param coreId: Specifies the ID of the connector's on-premise core. 
		:param enabled: Specifies whether or not the connector is enabled.. Example: enabled=True.
		:param host: Specifies the connector host address.. Example: host=127.0.0.1.
		:param name: Specifies the connector name.. Example: name=Connector Name.
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param password: Specifies the connector's user's password (credentials authentication mode). Should be empty if apiKey is used.. 
		:param port: Specifies the connector port.. Example: port=443.
		:param type: Specifies the connector type. See /connectors-metadata for valid types.. Example: type=Firewall.
		:param username: Specifies the connector's user's username (credentials authentication mode). Should be empty if apiKey is used.. 
		:param vendor: Specifies the connector's vendor. See /connectors-metadata for valid values.. Example: vendor=FortiGate.

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/integrations/update-connector'
		url_params = []
		url += '?' + '&'.join(url_params)
		updateConnectorRequest = {
			'apiKey': apiKey,
			'connectorActions': connectorActions,
			'coreId': coreId,
			'enabled': enabled,
			'host': host,
			'name': name,
			'organization': organization,
			'password': password,
			'port': port,
			'type': type,
			'username': username,
			'vendor': vendor
		}
		return fortiedr_connection.insert(url, updateConnectorRequest)

class IoT:

	def create_iot_group(self, name : str, organization :str = None) -> tuple[bool, None]:

		'''
		class IoT
		Description: This API call create IoT group.

		:param name: IoT group name. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/iot/create-iot-group'
		url_params = []
		if name:
			url_params.append('name=' + name)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.send(url)


	def delete_devices(self, categories :dict = None, devices :dict = None, devicesIds :dict = None, firstSeenEnd :str = None, firstSeenStart :str = None, internalIps :dict = None, iotGroups :dict = None, iotGroupsIds :dict = None, itemsPerPage :int = None, lastSeenEnd :str = None, lastSeenStart :str = None, locations :dict = None, macAddresses :dict = None, models :dict = None, organization :str = None, pageNumber :int = None, showExpired :bool = None, sorting :str = None, strictMode :bool = None, vendors :dict = None) -> tuple[bool, None]:

		'''
		class IoT
		Description: This API call deletes a IoT device(s).

		:param categories: Specifies the list of categories values. 
		:param devices: Specifies the list of device names. 
		:param devicesIds: Specifies the list of device ids. 
		:param firstSeenEnd: Retrieves IoT devices that were first seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss. 
		:param firstSeenStart: Retrieves IoT devices that were first seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss. 
		:param internalIps: Specifies the list of IP values. 
		:param iotGroups: Specifies the list of collector group names and retrieves collectors under the given groups. 
		:param iotGroupsIds: Specifies the list of collector group ids and retrieves collectors under the given groups. 
		:param itemsPerPage: An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000. 
		:param lastSeenEnd: Retrieves IoT devices that were last seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss. 
		:param lastSeenStart: Retrieves IoT devices that were last seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss. 
		:param locations: Specifies the list of locations values. 
		:param macAddresses: Specifies the list of mac address values. 
		:param models: Specifies the list of models values. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 
		:param pageNumber: An integer used for paging that indicates the required page number. 
		:param showExpired: Specifies whether to include IoT devices which have been disconnected for more than 3 days (sequentially) and are marked as Expired. 
		:param sorting: Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on. 
		:param strictMode: A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False. 
		:param vendors: Specifies the list of vendors values. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/iot/delete-devices'
		url_params = []
		if categories:
			url_params.append('categories=' + categories)
		if devices:
			url_params.append('devices=' + devices)
		if devicesIds:
			url_params.append('devicesIds=' + devicesIds)
		if firstSeenEnd:
			url_params.append('firstSeenEnd=' + firstSeenEnd)
		if firstSeenStart:
			url_params.append('firstSeenStart=' + firstSeenStart)
		if internalIps:
			url_params.append('internalIps=' + internalIps)
		if iotGroups:
			url_params.append('iotGroups=' + iotGroups)
		if iotGroupsIds:
			url_params.append('iotGroupsIds=' + iotGroupsIds)
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if lastSeenEnd:
			url_params.append('lastSeenEnd=' + lastSeenEnd)
		if lastSeenStart:
			url_params.append('lastSeenStart=' + lastSeenStart)
		if locations:
			url_params.append('locations=' + locations)
		if macAddresses:
			url_params.append('macAddresses=' + macAddresses)
		if models:
			url_params.append('models=' + models)
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
			url_params.append('vendors=' + vendors)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)


	def export_iot_json(self, iotDeviceIds : dict, organization :str = None) -> tuple[bool, None]:

		'''
		class IoT
		Description: This API call outputs a list of the IoT devices info.

		:param iotDeviceIds: Specifies the list of device ids. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/iot/export-iot-json'
		url_params = []
		if iotDeviceIds:
			url_params.append('iotDeviceIds=' + iotDeviceIds)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)


	def list_iot_devices(self, categories :dict = None, devices :dict = None, devicesIds :dict = None, firstSeenEnd :str = None, firstSeenStart :str = None, internalIps :dict = None, iotGroups :dict = None, iotGroupsIds :dict = None, itemsPerPage :int = None, lastSeenEnd :str = None, lastSeenStart :str = None, locations :dict = None, macAddresses :dict = None, models :dict = None, organization :str = None, pageNumber :int = None, showExpired :bool = None, sorting :str = None, strictMode :bool = None, vendors :dict = None) -> tuple[bool, dict]:

		'''
		class IoT
		Description: This API call outputs a list of the IoT devices in the system. Use the input parameters to filter the list.

		:param categories: Specifies the list of categories values. 
		:param devices: Specifies the list of device names. 
		:param devicesIds: Specifies the list of device ids. 
		:param firstSeenEnd: Retrieves IoT devices that were first seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss. 
		:param firstSeenStart: Retrieves IoT devices that were first seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss. 
		:param internalIps: Specifies the list of IP values. 
		:param iotGroups: Specifies the list of collector group names and retrieves collectors under the given groups. 
		:param iotGroupsIds: Specifies the list of collector group ids and retrieves collectors under the given groups. 
		:param itemsPerPage: An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000. 
		:param lastSeenEnd: Retrieves IoT devices that were last seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss. 
		:param lastSeenStart: Retrieves IoT devices that were last seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss. 
		:param locations: Specifies the list of locations values. 
		:param macAddresses: Specifies the list of mac address values. 
		:param models: Specifies the list of models values. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 
		:param pageNumber: An integer used for paging that indicates the required page number. 
		:param showExpired: Specifies whether to include IoT devices which have been disconnected for more than 3 days (sequentially) and are marked as Expired. 
		:param sorting: Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on. 
		:param strictMode: A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False. 
		:param vendors: Specifies the list of vendors values. 

		return: 
			Status of the request (True or False). 
			dict

		'''
		url = '/management-rest/iot/list-iot-devices'
		url_params = []
		if categories:
			url_params.append('categories=' + categories)
		if devices:
			url_params.append('devices=' + devices)
		if devicesIds:
			url_params.append('devicesIds=' + devicesIds)
		if firstSeenEnd:
			url_params.append('firstSeenEnd=' + firstSeenEnd)
		if firstSeenStart:
			url_params.append('firstSeenStart=' + firstSeenStart)
		if internalIps:
			url_params.append('internalIps=' + internalIps)
		if iotGroups:
			url_params.append('iotGroups=' + iotGroups)
		if iotGroupsIds:
			url_params.append('iotGroupsIds=' + iotGroupsIds)
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if lastSeenEnd:
			url_params.append('lastSeenEnd=' + lastSeenEnd)
		if lastSeenStart:
			url_params.append('lastSeenStart=' + lastSeenStart)
		if locations:
			url_params.append('locations=' + locations)
		if macAddresses:
			url_params.append('macAddresses=' + macAddresses)
		if models:
			url_params.append('models=' + models)
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
			url_params.append('vendors=' + vendors)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)


	def list_iot_groups(self, organization :str = None) -> tuple[bool, dict]:

		'''
		class IoT
		Description: This API call output the IoT devices groups.

		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 

		return: 
			Status of the request (True or False). 
			dict

		'''
		url = '/management-rest/iot/list-iot-groups'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)


	def move_iot_devices(self, iotDeviceIds : dict, targetIotGroup : str, organization :str = None) -> tuple[bool, None]:

		'''
		class IoT
		Description: This API call move IoT devices between groups.

		:param iotDeviceIds: Array of IoT device ids. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param targetIotGroup: IoT target group name. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/iot/move-iot-devices'
		url_params = []
		if iotDeviceIds:
			url_params.append('iotDeviceIds=' + iotDeviceIds)
		if organization:
			url_params.append('organization=' + organization)
		if targetIotGroup:
			url_params.append('targetIotGroup=' + targetIotGroup)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)


	def rescan_iot_device_details(self, categories :dict = None, devices :dict = None, devicesIds :dict = None, firstSeenEnd :str = None, firstSeenStart :str = None, internalIps :dict = None, iotGroups :dict = None, iotGroupsIds :dict = None, itemsPerPage :int = None, lastSeenEnd :str = None, lastSeenStart :str = None, locations :dict = None, macAddresses :dict = None, models :dict = None, organization :str = None, pageNumber :int = None, showExpired :bool = None, sorting :str = None, strictMode :bool = None, vendors :dict = None) -> tuple[bool, str]:

		'''
		class IoT
		Description: This API call device details scan on IoT device(s).

		:param categories: Specifies the list of categories values. 
		:param devices: Specifies the list of device names. 
		:param devicesIds: Specifies the list of device ids. 
		:param firstSeenEnd: Retrieves IoT devices that were first seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss. 
		:param firstSeenStart: Retrieves IoT devices that were first seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss. 
		:param internalIps: Specifies the list of IP values. 
		:param iotGroups: Specifies the list of collector group names and retrieves collectors under the given groups. 
		:param iotGroupsIds: Specifies the list of collector group ids and retrieves collectors under the given groups. 
		:param itemsPerPage: An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000. 
		:param lastSeenEnd: Retrieves IoT devices that were last seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss. 
		:param lastSeenStart: Retrieves IoT devices that were last seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss. 
		:param locations: Specifies the list of locations values. 
		:param macAddresses: Specifies the list of mac address values. 
		:param models: Specifies the list of models values. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 
		:param pageNumber: An integer used for paging that indicates the required page number. 
		:param showExpired: Specifies whether to include IoT devices which have been disconnected for more than 3 days (sequentially) and are marked as Expired. 
		:param sorting: Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on. 
		:param strictMode: A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False. 
		:param vendors: Specifies the list of vendors values. 

		return: 
			Status of the request (True or False). 
			str

		'''
		url = '/management-rest/iot/rescan-iot-device-details'
		url_params = []
		if categories:
			url_params.append('categories=' + categories)
		if devices:
			url_params.append('devices=' + devices)
		if devicesIds:
			url_params.append('devicesIds=' + devicesIds)
		if firstSeenEnd:
			url_params.append('firstSeenEnd=' + firstSeenEnd)
		if firstSeenStart:
			url_params.append('firstSeenStart=' + firstSeenStart)
		if internalIps:
			url_params.append('internalIps=' + internalIps)
		if iotGroups:
			url_params.append('iotGroups=' + iotGroups)
		if iotGroupsIds:
			url_params.append('iotGroupsIds=' + iotGroupsIds)
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if lastSeenEnd:
			url_params.append('lastSeenEnd=' + lastSeenEnd)
		if lastSeenStart:
			url_params.append('lastSeenStart=' + lastSeenStart)
		if locations:
			url_params.append('locations=' + locations)
		if macAddresses:
			url_params.append('macAddresses=' + macAddresses)
		if models:
			url_params.append('models=' + models)
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
			url_params.append('vendors=' + vendors)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

class Organizations:

	def create_organization(self, expirationDate: str, name: str, password: str, passwordConfirmation: str, eXtendedDetection: bool = None, edr: bool = None, edrAddOnsAllocated: int = None, edrBackupEnabled: bool = None, edrEnabled: bool = None, edrNumberOfShards: int = None, edrStorageAllocatedInMb: int = None, forensics: bool = None, iotAllocated: int = None, requestPolicyEngineLibUpdates: bool = None, serialNumber: str = None, serversAllocated: int = None, vulnerabilityAndIoT: bool = None, workstationsAllocated: int = None) -> tuple[bool, None]:

		'''
		class Organizations
		Description: This API creates organization in the system (only for Admin role).

		:param createAccountRequest: createAccountRequest. 
		:param eXtendedDetection: A true/false parameter indication if the eXtended Detection is enabled for the organization. 
		:param edr: A true/false parameter indicating whether the organization support Threat Hunting. 
		:param edrAddOnsAllocated: Specifies the EDR storage add-ons allocated to this account. 
		:param edrBackupEnabled: A true/false parameter indication if the EDR backup is enabled for the organization. 
		:param edrEnabled: A true/false parameter indication if the EDR is enabled for the organization. 
		:param edrNumberOfShards: Specifies the EDR shards per index, should be above 1 only for very large environments. 
		:param edrStorageAllocatedInMb: Specifies the EDR storage allocation in MB, used when edrStorageAllocatedPercents is empty. 
		:param expirationDate: Specifies the license expiration date. Specify the date using the following date format yyyy-MM-dd. 
		:param forensics: A true/false parameter indicating whether the organization support Forensics. 
		:param iotAllocated: Specifies the IoT device���s license capacity. 
		:param name: Specifies the organization name. 
		:param password: Specifies the device registration password name. 
		:param passwordConfirmation: Specifies the confirm device registration password name. 
		:param requestPolicyEngineLibUpdates: A true/false parameter indicating whether the organization collectors should request for policy engine lib updates. 
		:param serialNumber: Specifies the serial number. 
		:param serversAllocated: Specifies the server collector���s license capacity. 
		:param vulnerabilityAndIoT: A true/false parameter indicating whether the organization support Vulnerability And IoT. 
		:param workstationsAllocated: Specifies the workstation collector���s license capacity. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/organizations/create-organization'
		url_params = []
		url += '?' + '&'.join(url_params)
		createAccountRequest = {
			'eXtendedDetection': eXtendedDetection,
			'edr': edr,
			'edrAddOnsAllocated': edrAddOnsAllocated,
			'edrBackupEnabled': edrBackupEnabled,
			'edrEnabled': edrEnabled,
			'edrNumberOfShards': edrNumberOfShards,
			'edrStorageAllocatedInMb': edrStorageAllocatedInMb,
			'expirationDate': expirationDate,
			'forensics': forensics,
			'iotAllocated': iotAllocated,
			'name': name,
			'password': password,
			'passwordConfirmation': passwordConfirmation,
			'requestPolicyEngineLibUpdates': requestPolicyEngineLibUpdates,
			'serialNumber': serialNumber,
			'serversAllocated': serversAllocated,
			'vulnerabilityAndIoT': vulnerabilityAndIoT,
			'workstationsAllocated': workstationsAllocated
		}
		return fortiedr_connection.send(url, createAccountRequest)


	def delete_organization(self, organization :str = None) -> tuple[bool, None]:

		'''
		class Organizations
		Description: This API delete organization in the system (only for Admin role).

		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/organizations/delete-organization'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)


	def export_organization(self, destinationName :str = None, organization :str = None) -> tuple[bool, None]:

		'''
		class Organizations
		Description: Export organization data as zip file.

		:param destinationName: The organization destination name. 
		:param organization: Organization to export. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/organizations/export-organization'
		url_params = []
		if destinationName:
			url_params.append('destinationName=' + destinationName)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.download(url)


	def import_organization(self, file :BinaryIO = None) -> tuple[bool, None]:

		'''
		class Organizations
		Description: Import organization.

		:param file: Export zip file. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/organizations/import-organization'
		url_params = []
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.send(url)


	def list_organizations(self) -> tuple[bool, dict]:

		'''
		class Organizations
		Description: This API call outputs a list of the accounts in the system..

		:param file: Export zip file. 

		'''
		url = '/management-rest/organizations/list-organizations'
		return fortiedr_connection.get(url)


	def transfer_collectors(self, aggregatorsMap: dict, sourceOrganization: str, targetOrganization: str, verificationCode: str) -> tuple[bool, None]:

		'''
		class Organizations
		Description: Transfer collectors from aggregator to aggregator as the organization migration process.

		:param transferCollectorRequests: transferCollectorRequests. 
		:param aggregatorsMap: Specifies aggregators transfer mapping. 
		:param sourceOrganization: Specifies the organization which collectors will be transferred from.. 
		:param targetOrganization: Specifies the organization which collectors will be transferred to.. 
		:param verificationCode: Specifies the verification code to validate the import step was finished successfully.. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/organizations/transfer-collectors'
		url_params = []
		url += '?' + '&'.join(url_params)
		transferCollectorRequests = {
			'aggregatorsMap': aggregatorsMap,
			'sourceOrganization': sourceOrganization,
			'targetOrganization': targetOrganization,
			'verificationCode': verificationCode
		}
		return fortiedr_connection.send(url, transferCollectorRequests)


	def transfer_collectors_stop(self, organization :str = None) -> tuple[bool, None]:

		'''
		class Organizations
		Description: Transfer collector stop.

		:param organization: Specifies the organization which the migration process should stop. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/organizations/transfer-collectors-stop'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.send(url)


	def update_organization(self, organization :str = None, eXtendedDetection: bool = None, edr: bool = None, edrAddOnsAllocated: int = None, edrBackupEnabled: bool = None, edrEnabled: bool = None, edrNumberOfShards: int = None, edrStorageAllocatedInMb: int = None, expirationDate: str = None, forensics: bool = None, iotAllocated: int = None, name: str = None, requestPolicyEngineLibUpdates: bool = None, serialNumber: str = None, serversAllocated: int = None, vulnerabilityAndIoT: bool = None, workstationsAllocated: int = None) -> tuple[bool, None]:

		'''
		class Organizations
		Description: This API update organization in the system (only for Admin role).

		:param accountRequest: accountRequest. 
		:param eXtendedDetection: A true/false parameter indication if the eXtended Detection is enabled for the organization. 
		:param edr: A true/false parameter indicating whether the organization support Threat Hunting. 
		:param edrAddOnsAllocated: Specifies the EDR storage add-ons allocated to this account. 
		:param edrBackupEnabled: A true/false parameter indication if the EDR backup is enabled for the organization. 
		:param edrEnabled: A true/false parameter indication if the EDR is enabled for the organization. 
		:param edrNumberOfShards: Specifies the EDR shards per index, should be above 1 only for very large environments. 
		:param edrStorageAllocatedInMb: Specifies the EDR storage allocation in MB, used when edrStorageAllocatedPercents is empty. 
		:param expirationDate: Specifies the license expiration date. Specify the date using the following date format yyyy-MM-dd. 
		:param forensics: A true/false parameter indicating whether the organization support Forensics. 
		:param iotAllocated: Specifies the IoT device���s license capacity. 
		:param name: Specifies the organization name. 
		:param requestPolicyEngineLibUpdates: A true/false parameter indicating whether the organization collectors should request for policy engine lib updates. 
		:param serialNumber: Specifies the serial number. 
		:param serversAllocated: Specifies the server collector���s license capacity. 
		:param vulnerabilityAndIoT: A true/false parameter indicating whether the organization support Vulnerability And IoT. 
		:param workstationsAllocated: Specifies the workstation collector���s license capacity. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/organizations/update-organization'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

class Playbookspolicies:

	def assign_collector_group(self, collectorGroupNames : dict, policyName : str, forceAssign :bool = None, organization :str = None) -> tuple[bool, None]:

		'''
		class Playbookspolicies
		Description: Assign collector group to air policy.

		:param collectorGroupNames: Specifies the list of collector group names. 
		:param forceAssign: Indicates whether to force the assignment even if the group is assigned to similar policies. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param policyName: Specifies policy name. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/playbooks-policies/assign-collector-group'
		url_params = []
		if collectorGroupNames:
			url_params.append('collectorGroupNames=' + collectorGroupNames)
		if forceAssign:
			url_params.append('forceAssign=' + forceAssign)
		if organization:
			url_params.append('organization=' + organization)
		if policyName:
			url_params.append('policyName=' + policyName)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)


	def clone(self, newPolicyName : str, sourcePolicyName : str, organization :str = None) -> tuple[bool, None]:

		'''
		class Playbookspolicies
		Description: clone policy.

		:param newPolicyName: Specifies security policy target name.. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param sourcePolicyName: Specifies security policy source name. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
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


	def list_policies(self, organization :str = None) -> tuple[bool, dict]:

		'''
		class Playbookspolicies
		Description: List policies.

		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 

		return: 
			Status of the request (True or False). 
			dict

		'''
		url = '/management-rest/playbooks-policies/list-policies'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)


	def map_connectors_to_actions(self, policyName: str, organization :str = None, customActionsToConnectorsMaps: dict = None, fortinetActionsToConnectorsMaps: dict = None) -> tuple[bool, None]:

		'''
		class Playbookspolicies
		Description: Assign policy actions with connectors..

		:param assignAIRActionsWithConnectorsRequest: assignAIRActionsWithConnectorsRequest. 
		:param customActionsToConnectorsMaps: Specifies which connectors are to be used during a custom action invocation.. 
		:param fortinetActionsToConnectorsMaps: Specifies which connectors are to be used during an Fortinet action invocation.. 
		:param policyName: Specifies the policy name.. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/playbooks-policies/map-connectors-to-actions'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)


	def set_action_classification(self, policyName: str, organization :str = None, customActionsToClassificationMaps: dict = None, fortinetActionsToClassificationMaps: dict = None) -> tuple[bool, None]:

		'''
		class Playbookspolicies
		Description: Set the air policy actions' classifications..

		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param setActionsClassificationRequest: setActionsClassificationRequest. 
		:param customActionsToClassificationMaps: Specifies which custom actions' classifications should be enabled. Missing classifications are disabled.. 
		:param fortinetActionsToClassificationMaps: Specifies which Fortinet actions' classifications should be enabled. Missing classifications are disabled.. 
		:param policyName: Specifies the policy name.. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/playbooks-policies/set-action-classification'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		setActionsClassificationRequest = {
			'customActionsToClassificationMaps': customActionsToClassificationMaps,
			'fortinetActionsToClassificationMaps': fortinetActionsToClassificationMaps,
			'policyName': policyName
		}
		return fortiedr_connection.insert(url, setActionsClassificationRequest)


	def set_mode(self, mode : str, policyName : str, organization :str = None) -> tuple[bool, None]:

		'''
		class Playbookspolicies
		Description: Set playbook to simulation/prevention.

		:param mode: Operation mode. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param policyName: Specifies security policy name. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
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

	def assign_collector_group(self, collectorsGroupName : dict, policyName : str, forceAssign :bool = None, organization :str = None) -> tuple[bool, None]:

		'''
		class Policies
		Description: Assign collector group to policy.

		:param collectorsGroupName: Specifies the list of collector group names. 
		:param forceAssign: Indicates whether to force the assignment even if the group is assigned to similar policies. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param policyName: Specifies security policy name. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/policies/assign-collector-group'
		url_params = []
		if collectorsGroupName:
			url_params.append('collectorsGroupName=' + collectorsGroupName)
		if forceAssign:
			url_params.append('forceAssign=' + forceAssign)
		if organization:
			url_params.append('organization=' + organization)
		if policyName:
			url_params.append('policyName=' + policyName)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)


	def clone(self, newPolicyName : str, sourcePolicyName : str, organization :str = None) -> tuple[bool, None]:

		'''
		class Policies
		Description: clone policy.

		:param newPolicyName: Specifies security policy target name.. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param sourcePolicyName: Specifies security policy source name. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
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


	def list_policies(self, organization :str = None) -> tuple[bool, dict]:

		'''
		class Policies
		Description: List policies.

		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 

		return: 
			Status of the request (True or False). 
			dict

		'''
		url = '/management-rest/policies/list-policies'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)


	def set_mode(self, mode : str, policyName : str, organization :str = None) -> tuple[bool, None]:

		'''
		class Policies
		Description: Set policy to simulation/prevention.

		:param mode: Operation mode. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param policyName: Specifies security policy name. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
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


	def set_policy_rule_action(self, action : str, policyName : str, ruleName : str, organization :str = None) -> tuple[bool, None]:

		'''
		class Policies
		Description: Set rule in policy to block/log.

		:param action: Specifies the policy action. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param policyName: Specifies security policy name. 
		:param ruleName: Specifies rule name. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
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


	def set_policy_rule_state(self, policyName : str, ruleName : str, state : str, organization :str = None) -> tuple[bool, None]:

		'''
		class Policies
		Description: Set rule in policy to enable/disable.

		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param policyName: Specifies security policy name. 
		:param ruleName: Specifies rule name. 
		:param state: Policy rule state. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
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

	def set_mail_format(self, format : str, organization :str = None) -> tuple[bool, None]:

		'''
		class SendableEntities
		Description: set mail format.

		:param format: Specifies email format type. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/sendable-entities/set-mail-format'
		url_params = []
		if format:
			url_params.append('format=' + format)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)


	def syslog(self, host: str, name: str, port: int, protocol: str, syslogFormat: str, organization :str = None, certificateBlob: str = None, privateKeyFile: str = None, privateKeyPassword: str = None, useClientCertificate: bool = None, useSSL: bool = None) -> tuple[bool, None]:

		'''
		class SendableEntities
		Description: This API creates syslog.

		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non-shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� each ��� Indicates that the operation applies independently to each organization. For example, let's assume that the same user exists in multiple organizations. When each is specified in the organization parameter, then each organization can update this user separately.. 
		:param syslogRequest: syslogRequest. 
		:param certificateBlob: Specifies client certificate in Base64. 
		:param host: Specifies the syslog host. 
		:param name: Specifies the syslog name. 
		:param port: Specifies the syslog port. 
		:param privateKeyFile: Specifies client private key in Base64. 
		:param privateKeyPassword: Specifies client private key password. 
		:param protocol: Specifies syslog protocol type. 
		:param syslogFormat: Specifies syslog format type. 
		:param useClientCertificate: Specifies whether use client certificate. False by default. 
		:param useSSL: Specifies whether to use SSL. False by default. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/sendable-entities/syslog'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		syslogRequest = {
			'certificateBlob': certificateBlob,
			'host': host,
			'name': name,
			'port': port,
			'privateKeyFile': privateKeyFile,
			'privateKeyPassword': privateKeyPassword,
			'protocol': protocol,
			'syslogFormat': syslogFormat,
			'useClientCertificate': useClientCertificate,
			'useSSL': useSSL
		}
		return fortiedr_connection.send(url, syslogRequest)

class SystemEvents:

	def list_system_events(self, componentNames :dict = None, componentTypes :dict = None, fromDate :str = None, itemsPerPage :int = None, organization :str = None, pageNumber :int = None, sorting :str = None, strictMode :bool = None, toDate :str = None) -> tuple[bool, dict]:

		'''
		class SystemEvents
		Description: Retrieve system events.

		:param componentNames:  Specifies one or more names. The name is the customer name for license-related system events and the device name for all others events. 
		:param componentTypes: Specifies one or more component type. 
		:param fromDate: Searches for system events that occurred after this date. 
		:param itemsPerPage: An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 
		:param pageNumber: An integer used for paging that indicates the required page number. 
		:param sorting: Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on. 
		:param strictMode: A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False. 
		:param toDate: Searches for system events that occurred before this date. 

		return: 
			Status of the request (True or False). 
			dict

		'''
		url = '/management-rest/system-events/list-system-events'
		url_params = []
		if componentNames:
			url_params.append('componentNames=' + componentNames)
		if componentTypes:
			url_params.append('componentTypes=' + componentTypes)
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

class SystemInventory:

	def aggregator_logs(self, device :str = None, deviceId :int = None, organization :str = None) -> tuple[bool, None]:

		'''
		class SystemInventory
		Description: This API call retrieves a aggregator logs.

		:param device: Specifies the name of the device. 
		:param deviceId: Specifies the ID of the device. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
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


	def collector_logs(self, device :str = None, deviceId :int = None, organization :str = None) -> tuple[bool, None]:

		'''
		class SystemInventory
		Description: This API call retrieves a collector logs.

		:param device: Specifies the name of the device. 
		:param deviceId: Specifies the ID of the device. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
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


	def core_logs(self, device :str = None, deviceId :int = None, organization :str = None) -> tuple[bool, None]:

		'''
		class SystemInventory
		Description: This API call retrieves a core logs.

		:param device: Specifies the name of the device. 
		:param deviceId: Specifies the ID of the device. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
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


	def create_collector_group(self, name : str, organization :str = None) -> tuple[bool, None]:

		'''
		class SystemInventory
		Description: This API call create collector group.

		:param name: Collector group name. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/inventory/create-collector-group'
		url_params = []
		if name:
			url_params.append('name=' + name)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.send(url)


	def delete_collectors(self, collectorGroups :dict = None, confirmDeletion :bool = None, deleteAll :bool = None, devices :dict = None, devicesIds :dict = None, firstSeen :str = None, hasCrashDumps :bool = None, ips :dict = None, itemsPerPage :int = None, lastSeenEnd :str = None, lastSeenStart :str = None, loggedUser :str = None, operatingSystems :dict = None, organization :str = None, osFamilies :dict = None, pageNumber :int = None, showExpired :bool = None, sorting :str = None, states :dict = None, strictMode :bool = None, versions :dict = None) -> tuple[bool, None]:

		'''
		class SystemInventory
		Description: This API call deletes a Collector(s).

		:param collectorGroups: Specifies the list of collector group names and retrieves collectors under thegiven groups. 
		:param confirmDeletion: A true/false parameter indicating if to detach/delete relevant exceptions from Collector groups about to be deleted. 
		:param deleteAll: A true/false parameter indicating if all collectors should be deleted. 
		:param devices: Specifies the list of device names. 
		:param devicesIds: Specifies the list of device ids. 
		:param firstSeen: Retrieves collectors that were first seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss. 
		:param hasCrashDumps: Retrieves collectors that have crash dumps. 
		:param ips: Specifies the list of IP values. 
		:param itemsPerPage: An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000. 
		:param lastSeenEnd: Retrieves collectors that were last seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss. 
		:param lastSeenStart: Retrieves collectors that were last seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss. 
		:param loggedUser: Specifies the user that was logged when the event occurred. 
		:param operatingSystems: Specifies the list of specific operating systems. For example, Windows 7 Pro. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 
		:param osFamilies: Specifies the list of operating system families: Windows, Windows Server or OS X. 
		:param pageNumber: An integer used for paging that indicates the required page number. 
		:param showExpired: Specifies whether to include collectors which have been disconnected for more than 30 days (sequentially) and are marked as Expired. 
		:param sorting: Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on. 
		:param states: Specifies the list of collector states: Running, Disconnected, Disabled, Degraded, Pending Reboot, Isolated, Expired, Migrated or Pending Migration. 
		:param strictMode: A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False. 
		:param versions: Specifies the list of collector versions. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/inventory/delete-collectors'
		url_params = []
		if collectorGroups:
			url_params.append('collectorGroups=' + collectorGroups)
		if confirmDeletion:
			url_params.append('confirmDeletion=' + confirmDeletion)
		if deleteAll:
			url_params.append('deleteAll=' + deleteAll)
		if devices:
			url_params.append('devices=' + devices)
		if devicesIds:
			url_params.append('devicesIds=' + devicesIds)
		if firstSeen:
			url_params.append('firstSeen=' + firstSeen)
		if hasCrashDumps:
			url_params.append('hasCrashDumps=' + hasCrashDumps)
		if ips:
			url_params.append('ips=' + ips)
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if lastSeenEnd:
			url_params.append('lastSeenEnd=' + lastSeenEnd)
		if lastSeenStart:
			url_params.append('lastSeenStart=' + lastSeenStart)
		if loggedUser:
			url_params.append('loggedUser=' + loggedUser)
		if operatingSystems:
			url_params.append('operatingSystems=' + operatingSystems)
		if organization:
			url_params.append('organization=' + organization)
		if osFamilies:
			url_params.append('osFamilies=' + osFamilies)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if showExpired:
			url_params.append('showExpired=' + showExpired)
		if sorting:
			url_params.append('sorting=' + sorting)
		if states:
			url_params.append('states=' + states)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		if versions:
			url_params.append('versions=' + versions)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)


	def isolate_collectors(self, devices :dict = None, devicesIds :dict = None, organization :str = None) -> tuple[bool, None]:

		'''
		class SystemInventory
		Description: This API call isolate collector functionality.

		:param devices: Specifies the list of device names. 
		:param devicesIds: Specifies the list of device ids. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/inventory/isolate-collectors'
		url_params = []
		if devices:
			url_params.append('devices=' + devices)
		if devicesIds:
			url_params.append('devicesIds=' + devicesIds)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)


	def list_aggregators(self, ip :str = None, names :dict = None, organization :str = None, versions :dict = None) -> tuple[bool, dict]:

		'''
		class SystemInventory
		Description: This API call output the list of aggregators.

		:param ip: IP. 
		:param names: List of aggregators names. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 
		:param versions: List of aggregators versions. 

		return: 
			Status of the request (True or False). 
			dict

		'''
		url = '/management-rest/inventory/list-aggregators'
		url_params = []
		if ip:
			url_params.append('ip=' + ip)
		if names:
			url_params.append('names=' + names)
		if organization:
			url_params.append('organization=' + organization)
		if versions:
			url_params.append('versions=' + versions)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)


	def list_collector_groups(self, organization :str = None) -> tuple[bool, dict]:

		'''
		class SystemInventory
		Description: This API call output the collectors groups.

		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 

		return: 
			Status of the request (True or False). 
			dict

		'''
		url = '/management-rest/inventory/list-collector-groups'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)


	def list_collectors(self, collectorGroups :dict = None, devices :dict = None, devicesIds :dict = None, firstSeen :str = None, hasCrashDumps :bool = None, ips :dict = None, itemsPerPage :int = None, lastSeenEnd :str = None, lastSeenStart :str = None, loggedUser :str = None, operatingSystems :dict = None, organization :str = None, osFamilies :dict = None, pageNumber :int = None, showExpired :bool = None, sorting :str = None, states :dict = None, strictMode :bool = None, versions :dict = None) -> tuple[bool, dict]:

		'''
		class SystemInventory
		Description: This API call outputs a list of the Collectors in the system. Use the input parameters to filter the list.

		:param collectorGroups: Specifies the list of collector group names and retrieves collectors under thegiven groups. 
		:param devices: Specifies the list of device names. 
		:param devicesIds: Specifies the list of device ids. 
		:param firstSeen: Retrieves collectors that were first seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss. 
		:param hasCrashDumps: Retrieves collectors that have crash dumps. 
		:param ips: Specifies the list of IP values. 
		:param itemsPerPage: An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000. 
		:param lastSeenEnd: Retrieves collectors that were last seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss. 
		:param lastSeenStart: Retrieves collectors that were last seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss. 
		:param loggedUser: Specifies the user that was logged when the event occurred. 
		:param operatingSystems: Specifies the list of specific operating systems. For example, Windows 7 Pro. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 
		:param osFamilies: Specifies the list of operating system families: Windows, Windows Server or OS X. 
		:param pageNumber: An integer used for paging that indicates the required page number. 
		:param showExpired: Specifies whether to include collectors which have been disconnected for more than 30 days (sequentially) and are marked as Expired. 
		:param sorting: Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on. 
		:param states: Specifies the list of collector states: Running, Disconnected, Disabled, Degraded, Pending Reboot, Isolated, Expired, Migrated or Pending Migration. 
		:param strictMode: A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False. 
		:param versions: Specifies the list of collector versions. 

		return: 
			Status of the request (True or False). 
			dict

		'''
		url = '/management-rest/inventory/list-collectors'
		url_params = []
		if collectorGroups:
			url_params.append('collectorGroups=' + collectorGroups)
		if devices:
			url_params.append('devices=' + devices)
		if devicesIds:
			url_params.append('devicesIds=' + devicesIds)
		if firstSeen:
			url_params.append('firstSeen=' + firstSeen)
		if hasCrashDumps:
			url_params.append('hasCrashDumps=' + hasCrashDumps)
		if ips:
			url_params.append('ips=' + ips)
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if lastSeenEnd:
			url_params.append('lastSeenEnd=' + lastSeenEnd)
		if lastSeenStart:
			url_params.append('lastSeenStart=' + lastSeenStart)
		if loggedUser:
			url_params.append('loggedUser=' + loggedUser)
		if operatingSystems:
			url_params.append('operatingSystems=' + operatingSystems)
		if organization:
			url_params.append('organization=' + organization)
		if osFamilies:
			url_params.append('osFamilies=' + osFamilies)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if showExpired:
			url_params.append('showExpired=' + showExpired)
		if sorting:
			url_params.append('sorting=' + sorting)
		if states:
			url_params.append('states=' + states)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		if versions:
			url_params.append('versions=' + versions)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)


	def list_cores(self, deploymentModes :dict = None, hasCrashDumps :bool = None, ip :str = None, names :dict = None, organization :str = None, versions :dict = None) -> tuple[bool, dict]:

		'''
		class SystemInventory
		Description: This API call output the list of cores.

		:param deploymentModes: List of cores deployments modes. 
		:param hasCrashDumps: Has crash dumps. 
		:param ip: IP. 
		:param names: List of cores names. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 
		:param versions: List of cores versions. 

		return: 
			Status of the request (True or False). 
			dict

		'''
		url = '/management-rest/inventory/list-cores'
		url_params = []
		if deploymentModes:
			url_params.append('deploymentModes=' + deploymentModes)
		if hasCrashDumps:
			url_params.append('hasCrashDumps=' + hasCrashDumps)
		if ip:
			url_params.append('ip=' + ip)
		if names:
			url_params.append('names=' + names)
		if organization:
			url_params.append('organization=' + organization)
		if versions:
			url_params.append('versions=' + versions)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)


	def list_repositories(self) -> tuple[bool, dict]:

		'''
		class SystemInventory
		Description: This API call output the list of repositories (edrs).

		:param deploymentModes: List of cores deployments modes. 
		:param hasCrashDumps: Has crash dumps. 
		:param ip: IP. 
		:param names: List of cores names. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 
		:param versions: List of cores versions. 

		'''
		url = '/management-rest/inventory/list-repositories'
		return fortiedr_connection.get(url)


	def list_unmanaged_devices(self, itemsPerPage :int = None, organization :str = None, pageNumber :int = None, sorting :str = None, strictMode :bool = None) -> tuple[bool, dict]:

		'''
		class SystemInventory
		Description: This API call outputs a list of the unmanaged devices in the system.

		:param itemsPerPage: An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 
		:param pageNumber: An integer used for paging that indicates the required page number. 
		:param sorting: Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on. 
		:param strictMode: A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False. 

		return: 
			Status of the request (True or False). 
			dict

		'''
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


	def move_collectors(self, collectors : dict, targetCollectorGroup : str, forceAssign :bool = None, organization :str = None) -> tuple[bool, None]:

		'''
		class SystemInventory
		Description: This API call move collector between groups.

		:param collectors: Array of collectors names. To move collectors from one organization to another, for each collector please add the organization name before the collector name (<organization-name>\\<collector-name>). 
		:param forceAssign: Indicates whether to force the assignment even if the organization of the target Collector group is under migration. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 
		:param targetCollectorGroup: Collector group. To move collectors from one organization to another, please add the organization name before the target collector group (<organization-name>\\<collector-group-name>). 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/inventory/move-collectors'
		url_params = []
		if collectors:
			url_params.append('collectors=' + collectors)
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
		class SystemInventory
		Description: This API call retrieves a system logs.

		:param collectors: Array of collectors names. To move collectors from one organization to another, for each collector please add the organization name before the collector name (<organization-name>\\<collector-name>). 
		:param forceAssign: Indicates whether to force the assignment even if the organization of the target Collector group is under migration. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 
		:param targetCollectorGroup: Collector group. To move collectors from one organization to another, please add the organization name before the target collector group (<organization-name>\\<collector-group-name>). 

		'''
		url = '/management-rest/inventory/system-logs'
		return fortiedr_connection.get(url)


	def toggle_collectors(self, enable : bool, collectorGroups :dict = None, devices :dict = None, devicesIds :dict = None, firstSeen :str = None, hasCrashDumps :bool = None, ips :dict = None, itemsPerPage :int = None, lastSeenEnd :str = None, lastSeenStart :str = None, loggedUser :str = None, operatingSystems :dict = None, organization :str = None, osFamilies :dict = None, pageNumber :int = None, showExpired :bool = None, sorting :str = None, states :dict = None, strictMode :bool = None, versions :dict = None) -> tuple[bool, str]:

		'''
		class SystemInventory
		Description: This API call enables/disables a Collector(s). You must specify whether the Collector is to be enabled or disabled.

		:param collectorGroups: Specifies the list of collector group names and retrieves collectors under thegiven groups. 
		:param devices: Specifies the list of device names. 
		:param devicesIds: Specifies the list of device ids. 
		:param enable: Toggle enable. 
		:param firstSeen: Retrieves collectors that were first seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss. 
		:param hasCrashDumps: Retrieves collectors that have crash dumps. 
		:param ips: Specifies the list of IP values. 
		:param itemsPerPage: An integer used for paging that indicates the number of collectors to retrieve forthe current page. The default is 100. The maximum value is 1,000. 
		:param lastSeenEnd: Retrieves collectors that were last seen before the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss. 
		:param lastSeenStart: Retrieves collectors that were last seen after the value assigned to this date. Date Format: yyyy-MM-dd HH:mm:ss. 
		:param loggedUser: Specifies the user that was logged when the event occurred. 
		:param operatingSystems: Specifies the list of specific operating systems. For example, Windows 7 Pro. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 
		:param osFamilies: Specifies the list of operating system families: Windows, Windows Server or OS X. 
		:param pageNumber: An integer used for paging that indicates the required page number. 
		:param showExpired: Specifies whether to include collectors which have been disconnected for more than 30 days (sequentially) and are marked as Expired. 
		:param sorting: Specifies a list of strings in JSON format representing the fields by which to sort the results in the following format: %7B"column1":true, "column2":false%7D. True indicates to sort in descending order.Results are sorted by the first field, then by the second field and so on. 
		:param states: Specifies the list of collector states: Running, Disconnected, Disabled, Degraded, Pending Reboot, Isolated, Expired, Migrated or Pending Migration. 
		:param strictMode: A true/false parameter indicating whether to perform strict matching on the search parameters. The default is False. 
		:param versions: Specifies the list of collector versions. 

		return: 
			Status of the request (True or False). 
			str

		'''
		url = '/management-rest/inventory/toggle-collectors'
		url_params = []
		if collectorGroups:
			url_params.append('collectorGroups=' + collectorGroups)
		if devices:
			url_params.append('devices=' + devices)
		if devicesIds:
			url_params.append('devicesIds=' + devicesIds)
		if enable:
			url_params.append('enable=' + enable)
		if firstSeen:
			url_params.append('firstSeen=' + firstSeen)
		if hasCrashDumps:
			url_params.append('hasCrashDumps=' + hasCrashDumps)
		if ips:
			url_params.append('ips=' + ips)
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if lastSeenEnd:
			url_params.append('lastSeenEnd=' + lastSeenEnd)
		if lastSeenStart:
			url_params.append('lastSeenStart=' + lastSeenStart)
		if loggedUser:
			url_params.append('loggedUser=' + loggedUser)
		if operatingSystems:
			url_params.append('operatingSystems=' + operatingSystems)
		if organization:
			url_params.append('organization=' + organization)
		if osFamilies:
			url_params.append('osFamilies=' + osFamilies)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if showExpired:
			url_params.append('showExpired=' + showExpired)
		if sorting:
			url_params.append('sorting=' + sorting)
		if states:
			url_params.append('states=' + states)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		if versions:
			url_params.append('versions=' + versions)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)


	def unisolate_collectors(self, devices :dict = None, devicesIds :dict = None, organization :str = None) -> tuple[bool, None]:

		'''
		class SystemInventory
		Description: This API call isolate collector functionality.

		:param devices: Specifies the list of device names. 
		:param devicesIds: Specifies the list of device ids. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/inventory/unisolate-collectors'
		url_params = []
		if devices:
			url_params.append('devices=' + devices)
		if devicesIds:
			url_params.append('devicesIds=' + devicesIds)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

class ThreatHunting:

	def counts(self, category: str = None, devices: dict = None, filters: dict = None, fromTime: str = None, itemsPerPage: int = None, organization: str = None, pageNumber: int = None, query: str = None, sorting: dict = None, time: str = None, toTime: str = None) -> tuple[bool, None]:

		'''
		class ThreatHunting
		Description: This API call outputs EDR total events for every EDR category.

		:param edrRequest: edrRequest. 
		:param category: Specifies the category name. All is the default value. 
		:param devices: Specifies the devices name list. 
		:param filters: Specifies the filters list that available for the user based on the category selected 2. Specifies filters to add to the query.. 
		:param fromTime: Specifies events start at creation time. Specify the date using the yyyy-MM-dd HH:mm:ss format. The 'time' filed must be 'custom'. 
		:param itemsPerPage: Specifies the Threat Hunting chunck size to retrieve with each call. The default value is 100. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies: ��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly. ��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 
		:param pageNumber: Specifies the Threat Hunting start index number to retrieve from. The default value is 0. 
		:param query: Specifies the search lucene like query. 
		:param sorting: Specifies the Threat Hunting sorting. 
		:param time: Specifies the time period of the events. 
		:param toTime: Specifies events up to a creation time. Specify the date using the yyyy-MM-dd HH:mm:ss format. The 'time' filed must be 'custom'. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/threat-hunting/counts'
		url_params = []
		url += '?' + '&'.join(url_params)
		edrRequest = {
			'category': category,
			'devices': devices,
			'filters': filters,
			'fromTime': fromTime,
			'itemsPerPage': itemsPerPage,
			'organization': organization,
			'pageNumber': pageNumber,
			'query': query,
			'sorting': sorting,
			'time': time,
			'toTime': toTime
		}
		return fortiedr_connection.send(url, edrRequest)


	def create_or_edit_tag(self, newTagName: str, organization: str = None, tagId: int = None, tagName: str = None) -> tuple[bool, None]:

		'''
		class ThreatHunting
		Description: This API creates or edits the saved queries tag.

		:param createOrEditTagRequest: createOrEditTagRequest. 
		:param newTagName: Specifies the new tag name. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies: ��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly. ��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 
		:param tagId: Specifies the tag ID for editing.. 
		:param tagName: Specifies the tag name for editing.. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/threat-hunting/create-or-edit-tag'
		url_params = []
		url += '?' + '&'.join(url_params)
		createOrEditTagRequest = {
			'newTagName': newTagName,
			'organization': organization,
			'tagId': tagId,
			'tagName': tagName
		}
		return fortiedr_connection.send(url, createOrEditTagRequest)


	def customize_fortinet_query(self, id :int = None, queryToEdit :str = None, dayOfMonth: int = None, dayOfWeek: int = None, forceSaving: bool = None, frequency: int = None, frequencyUnit: str = None, fromTime: str = None, hour: int = None, organization: str = None, scheduled: bool = None, state: bool = None, time: str = None, toTime: str = None) -> tuple[bool, None]:

		'''
		class ThreatHunting
		Description: This API customizes the scheduling properties of a Fortinet query.

		:param id: Specifies the query ID to edit. 
		:param ootbQueryCustomizeRequest: ootbQueryCustomizeRequest. 
		:param dayOfMonth: Specifies the day of the month for the scheduled query. The value must be between 1 and 28. The properties scheduled and frequencyUnit must be true and Month respectively. 
		:param dayOfWeek: Specifies the day of the week for the scheduled query. The value must be between 0 and 6. 0 is Sunday and 6 is Saturday. The properties scheduled and frequencyUnit must be true and Week respectively. 
		:param forceSaving: A true/false parameter indicating whether to force the save, even when there is a large quantity of query results. 
		:param frequency: Specifies the query frequency for the scheduled query. The scheduled property must be true. 
		:param frequencyUnit: Specifies the query frequency unit. The scheduled property must be true. 
		:param fromTime: Specifies events starting from this creation time. Specify the timestamp using the yyyy-MM-dd HH:mm:ss format. The 'time' value must be 'custom'. 
		:param hour: Specifies the hour of the week for the scheduled query. The value must be between 0 and 23. The properties scheduled and frequencyUnit must be true and Day/Week/Month respectively. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param scheduled: Specifies whether the query is scheduled. False by default. 
		:param state: A true/false parameter indicating whether the query state is enabled. True by default. 
		:param time: Specifies the time period of the Threat Hunting events. The scheduled property must be false. 
		:param toTime: Specifies events up to a creation time. Specify the date using the yyyy-MM-dd HH:mm:ss format. The 'time' filed must be 'custom'. 
		:param queryToEdit: Specifies the query name to edit. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/threat-hunting/customize-fortinet-query'
		url_params = []
		if id:
			url_params.append('id=' + id)
		if queryToEdit:
			url_params.append('queryToEdit=' + queryToEdit)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.send(url)


	def delete_saved_queries(self, deleteAll :bool = None, deleteFromCommunity :bool = None, organization :str = None, queryIds :dict = None, queryNames :dict = None, scheduled :bool = None, source :dict = None) -> tuple[bool, None]:

		'''
		class ThreatHunting
		Description: This API deletes the saved queries.

		:param deleteAll: A true/false parameter indicating whether all queries should be deleted. False by default. 
		:param deleteFromCommunity: A true/false parameter indicating if whether to delete a query from the FortiEDR Community also. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 
		:param queryIds: Specifies the query IDs list. 
		:param queryNames: Specifies the query names list. 
		:param scheduled: A true/false parameter indicating whether the query is scheduled. 
		:param source: Specifies the query source list. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/threat-hunting/delete-saved-queries'
		url_params = []
		if deleteAll:
			url_params.append('deleteAll=' + deleteAll)
		if deleteFromCommunity:
			url_params.append('deleteFromCommunity=' + deleteFromCommunity)
		if organization:
			url_params.append('organization=' + organization)
		if queryIds:
			url_params.append('queryIds=' + queryIds)
		if queryNames:
			url_params.append('queryNames=' + queryNames)
		if scheduled:
			url_params.append('scheduled=' + scheduled)
		if source:
			url_params.append('source=' + source)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)


	def delete_tags(self, organization :str = None, tagIds :dict = None, tagNames :dict = None) -> tuple[bool, None]:

		'''
		class ThreatHunting
		Description: This API deletes the saved queries tags.

		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 
		:param tagIds: Specifies the tag ID list. 
		:param tagNames: Specifies the tag name list. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/threat-hunting/delete-tags'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		if tagIds:
			url_params.append('tagIds=' + tagIds)
		if tagNames:
			url_params.append('tagNames=' + tagNames)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)


	def facets(self, facets: dict, category: str = None, devices: dict = None, filters: dict = None, fromTime: str = None, itemsPerPage: int = None, organization: str = None, pageNumber: int = None, query: str = None, sorting: dict = None, time: str = None, toTime: str = None) -> tuple[bool, dict]:

		'''
		class ThreatHunting
		Description: This API retrieves EDR total events for every EDR facet item.

		:param facetsRequest: facetsRequest. 
		:param category: Specifies the category name. All is the default value. 
		:param devices: Specifies the devices name list. 
		:param facets: Specifies the facets list that available for the user based on the category selected 2. Specifies facets to add to the query.. 
		:param filters: Specifies the filters list that available for the user based on the category selected 2. Specifies filters to add to the query.. 
		:param fromTime: Specifies events start at creation time. Specify the date using the yyyy-MM-dd HH:mm:ss format. The 'time' filed must be 'custom'. 
		:param itemsPerPage: Specifies the Threat Hunting chunck size to retrieve with each call. The default value is 100. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies: ��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly. ��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 
		:param pageNumber: Specifies the Threat Hunting start index number to retrieve from. The default value is 0. 
		:param query: Specifies the search lucene like query. 
		:param sorting: Specifies the Threat Hunting sorting. 
		:param time: Specifies the time period of the events. 
		:param toTime: Specifies events up to a creation time. Specify the date using the yyyy-MM-dd HH:mm:ss format. The 'time' filed must be 'custom'. 

		return: 
			Status of the request (True or False). 
			dict

		'''
		url = '/management-rest/threat-hunting/facets'
		url_params = []
		url += '?' + '&'.join(url_params)
		facetsRequest = {
			'category': category,
			'devices': devices,
			'facets': facets,
			'filters': filters,
			'fromTime': fromTime,
			'itemsPerPage': itemsPerPage,
			'organization': organization,
			'pageNumber': pageNumber,
			'query': query,
			'sorting': sorting,
			'time': time,
			'toTime': toTime
		}
		return fortiedr_connection.send(url, facetsRequest)


	def list_saved_queries(self, organization :str = None, scheduled :bool = None, source :dict = None) -> tuple[bool, dict]:

		'''
		class ThreatHunting
		Description: This API retrieves the existing saved queries list.

		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 
		:param scheduled: A true/false parameter indicating whether the query is scheduled. 
		:param source: Specifies the query source list. 

		return: 
			Status of the request (True or False). 
			dict

		'''
		url = '/management-rest/threat-hunting/list-saved-queries'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		if scheduled:
			url_params.append('scheduled=' + scheduled)
		if source:
			url_params.append('source=' + source)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)


	def list_tags(self, organization :str = None) -> tuple[bool, dict]:

		'''
		class ThreatHunting
		Description: This API retrieves the existing saved queries tag list.

		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 

		return: 
			Status of the request (True or False). 
			dict

		'''
		url = '/management-rest/threat-hunting/list-tags'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)


	def save_query(self, id :int = None, queryToEdit :str = None, category: str = None, classification: str = None, collectorNames: dict = None, community: bool = None, dayOfMonth: int = None, dayOfWeek: int = None, description: str = None, forceSaving: bool = None, frequency: int = None, frequencyUnit: str = None, fromTime: str = None, hour: int = None, name: str = None, organization: str = None, query: str = None, scheduled: bool = None, state: bool = None, tagIds: dict = None, tagNames: dict = None, time: str = None, toTime: str = None) -> tuple[bool, None]:

		'''
		class ThreatHunting
		Description: This API saves the query.

		:param id: Specifies the query ID to edit. 
		:param queryToEdit: Specifies the query name to edit. 
		:param saveQueryRequest: saveQueryRequest. 
		:param category: Specifies the category name. All is the default value. 
		:param classification: Specifies the event classification. The scheduled property must be true. 
		:param collectorNames: Specifies the Collector names. 
		:param community: A true/false parameter indicating whether the query is available to the entire FortiEDR Community. False by default. 
		:param dayOfMonth: Specifies the day of the month for the scheduled query. The value must be between 1 and 28. The properties scheduled and frequencyUnit must be true and Month respectively. 
		:param dayOfWeek: Specifies the day of the week for the scheduled query. The value must be between 0 and 6. 0 is Sunday and 6 is Saturday. The properties scheduled and frequencyUnit must be true and Week respectively. 
		:param description: Specifies the description. 
		:param forceSaving: A true/false parameter indicating whether to force the save, even when there is a large quantity of query results. 
		:param frequency: Specifies the query frequency for the scheduled query. The scheduled property must be true. 
		:param frequencyUnit: Specifies the query frequency unit. The scheduled property must be true. 
		:param fromTime: Specifies events starting from this creation time. Specify the timestamp using the yyyy-MM-dd HH:mm:ss format. The 'time' value must be 'custom'. 
		:param hour: Specifies the hour of the day for the scheduled query. The value must be between 0 and 23. The properties scheduled and frequencyUnit must be true and Day/Week/Month respectively. 
		:param name: Specifies the name of the query being saved. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param query: Specifies the Lucene-like search query. 
		:param scheduled: Specifies whether the query is scheduled. False by default. 
		:param state: A true/false parameter indicating whether the query state is enabled. True by default. 
		:param tagIds: Specifies the query tag ids. 
		:param tagNames: Specifies the query tag names. 
		:param time: Specifies the time period of the Threat Hunting events. The scheduled property must be false. 
		:param toTime: Specifies events up to a creation time. Specify the date using the yyyy-MM-dd HH:mm:ss format. The 'time' filed must be 'custom'. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/threat-hunting/save-query'
		url_params = []
		if id:
			url_params.append('id=' + id)
		if queryToEdit:
			url_params.append('queryToEdit=' + queryToEdit)
		url += '?' + '&'.join(url_params)
		saveQueryRequest = {
			'category': category,
			'classification': classification,
			'collectorNames': collectorNames,
			'community': community,
			'dayOfMonth': dayOfMonth,
			'dayOfWeek': dayOfWeek,
			'description': description,
			'forceSaving': forceSaving,
			'frequency': frequency,
			'frequencyUnit': frequencyUnit,
			'fromTime': fromTime,
			'hour': hour,
			'name': name,
			'organization': organization,
			'query': query,
			'scheduled': scheduled,
			'state': state,
			'tagIds': tagIds,
			'tagNames': tagNames,
			'time': time,
			'toTime': toTime
		}
		return fortiedr_connection.send(url, saveQueryRequest)


	def search(self, category: str = None, devices: dict = None, filters: dict = None, fromTime: str = None, itemsPerPage: int = None, organization: str = None, pageNumber: int = None, query: str = None, sorting: dict = None, time: str = None, toTime: str = None) -> tuple[bool, dict]:

		'''
		class ThreatHunting
		Description: This API call outputs a list of Activity events from middleware..

		:param edrRequest: edrRequest. 
		:param category: Specifies the category name. All is the default value. 
		:param devices: Specifies the devices name list. 
		:param filters: Specifies the filters list that available for the user based on the category selected 2. Specifies filters to add to the query.. 
		:param fromTime: Specifies events start at creation time. Specify the date using the yyyy-MM-dd HH:mm:ss format. The 'time' filed must be 'custom'. 
		:param itemsPerPage: Specifies the Threat Hunting chunck size to retrieve with each call. The default value is 100. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies: ��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly. ��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 
		:param pageNumber: Specifies the Threat Hunting start index number to retrieve from. The default value is 0. 
		:param query: Specifies the search lucene like query. 
		:param sorting: Specifies the Threat Hunting sorting. 
		:param time: Specifies the time period of the events. 
		:param toTime: Specifies events up to a creation time. Specify the date using the yyyy-MM-dd HH:mm:ss format. The 'time' filed must be 'custom'. 

		return: 
			Status of the request (True or False). 
			dict

		'''
		url = '/management-rest/threat-hunting/search'
		url_params = []
		url += '?' + '&'.join(url_params)
		edrRequest = {
			'category': category,
			'devices': devices,
			'filters': filters,
			'fromTime': fromTime,
			'itemsPerPage': itemsPerPage,
			'organization': organization,
			'pageNumber': pageNumber,
			'query': query,
			'sorting': sorting,
			'time': time,
			'toTime': toTime
		}
		return fortiedr_connection.send(url, edrRequest)


	def set_query_state(self, state : bool, markAll :bool = None, organization :str = None, queryIds :dict = None, queryNames :dict = None, source :dict = None) -> tuple[bool, None]:

		'''
		class ThreatHunting
		Description: This API updates the scheduled saved query state.

		:param markAll: A true/false parameter indicating whether all queries should be marked with the same value as 'state' property. False by default. 
		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 
		:param queryIds: Specifies the query ID list. 
		:param queryNames: Specifies the query name list. 
		:param source: Specifies the query source list. 
		:param state: A true/false parameter indicating whether to save the query as enabled. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/threat-hunting/set-query-state'
		url_params = []
		if markAll:
			url_params.append('markAll=' + markAll)
		if organization:
			url_params.append('organization=' + organization)
		if queryIds:
			url_params.append('queryIds=' + queryIds)
		if queryNames:
			url_params.append('queryNames=' + queryNames)
		if source:
			url_params.append('source=' + source)
		if state:
			url_params.append('state=' + state)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)

class ThreatHuntingExclusions:

	def send_exclusions(self, exclusionListName: str, exclusions: dict, organization: str) -> tuple[bool, dict]:

		'''
		class ThreatHuntingExclusions
		Description: Creates exclusions..

		:param createExclusionsRequest: createExclusionsRequest. 
		:param exclusionListName: Exclusions created in the request will be associated with this list.. 
		:param exclusions: List of exclusions definitions to be created.. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 

		return: 
			Status of the request (True or False). 
			dict

		'''
		url = '/management-rest/threat-hunting-exclusions/exclusion'
		url_params = []
		url += '?' + '&'.join(url_params)
		createExclusionsRequest = {
			'exclusionListName': exclusionListName,
			'exclusions': exclusions,
			'organization': organization
		}
		return fortiedr_connection.send(url, createExclusionsRequest)

	def insert_exclusions(self, exclusionListName: str, exclusions: dict, organization: str) -> tuple[bool, dict]:

		'''
		class ThreatHuntingExclusions
		Description: Creates exclusions..

		:param updateExclusionsRequest: updateExclusionsRequest. 
		:param exclusionListName: Exclusions created in the request will be associated with this list.. 
		:param exclusions: List of exclusions definitions to update.. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 

		return: 
			Status of the request (True or False). 
			dict

		'''
		url = '/management-rest/threat-hunting-exclusions/exclusion'
		url_params = []
		url += '?' + '&'.join(url_params)
		updateExclusionsRequest = {
			'exclusionListName': exclusionListName,
			'exclusions': exclusions,
			'organization': organization
		}
		return fortiedr_connection.insert(url, updateExclusionsRequest)

	def delete_exclusion(self, exclusionIds: dict, organization: str) -> tuple[bool, str]:

		'''
		class ThreatHuntingExclusions
		Description: Creates exclusions..

		:param deleteExclusionsRequest: deleteExclusionsRequest. 
		:param exclusionIds: List of exclusion Ids for deletion.. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 

		return: 
			Status of the request (True or False). 
			str

		'''
		url = '/management-rest/threat-hunting-exclusions/exclusion'
		url_params = []
		url += '?' + '&'.join(url_params)
		deleteExclusionsRequest = {
			'exclusionIds': exclusionIds,
			'organization': organization
		}
		return fortiedr_connection.delete(url, deleteExclusionsRequest)


	def get_exclusions_list(self, organization : str) -> tuple[bool, dict]:

		'''
		class ThreatHuntingExclusions
		Description: Get the list of Exclusions lists..

		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 

		return: 
			Status of the request (True or False). 
			dict

		'''
		url = '/management-rest/threat-hunting-exclusions/exclusions-list'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def send_exclusions_list(self, name: str, organization: str, collectorGroupIds: dict = None) -> tuple[bool, None]:

		'''
		class ThreatHuntingExclusions
		Description: Get the list of Exclusions lists..

		:param createExclusionListRequest: createExclusionListRequest. 
		:param collectorGroupIds: The list of Collector group Ids associated with this exclusion list.. 
		:param name: Exclusion list name.. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/threat-hunting-exclusions/exclusions-list'
		url_params = []
		url += '?' + '&'.join(url_params)
		createExclusionListRequest = {
			'collectorGroupIds': collectorGroupIds,
			'name': name,
			'organization': organization
		}
		return fortiedr_connection.send(url, createExclusionListRequest)

	def insert_exclusions_list(self, collectorGroupIds: dict, listName: str, organization: str, newName: str = None) -> tuple[bool, None]:

		'''
		class ThreatHuntingExclusions
		Description: Get the list of Exclusions lists..

		:param updateExclusionListRequest: updateExclusionListRequest. 
		:param collectorGroupIds: The list of Collector group Ids associated with this exclusion list.. 
		:param listName: Exclusions list name.. 
		:param newName: Exclusion list new name.. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/threat-hunting-exclusions/exclusions-list'
		url_params = []
		url += '?' + '&'.join(url_params)
		updateExclusionListRequest = {
			'collectorGroupIds': collectorGroupIds,
			'listName': listName,
			'newName': newName,
			'organization': organization
		}
		return fortiedr_connection.insert(url, updateExclusionListRequest)

	def delete_exclusions_list(self, listName : str, organization : str) -> tuple[bool, None]:

		'''
		class ThreatHuntingExclusions
		Description: Get the list of Exclusions lists..

		:param listName: Exclusions list name.. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
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
		class ThreatHuntingExclusions
		Description: Get the metadata and available properties for exclusions configuration. When creating/modifying an exclusion, use the response of this API as a guide for the valid attribute names and values, and their corresponding EDR event types. Every attribute corresponds to an EDR category (for example, Filename attribute corresponds with the File category), and each category is a set of EDR event types. .

		:param listName: Exclusions list name.. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 

		'''
		url = '/management-rest/threat-hunting-exclusions/exclusions-metadata'
		return fortiedr_connection.get(url)


	def exclusions_search(self, searchText : str, organization :str = None, os :dict = None) -> tuple[bool, dict]:

		'''
		class ThreatHuntingExclusions
		Description: Free-text search of exclusions.

		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param os: OS identifiers list.. 
		:param searchText: The free text search string. The API will return every exclusion list that contains this string, or contains an exclusion with any field that contains it.. 

		return: 
			Status of the request (True or False). 
			dict

		'''
		url = '/management-rest/threat-hunting-exclusions/exclusions-search'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		if os:
			url_params.append('os=' + os)
		if searchText:
			url_params.append('searchText=' + searchText)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

class ThreatHuntingSettings:

	def threat_hunting_metadata(self) -> tuple[bool, dict]:

		'''
		class ThreatHuntingSettings
		Description: Get the Threat Hunting Settings metadata object, listing the available configuration options (Category and Event Types)..

		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param os: OS identifiers list.. 
		:param searchText: The free text search string. The API will return every exclusion list that contains this string, or contains an exclusion with any field that contains it.. 

		'''
		url = '/management-rest/threat-hunting-settings/threat-hunting-metadata'
		return fortiedr_connection.get(url)


	def get_threat_hunting_profile(self, organization : str) -> tuple[bool, dict]:

		'''
		class ThreatHuntingSettings
		Description: Get the list of Threat Hunting Setting profiles..

		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 

		return: 
			Status of the request (True or False). 
			dict

		'''
		url = '/management-rest/threat-hunting-settings/threat-hunting-profile'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)

	def send_threat_hunting_profile(self, associatedCollectorGroupIds: dict, name: str, organization: str, threatHuntingCategoryList: dict, newName: str = None) -> tuple[bool, None]:

		'''
		class ThreatHuntingSettings
		Description: Get the list of Threat Hunting Setting profiles..

		:param threatHuntingUpdateRequest: threatHuntingUpdateRequest. 
		:param associatedCollectorGroupIds: List of associated collector groups Ids, for example [1,2,3].. 
		:param name: Threat Hunting profile name.. 
		:param newName: New profile name. Optional.. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param threatHuntingCategoryList: Threat Hunting Categories. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/threat-hunting-settings/threat-hunting-profile'
		url_params = []
		url += '?' + '&'.join(url_params)
		threatHuntingUpdateRequest = {
			'associatedCollectorGroupIds': associatedCollectorGroupIds,
			'name': name,
			'newName': newName,
			'organization': organization,
			'threatHuntingCategoryList': threatHuntingCategoryList
		}
		return fortiedr_connection.send(url, threatHuntingUpdateRequest)

	def delete_threat_hunting_profile(self, name : str, organization : str) -> tuple[bool, None]:

		'''
		class ThreatHuntingSettings
		Description: Get the list of Threat Hunting Setting profiles..

		:param name: To be deleted profile's name.. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/threat-hunting-settings/threat-hunting-profile'
		url_params = []
		if name:
			url_params.append('name=' + name)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)


	def threat_hunting_profile_clone(self, cloneProfileName : str, existingProfileName : str, organization : str) -> tuple[bool, None]:

		'''
		class ThreatHuntingSettings
		Description: Clone a Threat Hunting Settings profile..

		:param cloneProfileName: Cloned profile name.. 
		:param existingProfileName: Existing profile name.. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
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


	def threat_hunting_profile_assign_collector_groups(self, associatedCollectorGroupIds: dict, name: str, organization: str = None) -> tuple[bool, dict]:

		'''
		class ThreatHuntingSettings
		Description: Update Threat Hunting profile assigned collector groups. Returns the updated list of assigned collector groups..

		:param threatHuntingAssignGroupsRequest: threatHuntingAssignGroupsRequest. 
		:param associatedCollectorGroupIds: List of associated collector groups Ids, for example [1,2,3].. 
		:param name: Threat Hunting profile name.. 
		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 

		return: 
			Status of the request (True or False). 
			dict

		'''
		url = '/management-rest/threat-hunting-settings/threat-hunting-profile/collector-groups'
		url_params = []
		url += '?' + '&'.join(url_params)
		threatHuntingAssignGroupsRequest = {
			'associatedCollectorGroupIds': associatedCollectorGroupIds,
			'name': name,
			'organization': organization
		}
		return fortiedr_connection.send(url, threatHuntingAssignGroupsRequest)

class Users:

	def create_user(self, confirmPassword: str, email: str, firstName: str, lastName: str, password: str, role: str, username: str, organization :str = None, customScript: bool = None, remoteShell: bool = None, restApi: bool = None, title: str = None) -> tuple[bool, None]:

		'''
		class Users
		Description: This API create user in the system. (only for Admin role.

		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non-shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� each ��� Indicates that the operation applies independently to each organization. For example, let's assume that the same user exists in multiple organizations. When each is specified in the organization parameter, then each organization can update this user separately.. 
		:param userRequest: userRequest. 
		:param confirmPassword: Specifies the confirm login password. 
		:param customScript: Is user can upload custom scripts. 
		:param email: Specifies the email of user. 
		:param firstName: Specifies the first name of user. 
		:param lastName: Specifies the last name of user. 
		:param password: Specifies the login password. 
		:param remoteShell: Is user can use remote shell. 
		:param restApi: Is user can access by rest to the api. 
		:param role: Specifies the roles of the user. 
		:param title: Specifies the title of user. 
		:param username: Specifies the login username of the user. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/users/create-user'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		userRequest = {
			'confirmPassword': confirmPassword,
			'customScript': customScript,
			'email': email,
			'firstName': firstName,
			'lastName': lastName,
			'password': password,
			'remoteShell': remoteShell,
			'restApi': restApi,
			'role': role,
			'title': title,
			'username': username
		}
		return fortiedr_connection.send(url, userRequest)


	def delete_saml_settings(self, organizationNameRequest : str) -> tuple[bool, None]:

		'''
		class Users
		Description: Delete SAML authentication settings per organization.

		:param organizationNameRequest: organizationNameRequest. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/users/delete-saml-settings'
		url_params = []
		if organizationNameRequest:
			url_params.append('organizationNameRequest=' + organizationNameRequest)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)


	def delete_user(self, username : str, organization :str = None) -> tuple[bool, None]:

		'''
		class Users
		Description: This API delete user from the system. Use the input parameters to filter organization.

		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param username: Specifies the name of the user. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/users/delete-user'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		if username:
			url_params.append('username=' + username)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.delete(url)


	def get_sp_metadata(self, organization : str) -> tuple[bool, str]:

		'''
		class Users
		Description: This API call retrieve the FortiEdr metadata by organization.

		:param organization: organization. 

		return: 
			Status of the request (True or False). 
			str

		'''
		url = '/management-rest/users/get-sp-metadata'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)


	def list_users(self, organization :str = None) -> tuple[bool, dict]:

		'''
		class Users
		Description: This API call outputs a list of the users in the system. Use the input parameters to filter the list.

		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� All organizations ��� Indicates that the operation applies to all organizations. In this case, the same data is shared by all organizations.. 

		return: 
			Status of the request (True or False). 
			dict

		'''
		url = '/management-rest/users/list-users'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.get(url)


	def reset_password(self, username : str, confirmPassword: str, password: str, organization :str = None) -> tuple[bool, None]:

		'''
		class Users
		Description: This API reset user password. Use the input parameters to filter organization.

		:param organization: Specifies the name of a specific organization. The value that you specify here must match exactly. 
		:param userRequest: userRequest. 
		:param confirmPassword: Specifies the confirm login password. 
		:param password: Specifies the login password. 
		:param username: Specifies the name of the user. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/users/reset-password'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		if username:
			url_params.append('username=' + username)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)


	def update_saml_settings(self, idpMetadataFile : BinaryIO) -> tuple[bool, None]:

		'''
		class Users
		Description: Create / Update SAML authentication settings per organization.

		:param idpMetadataFile: idpMetadataFile. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/users/update-saml-settings'
		url_params = []
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.send(url)


	def update_user(self, username : str, email: str, firstName: str, lastName: str, role: str, organization :str = None, customScript: bool = None, remoteShell: bool = None, restApi: bool = None, title: str = None) -> tuple[bool, None]:

		'''
		class Users
		Description: This API update user in the system. Use the input parameters to filter organization.

		:param organization: Specifies the organization. The value that you specify for this parameter indicates how the operation applies to an organization(s). Some parts of the Fortinet Endpoint Protection and Response Platform system have separate, non-shared data that is organization-specific. Other parts of the system have data that is shared by all organizations. The value that you specify for the organization parameter, as described below, determines to which organization(s) an operation applies:��� Exact organization name ��� Specifies the name of a specific organization. The value that you specify here must match exactly.��� each ��� Indicates that the operation applies independently to each organization. For example, let's assume that the same user exists in multiple organizations. When each is specified in the organization parameter, then each organization can update this user separately.. 
		:param userRequest: userRequest. 
		:param customScript: Is user can upload custom scripts. 
		:param email: Specifies the email of user. 
		:param firstName: Specifies the first name of user. 
		:param lastName: Specifies the last name of user. 
		:param remoteShell: Is user can use remote shell. 
		:param restApi: Is user can access by rest to the api. 
		:param role: Specifies the roles of the user. 
		:param title: Specifies the title of user. 
		:param username: Specifies the name of the user. 

		return: 
			Status of the request (True or False). 
			This function does not return any data.

		'''
		url = '/management-rest/users/update-user'
		url_params = []
		if organization:
			url_params.append('organization=' + organization)
		if username:
			url_params.append('username=' + username)
		url += '?' + '&'.join(url_params)
		return fortiedr_connection.insert(url)


debug = None
ssl_enabled = True

def disable_ssl():
	global ssl_enabled
	ssl_enabled = False
	print("[!] - We strongly advise you to enable SSL validations. Use this at your own risk!")

def enable_debug():
	global debug
	debug = True

def auth( host: str, user: str, passw: str, org: str = None):
	global debug
	global fortiedr_connection
	login = fedrAuth()
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
	authentication = fortiedr_connection.conn(headers, host, debug, ssl_enabled)
	return {
		'status': status,
		'data': data
	}

