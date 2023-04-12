from typing import BinaryIO
from fortiedr.auth import Auth as fedrAuth
from fortiedr.connector import FortiEDR_API_GW

fortiedr = None

class Administrator:

	'''
	class Administrator: This API call output the available collectors installers.
	'''
	def list_collector_installers(self, organization :str = None) -> tuple[bool, None]:

		url = '/management-rest/admin/list-collector-installers'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)


	'''
	class Administrator: Get System Summary.
	'''
	def list_system_summary(self, organization :str = None, addLicenseBlob :bool = None) -> tuple[bool, None]:
		url = '/management-rest/admin/list-system-summary'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if addLicenseBlob:
			url_params.append('addLicenseBlob=' + addLicenseBlob)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)


	'''
	class Administrator: Set system modeThis API call enables you to switch the system to Simulation mode.
	'''
	def set_system_mode(self, mode : str, organization :str = None, forceAll :bool = None) -> tuple[bool, None]:
		url = '/management-rest/admin/set-system-mode'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if mode:
			url_params.append('mode=' + mode)
		if forceAll:
			url_params.append('forceAll=' + forceAll)
		url += '?' + '&'.join(url_params)
		return fortiedr.insert(url)


	'''
	class Administrator: This API update collectors target version for collector groups.
	'''
	def update_collector_installer(self, collectorGroups :dict = None, collectorGroupIds :dict = None, organization :str = None, updateVersions: dict = None) -> tuple[bool, None]:
		url = '/management-rest/admin/update-collector-installer'
		url_params = list()
		if collectorGroups:
			url_params.append('collectorGroups=' + collectorGroups)
		if collectorGroupIds:
			url_params.append('collectorGroupIds=' + collectorGroupIds)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		requestUpdateData = {
			'updateVersions': updateVersions
		}
		return fortiedr.send(url, requestUpdateData)


	'''
	class Administrator: Upload content to the system.
	'''
	def upload_content(self, file : BinaryIO) -> tuple[bool, str]:
		url = '/management-rest/admin/upload-content'
		url_params = list()
		url += '?' + '&'.join(url_params)
		return fortiedr.send(url)


	'''
	class Administrator: Upload license to the system.
	'''
	def upload_license(self, licenseBlob: str = None) -> tuple[bool, None]:
		url = '/management-rest/admin/upload-license'
		url_params = list()
		url += '?' + '&'.join(url_params)
		license = {
			'licenseBlob': licenseBlob
		}
		return fortiedr.insert(url, license)

class Audit:

	'''
	class Audit: This API retrieve the audit between 2 dates.
	'''
	def get_audit(self, organization :str = None, fromTime :str = None, toTime :str = None) -> tuple[bool, dict]:
		url = '/management-rest/audit/get-audit'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if fromTime:
			url_params.append('fromTime=' + fromTime)
		if toTime:
			url_params.append('toTime=' + toTime)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)

class CommunicationControl:

	'''
	class CommunicationControl: Assign collector group to application policy.
	'''
	def assign_collector_group(self, collectorGroups : dict, policyName : str, organization :str = None, forceAssign :bool = None) -> tuple[bool, None]:
		url = '/management-rest/comm-control/assign-collector-group'
		url_params = list()
		if collectorGroups:
			url_params.append('collectorGroups=' + collectorGroups)
		if organization:
			url_params.append('organization=' + organization)
		if policyName:
			url_params.append('policyName=' + policyName)
		if forceAssign:
			url_params.append('forceAssign=' + forceAssign)
		url += '?' + '&'.join(url_params)
		return fortiedr.insert(url)


	'''
	class CommunicationControl: application clone policy.
	'''
	def clone_policy(self, sourcePolicyName : str, newPolicyName : str, organization :str = None) -> tuple[bool, None]:
		url = '/management-rest/comm-control/clone-policy'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if sourcePolicyName:
			url_params.append('sourcePolicyName=' + sourcePolicyName)
		if newPolicyName:
			url_params.append('newPolicyName=' + newPolicyName)
		url += '?' + '&'.join(url_params)
		return fortiedr.send(url)


	'''
	class CommunicationControl: This API call outputs a list of all the communication control policies in the system, and information about each of them.
	'''
	def list_policies(self, decisions : dict, policies :dict = None, rules :dict = None, sources :dict = None, pageNumber :int = None, strictMode :bool = None, itemsPerPage :int = None, sorting :str = None, organization :str = None, state :str = None) -> tuple[bool, dict]:
		url = '/management-rest/comm-control/list-policies'
		url_params = list()
		if policies:
			url_params.append('policies=' + policies)
		if rules:
			url_params.append('rules=' + rules)
		if sources:
			url_params.append('sources=' + sources)
		if decisions:
			url_params.append('decisions=' + decisions)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if sorting:
			url_params.append('sorting=' + sorting)
		if organization:
			url_params.append('organization=' + organization)
		if state:
			url_params.append('state=' + state)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)


	'''
	class CommunicationControl: This API call outputs a list of all the communicating applications in the system, and information about each of them.
	'''
	def list_products(self, vendors :dict = None, products :dict = None, versions :dict = None, processes :dict = None, devices :dict = None, collectorGroups :dict = None, ips :dict = None, os :dict = None, policies :dict = None, reputation :dict = None, vulnerabilities :dict = None, pageNumber :int = None, strictMode :bool = None, itemsPerPage :int = None, sorting :str = None, organization :str = None, vendor :str = None, product :str = None, version :str = None, lastConnectionTimeStart :str = None, lastConnectionTimeEnd :str = None, firstConnectionTimeStart :str = None, firstConnectionTimeEnd :str = None, action :str = None, seen :bool = None, handled :bool = None, processHash :str = None, includeStatistics :bool = None, rulePolicy :str = None, rule :str = None, cveIdentifier :str = None) -> tuple[bool, dict]:
		url = '/management-rest/comm-control/list-products'
		url_params = list()
		if vendors:
			url_params.append('vendors=' + vendors)
		if products:
			url_params.append('products=' + products)
		if versions:
			url_params.append('versions=' + versions)
		if processes:
			url_params.append('processes=' + processes)
		if devices:
			url_params.append('devices=' + devices)
		if collectorGroups:
			url_params.append('collectorGroups=' + collectorGroups)
		if ips:
			url_params.append('ips=' + ips)
		if os:
			url_params.append('os=' + os)
		if policies:
			url_params.append('policies=' + policies)
		if reputation:
			url_params.append('reputation=' + reputation)
		if vulnerabilities:
			url_params.append('vulnerabilities=' + vulnerabilities)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if sorting:
			url_params.append('sorting=' + sorting)
		if organization:
			url_params.append('organization=' + organization)
		if vendor:
			url_params.append('vendor=' + vendor)
		if product:
			url_params.append('product=' + product)
		if version:
			url_params.append('version=' + version)
		if lastConnectionTimeStart:
			url_params.append('lastConnectionTimeStart=' + lastConnectionTimeStart)
		if lastConnectionTimeEnd:
			url_params.append('lastConnectionTimeEnd=' + lastConnectionTimeEnd)
		if firstConnectionTimeStart:
			url_params.append('firstConnectionTimeStart=' + firstConnectionTimeStart)
		if firstConnectionTimeEnd:
			url_params.append('firstConnectionTimeEnd=' + firstConnectionTimeEnd)
		if action:
			url_params.append('action=' + action)
		if seen:
			url_params.append('seen=' + seen)
		if handled:
			url_params.append('handled=' + handled)
		if processHash:
			url_params.append('processHash=' + processHash)
		if includeStatistics:
			url_params.append('includeStatistics=' + includeStatistics)
		if rulePolicy:
			url_params.append('rulePolicy=' + rulePolicy)
		if rule:
			url_params.append('rule=' + rule)
		if cveIdentifier:
			url_params.append('cveIdentifier=' + cveIdentifier)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)


	'''
	class CommunicationControl: Enable resolving/unresolving applications.
	'''
	def resolve_applications(self, vendors :dict = None, products :dict = None, versions :dict = None, organization :str = None, signed :bool = None, applyNested :bool = None, comment :str = None, resolve :bool = None) -> tuple[bool, None]:
		url = '/management-rest/comm-control/resolve-applications'
		url_params = list()
		if vendors:
			url_params.append('vendors=' + vendors)
		if products:
			url_params.append('products=' + products)
		if versions:
			url_params.append('versions=' + versions)
		if organization:
			url_params.append('organization=' + organization)
		if signed:
			url_params.append('signed=' + signed)
		if applyNested:
			url_params.append('applyNested=' + applyNested)
		if comment:
			url_params.append('comment=' + comment)
		if resolve:
			url_params.append('resolve=' + resolve)
		url += '?' + '&'.join(url_params)
		return fortiedr.insert(url)


	'''
	class CommunicationControl: Set policy to simulation/prevention.
	'''
	def set_policy_mode(self, policyNames : dict, mode : str, organization :str = None) -> tuple[bool, None]:
		url = '/management-rest/comm-control/set-policy-mode'
		url_params = list()
		if policyNames:
			url_params.append('policyNames=' + policyNames)
		if organization:
			url_params.append('organization=' + organization)
		if mode:
			url_params.append('mode=' + mode)
		url += '?' + '&'.join(url_params)
		return fortiedr.insert(url)


	'''
	class CommunicationControl: Set the application allow/deny.
	'''
	def set_policy_permission(self, policies : dict, decision : str, vendors :dict = None, products :dict = None, versions :dict = None, organization :str = None, signed :bool = None, applyNested :bool = None) -> tuple[bool, None]:
		url = '/management-rest/comm-control/set-policy-permission'
		url_params = list()
		if vendors:
			url_params.append('vendors=' + vendors)
		if products:
			url_params.append('products=' + products)
		if versions:
			url_params.append('versions=' + versions)
		if policies:
			url_params.append('policies=' + policies)
		if organization:
			url_params.append('organization=' + organization)
		if signed:
			url_params.append('signed=' + signed)
		if applyNested:
			url_params.append('applyNested=' + applyNested)
		if decision:
			url_params.append('decision=' + decision)
		url += '?' + '&'.join(url_params)
		return fortiedr.insert(url)


	'''
	class CommunicationControl: Set rule in policy to enable/disable.
	'''
	def set_policy_rule_state(self, policyName : str, ruleName : str, state : str, organization :str = None) -> tuple[bool, None]:
		url = '/management-rest/comm-control/set-policy-rule-state'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if policyName:
			url_params.append('policyName=' + policyName)
		if ruleName:
			url_params.append('ruleName=' + ruleName)
		if state:
			url_params.append('state=' + state)
		url += '?' + '&'.join(url_params)
		return fortiedr.insert(url)

class Events:

	'''
	class Events: This API call updates the read/unread, handled/unhandled or archived/unarchived state of an event. The output of this call is a message indicating whether the update succeeded or failed.
	'''
	def insert_events(self, eventIds :dict = None, collectorGroups :dict = None, deviceIps :dict = None, macAddresses :dict = None, severities :dict = None, classifications :dict = None, actions :dict = None, paths :dict = None, operatingSystems :dict = None, destinations :dict = None, eventType :dict = None, pageNumber :int = None, strictMode :bool = None, itemsPerPage :int = None, sorting :str = None, organization :str = None, device :str = None, process :str = None, fileHash :str = None, firstSeen :str = None, lastSeen :str = None, firstSeenFrom :str = None, firstSeenTo :str = None, lastSeenFrom :str = None, lastSeenTo :str = None, seen :bool = None, handled :bool = None, rule :str = None, loggedUser :str = None, archived :bool = None, signed :bool = None, muted :bool = None, deviceControl :bool = None, expired :bool = None, archive: bool = None, classification: str = None, comment: str = None, familyName: str = None, forceUnmute: bool = None, handle: bool = None, malwareType: str = None, mute: bool = None, muteDuration: str = None, read: bool = None, threatName: str = None) -> tuple[bool, None]:
		url = '/management-rest/events'
		url_params = list()
		if eventIds:
			url_params.append('eventIds=' + eventIds)
		if collectorGroups:
			url_params.append('collectorGroups=' + collectorGroups)
		if deviceIps:
			url_params.append('deviceIps=' + deviceIps)
		if macAddresses:
			url_params.append('macAddresses=' + macAddresses)
		if severities:
			url_params.append('severities=' + severities)
		if classifications:
			url_params.append('classifications=' + classifications)
		if actions:
			url_params.append('actions=' + actions)
		if paths:
			url_params.append('paths=' + paths)
		if operatingSystems:
			url_params.append('operatingSystems=' + operatingSystems)
		if destinations:
			url_params.append('destinations=' + destinations)
		if eventType:
			url_params.append('eventType=' + eventType)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if sorting:
			url_params.append('sorting=' + sorting)
		if organization:
			url_params.append('organization=' + organization)
		if device:
			url_params.append('device=' + device)
		if process:
			url_params.append('process=' + process)
		if fileHash:
			url_params.append('fileHash=' + fileHash)
		if firstSeen:
			url_params.append('firstSeen=' + firstSeen)
		if lastSeen:
			url_params.append('lastSeen=' + lastSeen)
		if firstSeenFrom:
			url_params.append('firstSeenFrom=' + firstSeenFrom)
		if firstSeenTo:
			url_params.append('firstSeenTo=' + firstSeenTo)
		if lastSeenFrom:
			url_params.append('lastSeenFrom=' + lastSeenFrom)
		if lastSeenTo:
			url_params.append('lastSeenTo=' + lastSeenTo)
		if seen:
			url_params.append('seen=' + seen)
		if handled:
			url_params.append('handled=' + handled)
		if rule:
			url_params.append('rule=' + rule)
		if loggedUser:
			url_params.append('loggedUser=' + loggedUser)
		if archived:
			url_params.append('archived=' + archived)
		if signed:
			url_params.append('signed=' + signed)
		if muted:
			url_params.append('muted=' + muted)
		if deviceControl:
			url_params.append('deviceControl=' + deviceControl)
		if expired:
			url_params.append('expired=' + expired)
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
		return fortiedr.insert(url, updateEventsRequest)

	'''
	class Events: This API call updates the read/unread, handled/unhandled or archived/unarchived state of an event. The output of this call is a message indicating whether the update succeeded or failed.
	'''
	def delete_events(self, eventIds :dict = None, collectorGroups :dict = None, deviceIps :dict = None, macAddresses :dict = None, severities :dict = None, classifications :dict = None, actions :dict = None, paths :dict = None, operatingSystems :dict = None, destinations :dict = None, eventType :dict = None, pageNumber :int = None, strictMode :bool = None, itemsPerPage :int = None, sorting :str = None, organization :str = None, device :str = None, process :str = None, fileHash :str = None, firstSeen :str = None, lastSeen :str = None, firstSeenFrom :str = None, firstSeenTo :str = None, lastSeenFrom :str = None, lastSeenTo :str = None, seen :bool = None, handled :bool = None, rule :str = None, loggedUser :str = None, archived :bool = None, signed :bool = None, muted :bool = None, deviceControl :bool = None, expired :bool = None, deleteAll :bool = None) -> tuple[bool, None]:
		url = '/management-rest/events'
		url_params = list()
		if eventIds:
			url_params.append('eventIds=' + eventIds)
		if collectorGroups:
			url_params.append('collectorGroups=' + collectorGroups)
		if deviceIps:
			url_params.append('deviceIps=' + deviceIps)
		if macAddresses:
			url_params.append('macAddresses=' + macAddresses)
		if severities:
			url_params.append('severities=' + severities)
		if classifications:
			url_params.append('classifications=' + classifications)
		if actions:
			url_params.append('actions=' + actions)
		if paths:
			url_params.append('paths=' + paths)
		if operatingSystems:
			url_params.append('operatingSystems=' + operatingSystems)
		if destinations:
			url_params.append('destinations=' + destinations)
		if eventType:
			url_params.append('eventType=' + eventType)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if sorting:
			url_params.append('sorting=' + sorting)
		if organization:
			url_params.append('organization=' + organization)
		if device:
			url_params.append('device=' + device)
		if process:
			url_params.append('process=' + process)
		if fileHash:
			url_params.append('fileHash=' + fileHash)
		if firstSeen:
			url_params.append('firstSeen=' + firstSeen)
		if lastSeen:
			url_params.append('lastSeen=' + lastSeen)
		if firstSeenFrom:
			url_params.append('firstSeenFrom=' + firstSeenFrom)
		if firstSeenTo:
			url_params.append('firstSeenTo=' + firstSeenTo)
		if lastSeenFrom:
			url_params.append('lastSeenFrom=' + lastSeenFrom)
		if lastSeenTo:
			url_params.append('lastSeenTo=' + lastSeenTo)
		if seen:
			url_params.append('seen=' + seen)
		if handled:
			url_params.append('handled=' + handled)
		if rule:
			url_params.append('rule=' + rule)
		if loggedUser:
			url_params.append('loggedUser=' + loggedUser)
		if archived:
			url_params.append('archived=' + archived)
		if signed:
			url_params.append('signed=' + signed)
		if muted:
			url_params.append('muted=' + muted)
		if deviceControl:
			url_params.append('deviceControl=' + deviceControl)
		if expired:
			url_params.append('expired=' + expired)
		if deleteAll:
			url_params.append('deleteAll=' + deleteAll)
		url += '?' + '&'.join(url_params)
		return fortiedr.delete(url)


	'''
	class Events: Count Events.
	'''
	def count_events(self, eventIds :dict = None, collectorGroups :dict = None, deviceIps :dict = None, macAddresses :dict = None, severities :dict = None, classifications :dict = None, actions :dict = None, paths :dict = None, operatingSystems :dict = None, destinations :dict = None, eventType :dict = None, pageNumber :int = None, strictMode :bool = None, itemsPerPage :int = None, sorting :str = None, organization :str = None, device :str = None, process :str = None, fileHash :str = None, firstSeen :str = None, lastSeen :str = None, firstSeenFrom :str = None, firstSeenTo :str = None, lastSeenFrom :str = None, lastSeenTo :str = None, seen :bool = None, handled :bool = None, rule :str = None, loggedUser :str = None, archived :bool = None, signed :bool = None, muted :bool = None, deviceControl :bool = None, expired :bool = None) -> tuple[bool, int]:
		url = '/management-rest/events/count-events'
		url_params = list()
		if eventIds:
			url_params.append('eventIds=' + eventIds)
		if collectorGroups:
			url_params.append('collectorGroups=' + collectorGroups)
		if deviceIps:
			url_params.append('deviceIps=' + deviceIps)
		if macAddresses:
			url_params.append('macAddresses=' + macAddresses)
		if severities:
			url_params.append('severities=' + severities)
		if classifications:
			url_params.append('classifications=' + classifications)
		if actions:
			url_params.append('actions=' + actions)
		if paths:
			url_params.append('paths=' + paths)
		if operatingSystems:
			url_params.append('operatingSystems=' + operatingSystems)
		if destinations:
			url_params.append('destinations=' + destinations)
		if eventType:
			url_params.append('eventType=' + eventType)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if sorting:
			url_params.append('sorting=' + sorting)
		if organization:
			url_params.append('organization=' + organization)
		if device:
			url_params.append('device=' + device)
		if process:
			url_params.append('process=' + process)
		if fileHash:
			url_params.append('fileHash=' + fileHash)
		if firstSeen:
			url_params.append('firstSeen=' + firstSeen)
		if lastSeen:
			url_params.append('lastSeen=' + lastSeen)
		if firstSeenFrom:
			url_params.append('firstSeenFrom=' + firstSeenFrom)
		if firstSeenTo:
			url_params.append('firstSeenTo=' + firstSeenTo)
		if lastSeenFrom:
			url_params.append('lastSeenFrom=' + lastSeenFrom)
		if lastSeenTo:
			url_params.append('lastSeenTo=' + lastSeenTo)
		if seen:
			url_params.append('seen=' + seen)
		if handled:
			url_params.append('handled=' + handled)
		if rule:
			url_params.append('rule=' + rule)
		if loggedUser:
			url_params.append('loggedUser=' + loggedUser)
		if archived:
			url_params.append('archived=' + archived)
		if signed:
			url_params.append('signed=' + signed)
		if muted:
			url_params.append('muted=' + muted)
		if deviceControl:
			url_params.append('deviceControl=' + deviceControl)
		if expired:
			url_params.append('expired=' + expired)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)


	'''
	class Events: This API call adds an exception to a specific event. The output of this call is a message indicating whether the creation of the exception .
	'''
	def create_exception(self, destinations :dict = None, users :dict = None, collectorGroups :dict = None, organization :str = None, eventId :int = None, allCollectorGroups :bool = None, allOrganizations :bool = None, allDestinations :bool = None, allUsers :bool = None, comment :str = None, forceCreate :bool = None, exceptionId :int = None, useAnyPath: object = None, useInException: object = None, wildcardFiles: object = None, wildcardPaths: object = None) -> tuple[bool, str]:
		url = '/management-rest/events/create-exception'
		url_params = list()
		if destinations:
			url_params.append('destinations=' + destinations)
		if users:
			url_params.append('users=' + users)
		if collectorGroups:
			url_params.append('collectorGroups=' + collectorGroups)
		if organization:
			url_params.append('organization=' + organization)
		if eventId:
			url_params.append('eventId=' + eventId)
		if allCollectorGroups:
			url_params.append('allCollectorGroups=' + allCollectorGroups)
		if allOrganizations:
			url_params.append('allOrganizations=' + allOrganizations)
		if allDestinations:
			url_params.append('allDestinations=' + allDestinations)
		if allUsers:
			url_params.append('allUsers=' + allUsers)
		if comment:
			url_params.append('comment=' + comment)
		if forceCreate:
			url_params.append('forceCreate=' + forceCreate)
		if exceptionId:
			url_params.append('exceptionId=' + exceptionId)
		url += '?' + '&'.join(url_params)
		exceptionRequest = {
			'useAnyPath': useAnyPath,
			'useInException': useInException,
			'wildcardFiles': wildcardFiles,
			'wildcardPaths': wildcardPaths
		}
		return fortiedr.send(url, exceptionRequest)


	'''
	class Events: Get event as Json format.
	'''
	def export_raw_data_items_json(self, organization :str = None, rawItemIds :str = None) -> tuple[bool, None]:
		url = '/management-rest/events/export-raw-data-items-json'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if rawItemIds:
			url_params.append('rawItemIds=' + rawItemIds)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)


	'''
	class Events: List Events.
	'''
	def list_events(self, eventIds :dict = None, collectorGroups :dict = None, deviceIps :dict = None, macAddresses :dict = None, severities :dict = None, classifications :dict = None, actions :dict = None, paths :dict = None, operatingSystems :dict = None, destinations :dict = None, eventType :dict = None, pageNumber :int = None, strictMode :bool = None, itemsPerPage :int = None, sorting :str = None, organization :str = None, device :str = None, process :str = None, fileHash :str = None, firstSeen :str = None, lastSeen :str = None, firstSeenFrom :str = None, firstSeenTo :str = None, lastSeenFrom :str = None, lastSeenTo :str = None, seen :bool = None, handled :bool = None, rule :str = None, loggedUser :str = None, archived :bool = None, signed :bool = None, muted :bool = None, deviceControl :bool = None, expired :bool = None) -> tuple[bool, dict]:
		url = '/management-rest/events/list-events'
		url_params = list()
		if eventIds:
			url_params.append('eventIds=' + eventIds)
		if collectorGroups:
			url_params.append('collectorGroups=' + collectorGroups)
		if deviceIps:
			url_params.append('deviceIps=' + deviceIps)
		if macAddresses:
			url_params.append('macAddresses=' + macAddresses)
		if severities:
			url_params.append('severities=' + severities)
		if classifications:
			url_params.append('classifications=' + classifications)
		if actions:
			url_params.append('actions=' + actions)
		if paths:
			url_params.append('paths=' + paths)
		if operatingSystems:
			url_params.append('operatingSystems=' + operatingSystems)
		if destinations:
			url_params.append('destinations=' + destinations)
		if eventType:
			url_params.append('eventType=' + eventType)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if sorting:
			url_params.append('sorting=' + sorting)
		if organization:
			url_params.append('organization=' + organization)
		if device:
			url_params.append('device=' + device)
		if process:
			url_params.append('process=' + process)
		if fileHash:
			url_params.append('fileHash=' + fileHash)
		if firstSeen:
			url_params.append('firstSeen=' + firstSeen)
		if lastSeen:
			url_params.append('lastSeen=' + lastSeen)
		if firstSeenFrom:
			url_params.append('firstSeenFrom=' + firstSeenFrom)
		if firstSeenTo:
			url_params.append('firstSeenTo=' + firstSeenTo)
		if lastSeenFrom:
			url_params.append('lastSeenFrom=' + lastSeenFrom)
		if lastSeenTo:
			url_params.append('lastSeenTo=' + lastSeenTo)
		if seen:
			url_params.append('seen=' + seen)
		if handled:
			url_params.append('handled=' + handled)
		if rule:
			url_params.append('rule=' + rule)
		if loggedUser:
			url_params.append('loggedUser=' + loggedUser)
		if archived:
			url_params.append('archived=' + archived)
		if signed:
			url_params.append('signed=' + signed)
		if muted:
			url_params.append('muted=' + muted)
		if deviceControl:
			url_params.append('deviceControl=' + deviceControl)
		if expired:
			url_params.append('expired=' + expired)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)


	'''
	class Events: List raw data items.
	'''
	def list_raw_data_items(self, eventId : int, deviceIps :dict = None, collectorGroups :dict = None, destinations :dict = None, rawEventIds :dict = None, pageNumber :int = None, strictMode :bool = None, itemsPerPage :int = None, sorting :str = None, organization :str = None, device :str = None, firstSeen :str = None, lastSeen :str = None, firstSeenFrom :str = None, firstSeenTo :str = None, lastSeenFrom :str = None, lastSeenTo :str = None, fullDataRequested :bool = None, loggedUser :str = None) -> tuple[bool, dict]:
		url = '/management-rest/events/list-raw-data-items'
		url_params = list()
		if deviceIps:
			url_params.append('deviceIps=' + deviceIps)
		if collectorGroups:
			url_params.append('collectorGroups=' + collectorGroups)
		if destinations:
			url_params.append('destinations=' + destinations)
		if rawEventIds:
			url_params.append('rawEventIds=' + rawEventIds)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if sorting:
			url_params.append('sorting=' + sorting)
		if organization:
			url_params.append('organization=' + organization)
		if eventId:
			url_params.append('eventId=' + eventId)
		if device:
			url_params.append('device=' + device)
		if firstSeen:
			url_params.append('firstSeen=' + firstSeen)
		if lastSeen:
			url_params.append('lastSeen=' + lastSeen)
		if firstSeenFrom:
			url_params.append('firstSeenFrom=' + firstSeenFrom)
		if firstSeenTo:
			url_params.append('firstSeenTo=' + firstSeenTo)
		if lastSeenFrom:
			url_params.append('lastSeenFrom=' + lastSeenFrom)
		if lastSeenTo:
			url_params.append('lastSeenTo=' + lastSeenTo)
		if fullDataRequested:
			url_params.append('fullDataRequested=' + fullDataRequested)
		if loggedUser:
			url_params.append('loggedUser=' + loggedUser)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)

class Exceptions:

	'''
	class Exceptions: This API call creates a new exception or updates an existing exception based on the given exception JSON body parameter.
	'''
	def create_or_edit_exception(self, organization :str = None, confirmEdit :bool = None, exceptionJSON :str = None) -> tuple[bool, int]:
		url = '/management-rest/exceptions/create-or-edit-exception'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if confirmEdit:
			url_params.append('confirmEdit=' + confirmEdit)
		url += '?' + '&'.join(url_params)
		return fortiedr.send(url)


	'''
	class Exceptions: Delete exceptions.
	'''
	def delete(self, exceptionIds :dict = None, rules :dict = None, collectorGroups :dict = None, organization :str = None, createdBefore :str = None, createdAfter :str = None, updatedBefore :str = None, updatedAfter :str = None, process :str = None, path :str = None, comment :str = None, destination :str = None, user :str = None, deleteAll :bool = None, exceptionId :int = None) -> tuple[bool, None]:
		url = '/management-rest/exceptions/delete'
		url_params = list()
		if exceptionIds:
			url_params.append('exceptionIds=' + exceptionIds)
		if rules:
			url_params.append('rules=' + rules)
		if collectorGroups:
			url_params.append('collectorGroups=' + collectorGroups)
		if organization:
			url_params.append('organization=' + organization)
		if createdBefore:
			url_params.append('createdBefore=' + createdBefore)
		if createdAfter:
			url_params.append('createdAfter=' + createdAfter)
		if updatedBefore:
			url_params.append('updatedBefore=' + updatedBefore)
		if updatedAfter:
			url_params.append('updatedAfter=' + updatedAfter)
		if process:
			url_params.append('process=' + process)
		if path:
			url_params.append('path=' + path)
		if comment:
			url_params.append('comment=' + comment)
		if destination:
			url_params.append('destination=' + destination)
		if user:
			url_params.append('user=' + user)
		if deleteAll:
			url_params.append('deleteAll=' + deleteAll)
		if exceptionId:
			url_params.append('exceptionId=' + exceptionId)
		url += '?' + '&'.join(url_params)
		return fortiedr.delete(url)


	'''
	class Exceptions: Show exceptions.
	'''
	def get_event_exceptions(self, eventId : int, organization :str = None) -> tuple[bool, dict]:
		url = '/management-rest/exceptions/get-event-exceptions'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if eventId:
			url_params.append('eventId=' + eventId)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)


	'''
	class Exceptions: List of exceptions.
	'''
	def list_exceptions(self, exceptionIds :dict = None, rules :dict = None, collectorGroups :dict = None, organization :str = None, createdBefore :str = None, createdAfter :str = None, updatedBefore :str = None, updatedAfter :str = None, process :str = None, path :str = None, comment :str = None, destination :str = None, user :str = None) -> tuple[bool, dict]:
		url = '/management-rest/exceptions/list-exceptions'
		url_params = list()
		if exceptionIds:
			url_params.append('exceptionIds=' + exceptionIds)
		if rules:
			url_params.append('rules=' + rules)
		if collectorGroups:
			url_params.append('collectorGroups=' + collectorGroups)
		if organization:
			url_params.append('organization=' + organization)
		if createdBefore:
			url_params.append('createdBefore=' + createdBefore)
		if createdAfter:
			url_params.append('createdAfter=' + createdAfter)
		if updatedBefore:
			url_params.append('updatedBefore=' + updatedBefore)
		if updatedAfter:
			url_params.append('updatedAfter=' + updatedAfter)
		if process:
			url_params.append('process=' + process)
		if path:
			url_params.append('path=' + path)
		if comment:
			url_params.append('comment=' + comment)
		if destination:
			url_params.append('destination=' + destination)
		if user:
			url_params.append('user=' + user)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)

class Forensics:

	'''
	class Forensics: This API call retrieves a file or memory.
	'''
	def get_event_file(self, rawEventId : int, filePaths :dict = None, organization :str = None, startRange :str = None, endRange :str = None, processId :int = None, memory :bool = None, disk :bool = None) -> tuple[bool, None]:
		url = '/management-rest/forensics/get-event-file'
		url_params = list()
		if filePaths:
			url_params.append('filePaths=' + filePaths)
		if organization:
			url_params.append('organization=' + organization)
		if startRange:
			url_params.append('startRange=' + startRange)
		if endRange:
			url_params.append('endRange=' + endRange)
		if rawEventId:
			url_params.append('rawEventId=' + rawEventId)
		if processId:
			url_params.append('processId=' + processId)
		if memory:
			url_params.append('memory=' + memory)
		if disk:
			url_params.append('disk=' + disk)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)


	'''
	class Forensics: This API call retrieves a file or memory.
	'''
	def get_file(self, filePaths : dict, type : str, device : str, organization :str = None) -> tuple[bool, None]:
		url = '/management-rest/forensics/get-file'
		url_params = list()
		if filePaths:
			url_params.append('filePaths=' + filePaths)
		if organization:
			url_params.append('organization=' + organization)
		if type:
			url_params.append('type=' + type)
		if device:
			url_params.append('device=' + device)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)


	'''
	class Forensics: This API kill process / delete file / clean persistence, File and persistence paths must be specified in a logical format.
	'''
	def remediate_device(self, terminatedProcessId : int, executablesToRemove :dict = None, organization :str = None, processName :str = None, device :str = None, deviceId :int = None, persistenceDataAction :str = None, persistenceDataPath :str = None, persistenceDataValueName :str = None, persistenceDataValueNewType :str = None, persistenceDataNewContent :str = None, threadId :int = None) -> tuple[bool, None]:
		url = '/management-rest/forensics/remediate-device'
		url_params = list()
		if executablesToRemove:
			url_params.append('executablesToRemove=' + executablesToRemove)
		if organization:
			url_params.append('organization=' + organization)
		if terminatedProcessId:
			url_params.append('terminatedProcessId=' + terminatedProcessId)
		if processName:
			url_params.append('processName=' + processName)
		if device:
			url_params.append('device=' + device)
		if deviceId:
			url_params.append('deviceId=' + deviceId)
		if persistenceDataAction:
			url_params.append('persistenceDataAction=' + persistenceDataAction)
		if persistenceDataPath:
			url_params.append('persistenceDataPath=' + persistenceDataPath)
		if persistenceDataValueName:
			url_params.append('persistenceDataValueName=' + persistenceDataValueName)
		if persistenceDataValueNewType:
			url_params.append('persistenceDataValueNewType=' + persistenceDataValueNewType)
		if persistenceDataNewContent:
			url_params.append('persistenceDataNewContent=' + persistenceDataNewContent)
		if threadId:
			url_params.append('threadId=' + threadId)
		url += '?' + '&'.join(url_params)
		return fortiedr.insert(url)

class HashSearch:

	'''
	class HashSearch: This API enables the user to search a file hash among the current events, threat hunting repository and communicating applications that exist in the system.
	'''
	def search(self, fileHashes : dict, organization :str = None) -> tuple[bool, None]:
		url = '/management-rest/hash/search'
		url_params = list()
		if fileHashes:
			url_params.append('fileHashes=' + fileHashes)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)

class IPsets:

	'''
	class IPsets: This API create IP sets in the system.
Use the input parameter organization=All organizations to create for all the organization. (only for Admin role.
	'''
	def create_ip_set(self, include: dict, name: str, description: str = None, exclude: dict = None, organization: str = None) -> tuple[bool, None]:
		url = '/management-rest/ip-sets/create-ip-set'
		url_params = list()
		url += '?' + '&'.join(url_params)
		ipGroupsRequest = {
			'description': description,
			'exclude': exclude,
			'include': include,
			'name': name,
			'organization': organization
		}
		return fortiedr.send(url, ipGroupsRequest)


	'''
	class IPsets: This API delete IP sets from the system. Use the input parameters to filter organization.
	'''
	def delete_ip_set(self, ipSets : dict, organization :str = None) -> tuple[bool, None]:
		url = '/management-rest/ip-sets/delete-ip-set'
		url_params = list()
		if ipSets:
			url_params.append('ipSets=' + ipSets)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr.delete(url)


	'''
	class IPsets: This API call outputs a list of the IP sets in the system. Use the input parameters to filter the list.
	'''
	def list_ip_sets(self, organization :str = None, ip :str = None) -> tuple[bool, dict]:
		url = '/management-rest/ip-sets/list-ip-sets'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if ip:
			url_params.append('ip=' + ip)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)


	'''
	class IPsets: This API update IP sets in the system. Use the input parameters to filter organization.
	'''
	def update_ip_set(self, include: dict, name: str, organization :str = None, description: str = None, exclude: dict = None) -> tuple[bool, None]:
		url = '/management-rest/ip-sets/update-ip-set'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		ipGroupsRequest = {
			'description': description,
			'exclude': exclude,
			'include': include,
			'name': name
		}
		return fortiedr.insert(url, ipGroupsRequest)

class Integrations:

	'''
	class Integrations: Get connectors metadata, describing the valid values for connector fields definition and on-premise cores..
	'''
	def connectors_metadata(self, organization :str = None) -> tuple[bool, None]:
		url = '/management-rest/integrations/connectors-metadata'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)


	'''
	class Integrations: Creates a new connector. Please note: Creation of Custom connectors/actions is not yet support..
	'''
	def create_connector(self, connectorActions: dict, enabled: bool, host: str, name: str, organization: str, port: str, type: str, vendor: str, apiKey: str = None, coreId: int = None, password: str = None, username: str = None) -> tuple[bool, None]:
		url = '/management-rest/integrations/create-connector'
		url_params = list()
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
		return fortiedr.send(url, createConnectorRequest)


	'''
	class Integrations: Deletes a connector.
	'''
	def delete_connector(self, connectorName : str, connectorType : str, organization :str = None) -> tuple[bool, None]:
		url = '/management-rest/integrations/delete-connector'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if connectorName:
			url_params.append('connectorName=' + connectorName)
		if connectorType:
			url_params.append('connectorType=' + connectorType)
		url += '?' + '&'.join(url_params)
		return fortiedr.delete(url)


	'''
	class Integrations: List all organization connectors.
	'''
	def list_connectors(self, organization :str = None, onlyValidConnectors :bool = None) -> tuple[bool, dict]:
		url = '/management-rest/integrations/list-connectors'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if onlyValidConnectors:
			url_params.append('onlyValidConnectors=' + onlyValidConnectors)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)


	'''
	class Integrations: Tests a connector.
	'''
	def test_connector(self, connectorName : str, connectorType : str, organization :str = None) -> tuple[bool, None]:
		url = '/management-rest/integrations/test-connector'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if connectorName:
			url_params.append('connectorName=' + connectorName)
		if connectorType:
			url_params.append('connectorType=' + connectorType)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)


	'''
	class Integrations: Updates an existing connector based on (name, type, organization). Please note: Modification of Custom connectors/actions is not yet support..
	'''
	def update_connector(self, connectorActions: dict, enabled: bool, host: str, name: str, organization: str, port: str, type: str, vendor: str, apiKey: str = None, coreId: int = None, password: str = None, username: str = None) -> tuple[bool, None]:
		url = '/management-rest/integrations/update-connector'
		url_params = list()
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
		return fortiedr.insert(url, updateConnectorRequest)

class IoT:

	'''
	class IoT: This API call create IoT group.
	'''
	def create_iot_group(self, name : str, organization :str = None) -> tuple[bool, None]:
		url = '/management-rest/iot/create-iot-group'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if name:
			url_params.append('name=' + name)
		url += '?' + '&'.join(url_params)
		return fortiedr.send(url)


	'''
	class IoT: This API call deletes a IoT device(s).
	'''
	def delete_devices(self, devicesIds :dict = None, devices :dict = None, iotGroups :dict = None, iotGroupsIds :dict = None, internalIps :dict = None, macAddresses :dict = None, categories :dict = None, models :dict = None, vendors :dict = None, locations :dict = None, pageNumber :int = None, strictMode :bool = None, itemsPerPage :int = None, sorting :str = None, organization :str = None, lastSeenStart :str = None, lastSeenEnd :str = None, firstSeenStart :str = None, firstSeenEnd :str = None, showExpired :bool = None) -> tuple[bool, None]:
		url = '/management-rest/iot/delete-devices'
		url_params = list()
		if devicesIds:
			url_params.append('devicesIds=' + devicesIds)
		if devices:
			url_params.append('devices=' + devices)
		if iotGroups:
			url_params.append('iotGroups=' + iotGroups)
		if iotGroupsIds:
			url_params.append('iotGroupsIds=' + iotGroupsIds)
		if internalIps:
			url_params.append('internalIps=' + internalIps)
		if macAddresses:
			url_params.append('macAddresses=' + macAddresses)
		if categories:
			url_params.append('categories=' + categories)
		if models:
			url_params.append('models=' + models)
		if vendors:
			url_params.append('vendors=' + vendors)
		if locations:
			url_params.append('locations=' + locations)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if sorting:
			url_params.append('sorting=' + sorting)
		if organization:
			url_params.append('organization=' + organization)
		if lastSeenStart:
			url_params.append('lastSeenStart=' + lastSeenStart)
		if lastSeenEnd:
			url_params.append('lastSeenEnd=' + lastSeenEnd)
		if firstSeenStart:
			url_params.append('firstSeenStart=' + firstSeenStart)
		if firstSeenEnd:
			url_params.append('firstSeenEnd=' + firstSeenEnd)
		if showExpired:
			url_params.append('showExpired=' + showExpired)
		url += '?' + '&'.join(url_params)
		return fortiedr.delete(url)


	'''
	class IoT: This API call outputs a list of the IoT devices info.
	'''
	def export_iot_json(self, iotDeviceIds : dict, organization :str = None) -> tuple[bool, None]:
		url = '/management-rest/iot/export-iot-json'
		url_params = list()
		if iotDeviceIds:
			url_params.append('iotDeviceIds=' + iotDeviceIds)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)


	'''
	class IoT: This API call outputs a list of the IoT devices in the system. Use the input parameters to filter the list.
	'''
	def list_iot_devices(self, devicesIds :dict = None, devices :dict = None, iotGroups :dict = None, iotGroupsIds :dict = None, internalIps :dict = None, macAddresses :dict = None, categories :dict = None, models :dict = None, vendors :dict = None, locations :dict = None, pageNumber :int = None, strictMode :bool = None, itemsPerPage :int = None, sorting :str = None, organization :str = None, lastSeenStart :str = None, lastSeenEnd :str = None, firstSeenStart :str = None, firstSeenEnd :str = None, showExpired :bool = None) -> tuple[bool, dict]:
		url = '/management-rest/iot/list-iot-devices'
		url_params = list()
		if devicesIds:
			url_params.append('devicesIds=' + devicesIds)
		if devices:
			url_params.append('devices=' + devices)
		if iotGroups:
			url_params.append('iotGroups=' + iotGroups)
		if iotGroupsIds:
			url_params.append('iotGroupsIds=' + iotGroupsIds)
		if internalIps:
			url_params.append('internalIps=' + internalIps)
		if macAddresses:
			url_params.append('macAddresses=' + macAddresses)
		if categories:
			url_params.append('categories=' + categories)
		if models:
			url_params.append('models=' + models)
		if vendors:
			url_params.append('vendors=' + vendors)
		if locations:
			url_params.append('locations=' + locations)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if sorting:
			url_params.append('sorting=' + sorting)
		if organization:
			url_params.append('organization=' + organization)
		if lastSeenStart:
			url_params.append('lastSeenStart=' + lastSeenStart)
		if lastSeenEnd:
			url_params.append('lastSeenEnd=' + lastSeenEnd)
		if firstSeenStart:
			url_params.append('firstSeenStart=' + firstSeenStart)
		if firstSeenEnd:
			url_params.append('firstSeenEnd=' + firstSeenEnd)
		if showExpired:
			url_params.append('showExpired=' + showExpired)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)


	'''
	class IoT: This API call output the IoT devices groups.
	'''
	def list_iot_groups(self, organization :str = None) -> tuple[bool, dict]:
		url = '/management-rest/iot/list-iot-groups'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)


	'''
	class IoT: This API call move IoT devices between groups.
	'''
	def move_iot_devices(self, iotDeviceIds : dict, targetIotGroup : str, organization :str = None) -> tuple[bool, None]:
		url = '/management-rest/iot/move-iot-devices'
		url_params = list()
		if iotDeviceIds:
			url_params.append('iotDeviceIds=' + iotDeviceIds)
		if organization:
			url_params.append('organization=' + organization)
		if targetIotGroup:
			url_params.append('targetIotGroup=' + targetIotGroup)
		url += '?' + '&'.join(url_params)
		return fortiedr.insert(url)


	'''
	class IoT: This API call device details scan on IoT device(s).
	'''
	def rescan_iot_device_details(self, devicesIds :dict = None, devices :dict = None, iotGroups :dict = None, iotGroupsIds :dict = None, internalIps :dict = None, macAddresses :dict = None, categories :dict = None, models :dict = None, vendors :dict = None, locations :dict = None, pageNumber :int = None, strictMode :bool = None, itemsPerPage :int = None, sorting :str = None, organization :str = None, lastSeenStart :str = None, lastSeenEnd :str = None, firstSeenStart :str = None, firstSeenEnd :str = None, showExpired :bool = None) -> tuple[bool, str]:
		url = '/management-rest/iot/rescan-iot-device-details'
		url_params = list()
		if devicesIds:
			url_params.append('devicesIds=' + devicesIds)
		if devices:
			url_params.append('devices=' + devices)
		if iotGroups:
			url_params.append('iotGroups=' + iotGroups)
		if iotGroupsIds:
			url_params.append('iotGroupsIds=' + iotGroupsIds)
		if internalIps:
			url_params.append('internalIps=' + internalIps)
		if macAddresses:
			url_params.append('macAddresses=' + macAddresses)
		if categories:
			url_params.append('categories=' + categories)
		if models:
			url_params.append('models=' + models)
		if vendors:
			url_params.append('vendors=' + vendors)
		if locations:
			url_params.append('locations=' + locations)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if sorting:
			url_params.append('sorting=' + sorting)
		if organization:
			url_params.append('organization=' + organization)
		if lastSeenStart:
			url_params.append('lastSeenStart=' + lastSeenStart)
		if lastSeenEnd:
			url_params.append('lastSeenEnd=' + lastSeenEnd)
		if firstSeenStart:
			url_params.append('firstSeenStart=' + firstSeenStart)
		if firstSeenEnd:
			url_params.append('firstSeenEnd=' + firstSeenEnd)
		if showExpired:
			url_params.append('showExpired=' + showExpired)
		url += '?' + '&'.join(url_params)
		return fortiedr.insert(url)

class Organizations:

	'''
	class Organizations: This API creates organization in the system (only for Admin role).
	'''
	def create_organization(self, expirationDate: str, name: str, password: str, passwordConfirmation: str, eXtendedDetection: bool = None, edr: bool = None, edrAddOnsAllocated: int = None, edrBackupEnabled: bool = None, edrEnabled: bool = None, edrNumberOfShards: int = None, edrStorageAllocatedInMb: int = None, forensics: bool = None, iotAllocated: int = None, requestPolicyEngineLibUpdates: bool = None, serialNumber: str = None, serversAllocated: int = None, vulnerabilityAndIoT: bool = None, workstationsAllocated: int = None) -> tuple[bool, None]:
		url = '/management-rest/organizations/create-organization'
		url_params = list()
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
		return fortiedr.send(url, createAccountRequest)


	'''
	class Organizations: This API delete organization in the system (only for Admin role).
	'''
	def delete_organization(self, organization :str = None) -> tuple[bool, None]:
		url = '/management-rest/organizations/delete-organization'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr.delete(url)


	'''
	class Organizations: Export organization data as zip file.
	'''
	def export_organization(self, organization :str = None, destinationName :str = None) -> tuple[bool, None]:
		url = '/management-rest/organizations/export-organization'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if destinationName:
			url_params.append('destinationName=' + destinationName)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)


	'''
	class Organizations: Import organization.
	'''
	def import_organization(self, file :BinaryIO = None) -> tuple[bool, None]:
		url = '/management-rest/organizations/import-organization'
		url_params = list()
		url += '?' + '&'.join(url_params)
		return fortiedr.send(url)


	'''
	class Organizations: This API call outputs a list of the accounts in the system..
	'''
	def list_organizations(self) -> tuple[bool, dict]:
		url = '/management-rest/organizations/list-organizations'
		return fortiedr.get(url)


	'''
	class Organizations: Transfer collectors from aggregator to aggregator as the organization migration process.
	'''
	def transfer_collectors(self, aggregatorsMap: dict, sourceOrganization: str, targetOrganization: str, verificationCode: str) -> tuple[bool, None]:
		url = '/management-rest/organizations/transfer-collectors'
		url_params = list()
		url += '?' + '&'.join(url_params)
		transferCollectorRequests = {
			'aggregatorsMap': aggregatorsMap,
			'sourceOrganization': sourceOrganization,
			'targetOrganization': targetOrganization,
			'verificationCode': verificationCode
		}
		return fortiedr.send(url, transferCollectorRequests)


	'''
	class Organizations: Transfer collector stop.
	'''
	def transfer_collectors_stop(self, organization :str = None) -> tuple[bool, None]:
		url = '/management-rest/organizations/transfer-collectors-stop'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr.send(url)


	'''
	class Organizations: This API update organization in the system (only for Admin role).
	'''
	def update_organization(self, organization :str = None, eXtendedDetection: bool = None, edr: bool = None, edrAddOnsAllocated: int = None, edrBackupEnabled: bool = None, edrEnabled: bool = None, edrNumberOfShards: int = None, edrStorageAllocatedInMb: int = None, expirationDate: str = None, forensics: bool = None, iotAllocated: int = None, name: str = None, requestPolicyEngineLibUpdates: bool = None, serialNumber: str = None, serversAllocated: int = None, vulnerabilityAndIoT: bool = None, workstationsAllocated: int = None) -> tuple[bool, None]:
		url = '/management-rest/organizations/update-organization'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		accountRequest = {
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
			'requestPolicyEngineLibUpdates': requestPolicyEngineLibUpdates,
			'serialNumber': serialNumber,
			'serversAllocated': serversAllocated,
			'vulnerabilityAndIoT': vulnerabilityAndIoT,
			'workstationsAllocated': workstationsAllocated
		}
		return fortiedr.insert(url, accountRequest)

class Playbookspolicies:

	'''
	class Playbookspolicies: Assign collector group to air policy.
	'''
	def assign_collector_group(self, collectorGroupNames : dict, policyName : str, organization :str = None, forceAssign :bool = None) -> tuple[bool, None]:
		url = '/management-rest/playbooks-policies/assign-collector-group'
		url_params = list()
		if collectorGroupNames:
			url_params.append('collectorGroupNames=' + collectorGroupNames)
		if organization:
			url_params.append('organization=' + organization)
		if policyName:
			url_params.append('policyName=' + policyName)
		if forceAssign:
			url_params.append('forceAssign=' + forceAssign)
		url += '?' + '&'.join(url_params)
		return fortiedr.insert(url)


	'''
	class Playbookspolicies: clone policy.
	'''
	def clone(self, sourcePolicyName : str, newPolicyName : str, organization :str = None) -> tuple[bool, None]:
		url = '/management-rest/playbooks-policies/clone'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if sourcePolicyName:
			url_params.append('sourcePolicyName=' + sourcePolicyName)
		if newPolicyName:
			url_params.append('newPolicyName=' + newPolicyName)
		url += '?' + '&'.join(url_params)
		return fortiedr.send(url)


	'''
	class Playbookspolicies: List policies.
	'''
	def list_policies(self, organization :str = None) -> tuple[bool, dict]:
		url = '/management-rest/playbooks-policies/list-policies'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)


	'''
	class Playbookspolicies: Assign policy actions with connectors..
	'''
	def map_connectors_to_actions(self, policyName: str, organization :str = None, customActionsToConnectorsMaps: dict = None, fortinetActionsToConnectorsMaps: dict = None) -> tuple[bool, None]:
		url = '/management-rest/playbooks-policies/map-connectors-to-actions'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		assignAIRActionsWithConnectorsRequest = {
			'customActionsToConnectorsMaps': customActionsToConnectorsMaps,
			'fortinetActionsToConnectorsMaps': fortinetActionsToConnectorsMaps,
			'policyName': policyName
		}
		return fortiedr.insert(url, assignAIRActionsWithConnectorsRequest)


	'''
	class Playbookspolicies: Set the air policy actions' classifications..
	'''
	def set_action_classification(self, policyName: str, organization :str = None, customActionsToClassificationMaps: dict = None, fortinetActionsToClassificationMaps: dict = None) -> tuple[bool, None]:
		url = '/management-rest/playbooks-policies/set-action-classification'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		setActionsClassificationRequest = {
			'customActionsToClassificationMaps': customActionsToClassificationMaps,
			'fortinetActionsToClassificationMaps': fortinetActionsToClassificationMaps,
			'policyName': policyName
		}
		return fortiedr.insert(url, setActionsClassificationRequest)


	'''
	class Playbookspolicies: Set playbook to simulation/prevention.
	'''
	def set_mode(self, policyName : str, mode : str, organization :str = None) -> tuple[bool, None]:
		url = '/management-rest/playbooks-policies/set-mode'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if policyName:
			url_params.append('policyName=' + policyName)
		if mode:
			url_params.append('mode=' + mode)
		url += '?' + '&'.join(url_params)
		return fortiedr.insert(url)

class Policies:

	'''
	class Policies: Assign collector group to policy.
	'''
	def assign_collector_group(self, collectorsGroupName : dict, policyName : str, organization :str = None, forceAssign :bool = None) -> tuple[bool, None]:
		url = '/management-rest/policies/assign-collector-group'
		url_params = list()
		if collectorsGroupName:
			url_params.append('collectorsGroupName=' + collectorsGroupName)
		if organization:
			url_params.append('organization=' + organization)
		if policyName:
			url_params.append('policyName=' + policyName)
		if forceAssign:
			url_params.append('forceAssign=' + forceAssign)
		url += '?' + '&'.join(url_params)
		return fortiedr.insert(url)


	'''
	class Policies: clone policy.
	'''
	def clone(self, sourcePolicyName : str, newPolicyName : str, organization :str = None) -> tuple[bool, None]:
		url = '/management-rest/policies/clone'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if sourcePolicyName:
			url_params.append('sourcePolicyName=' + sourcePolicyName)
		if newPolicyName:
			url_params.append('newPolicyName=' + newPolicyName)
		url += '?' + '&'.join(url_params)
		return fortiedr.send(url)


	'''
	class Policies: List policies.
	'''
	def list_policies(self, organization :str = None) -> tuple[bool, dict]:
		url = '/management-rest/policies/list-policies'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)


	'''
	class Policies: Set policy to simulation/prevention.
	'''
	def set_mode(self, policyName : str, mode : str, organization :str = None) -> tuple[bool, None]:
		url = '/management-rest/policies/set-mode'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if policyName:
			url_params.append('policyName=' + policyName)
		if mode:
			url_params.append('mode=' + mode)
		url += '?' + '&'.join(url_params)
		return fortiedr.insert(url)


	'''
	class Policies: Set rule in policy to block/log.
	'''
	def set_policy_rule_action(self, policyName : str, ruleName : str, action : str, organization :str = None) -> tuple[bool, None]:
		url = '/management-rest/policies/set-policy-rule-action'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if policyName:
			url_params.append('policyName=' + policyName)
		if ruleName:
			url_params.append('ruleName=' + ruleName)
		if action:
			url_params.append('action=' + action)
		url += '?' + '&'.join(url_params)
		return fortiedr.insert(url)


	'''
	class Policies: Set rule in policy to enable/disable.
	'''
	def set_policy_rule_state(self, policyName : str, ruleName : str, state : str, organization :str = None) -> tuple[bool, None]:
		url = '/management-rest/policies/set-policy-rule-state'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if policyName:
			url_params.append('policyName=' + policyName)
		if ruleName:
			url_params.append('ruleName=' + ruleName)
		if state:
			url_params.append('state=' + state)
		url += '?' + '&'.join(url_params)
		return fortiedr.insert(url)

class SendableEntities:

	'''
	class SendableEntities: set mail format.
	'''
	def set_mail_format(self, format : str, organization :str = None) -> tuple[bool, None]:
		url = '/management-rest/sendable-entities/set-mail-format'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if format:
			url_params.append('format=' + format)
		url += '?' + '&'.join(url_params)
		return fortiedr.insert(url)

class SystemEvents:

	'''
	class SystemEvents: Retrieve system events.
	'''
	def list_system_events(self, componentNames :dict = None, componentTypes :dict = None, pageNumber :int = None, strictMode :bool = None, itemsPerPage :int = None, sorting :str = None, organization :str = None, fromDate :str = None, toDate :str = None) -> tuple[bool, dict]:
		url = '/management-rest/system-events/list-system-events'
		url_params = list()
		if componentNames:
			url_params.append('componentNames=' + componentNames)
		if componentTypes:
			url_params.append('componentTypes=' + componentTypes)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if sorting:
			url_params.append('sorting=' + sorting)
		if organization:
			url_params.append('organization=' + organization)
		if fromDate:
			url_params.append('fromDate=' + fromDate)
		if toDate:
			url_params.append('toDate=' + toDate)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)

class SystemInventory:

	'''
	class SystemInventory: This API call retrieves a aggregator logs.
	'''
	def aggregator_logs(self, organization :str = None, device :str = None, deviceId :int = None) -> tuple[bool, None]:
		url = '/management-rest/inventory/aggregator-logs'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if device:
			url_params.append('device=' + device)
		if deviceId:
			url_params.append('deviceId=' + deviceId)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)


	'''
	class SystemInventory: This API call retrieves a collector logs.
	'''
	def collector_logs(self, organization :str = None, device :str = None, deviceId :int = None) -> tuple[bool, None]:
		url = '/management-rest/inventory/collector-logs'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if device:
			url_params.append('device=' + device)
		if deviceId:
			url_params.append('deviceId=' + deviceId)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)


	'''
	class SystemInventory: This API call retrieves a core logs.
	'''
	def core_logs(self, organization :str = None, device :str = None, deviceId :int = None) -> tuple[bool, None]:
		url = '/management-rest/inventory/core-logs'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if device:
			url_params.append('device=' + device)
		if deviceId:
			url_params.append('deviceId=' + deviceId)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)


	'''
	class SystemInventory: This API call create collector group.
	'''
	def create_collector_group(self, name : str, organization :str = None) -> tuple[bool, None]:
		url = '/management-rest/inventory/create-collector-group'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if name:
			url_params.append('name=' + name)
		url += '?' + '&'.join(url_params)
		return fortiedr.send(url)


	'''
	class SystemInventory: This API call deletes a Collector(s).
	'''
	def delete_collectors(self, devicesIds :dict = None, devices :dict = None, collectorGroups :dict = None, ips :dict = None, operatingSystems :dict = None, osFamilies :dict = None, states :dict = None, versions :dict = None, pageNumber :int = None, strictMode :bool = None, itemsPerPage :int = None, sorting :str = None, organization :str = None, firstSeen :str = None, lastSeenStart :str = None, lastSeenEnd :str = None, showExpired :bool = None, loggedUser :str = None, hasCrashDumps :bool = None, deleteAll :bool = None, confirmDeletion :bool = None) -> tuple[bool, None]:
		url = '/management-rest/inventory/delete-collectors'
		url_params = list()
		if devicesIds:
			url_params.append('devicesIds=' + devicesIds)
		if devices:
			url_params.append('devices=' + devices)
		if collectorGroups:
			url_params.append('collectorGroups=' + collectorGroups)
		if ips:
			url_params.append('ips=' + ips)
		if operatingSystems:
			url_params.append('operatingSystems=' + operatingSystems)
		if osFamilies:
			url_params.append('osFamilies=' + osFamilies)
		if states:
			url_params.append('states=' + states)
		if versions:
			url_params.append('versions=' + versions)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if sorting:
			url_params.append('sorting=' + sorting)
		if organization:
			url_params.append('organization=' + organization)
		if firstSeen:
			url_params.append('firstSeen=' + firstSeen)
		if lastSeenStart:
			url_params.append('lastSeenStart=' + lastSeenStart)
		if lastSeenEnd:
			url_params.append('lastSeenEnd=' + lastSeenEnd)
		if showExpired:
			url_params.append('showExpired=' + showExpired)
		if loggedUser:
			url_params.append('loggedUser=' + loggedUser)
		if hasCrashDumps:
			url_params.append('hasCrashDumps=' + hasCrashDumps)
		if deleteAll:
			url_params.append('deleteAll=' + deleteAll)
		if confirmDeletion:
			url_params.append('confirmDeletion=' + confirmDeletion)
		url += '?' + '&'.join(url_params)
		return fortiedr.delete(url)


	'''
	class SystemInventory: This API call isolate collector functionality.
	'''
	def isolate_collectors(self, devicesIds :dict = None, devices :dict = None, organization :str = None) -> tuple[bool, None]:
		url = '/management-rest/inventory/isolate-collectors'
		url_params = list()
		if devicesIds:
			url_params.append('devicesIds=' + devicesIds)
		if devices:
			url_params.append('devices=' + devices)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr.insert(url)


	'''
	class SystemInventory: This API call output the list of aggregators.
	'''
	def list_aggregators(self, names :dict = None, versions :dict = None, organization :str = None, ip :str = None) -> tuple[bool, dict]:
		url = '/management-rest/inventory/list-aggregators'
		url_params = list()
		if names:
			url_params.append('names=' + names)
		if versions:
			url_params.append('versions=' + versions)
		if organization:
			url_params.append('organization=' + organization)
		if ip:
			url_params.append('ip=' + ip)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)


	'''
	class SystemInventory: This API call output the collectors groups.
	'''
	def list_collector_groups(self, organization :str = None) -> tuple[bool, dict]:
		url = '/management-rest/inventory/list-collector-groups'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)


	'''
	class SystemInventory: This API call outputs a list of the Collectors in the system. Use the input parameters to filter the list.
	'''
	def list_collectors(self, devicesIds :dict = None, devices :dict = None, collectorGroups :dict = None, ips :dict = None, operatingSystems :dict = None, osFamilies :dict = None, states :dict = None, versions :dict = None, pageNumber :int = None, strictMode :bool = None, itemsPerPage :int = None, sorting :str = None, organization :str = None, firstSeen :str = None, lastSeenStart :str = None, lastSeenEnd :str = None, showExpired :bool = None, loggedUser :str = None, hasCrashDumps :bool = None) -> tuple[bool, dict]:
		url = '/management-rest/inventory/list-collectors'
		url_params = list()
		if devicesIds:
			url_params.append('devicesIds=' + devicesIds)
		if devices:
			url_params.append('devices=' + devices)
		if collectorGroups:
			url_params.append('collectorGroups=' + collectorGroups)
		if ips:
			url_params.append('ips=' + ips)
		if operatingSystems:
			url_params.append('operatingSystems=' + operatingSystems)
		if osFamilies:
			url_params.append('osFamilies=' + osFamilies)
		if states:
			url_params.append('states=' + states)
		if versions:
			url_params.append('versions=' + versions)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if sorting:
			url_params.append('sorting=' + sorting)
		if organization:
			url_params.append('organization=' + organization)
		if firstSeen:
			url_params.append('firstSeen=' + firstSeen)
		if lastSeenStart:
			url_params.append('lastSeenStart=' + lastSeenStart)
		if lastSeenEnd:
			url_params.append('lastSeenEnd=' + lastSeenEnd)
		if showExpired:
			url_params.append('showExpired=' + showExpired)
		if loggedUser:
			url_params.append('loggedUser=' + loggedUser)
		if hasCrashDumps:
			url_params.append('hasCrashDumps=' + hasCrashDumps)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)


	'''
	class SystemInventory: This API call output the list of cores.
	'''
	def list_cores(self, names :dict = None, versions :dict = None, deploymentModes :dict = None, organization :str = None, ip :str = None, hasCrashDumps :bool = None) -> tuple[bool, dict]:
		url = '/management-rest/inventory/list-cores'
		url_params = list()
		if names:
			url_params.append('names=' + names)
		if versions:
			url_params.append('versions=' + versions)
		if deploymentModes:
			url_params.append('deploymentModes=' + deploymentModes)
		if organization:
			url_params.append('organization=' + organization)
		if ip:
			url_params.append('ip=' + ip)
		if hasCrashDumps:
			url_params.append('hasCrashDumps=' + hasCrashDumps)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)


	'''
	class SystemInventory: This API call output the list of repositories (edrs).
	'''
	def list_repositories(self) -> tuple[bool, dict]:
		url = '/management-rest/inventory/list-repositories'
		return fortiedr.get(url)


	'''
	class SystemInventory: This API call outputs a list of the unmanaged devices in the system.
	'''
	def list_unmanaged_devices(self, pageNumber :int = None, strictMode :bool = None, itemsPerPage :int = None, sorting :str = None, organization :str = None) -> tuple[bool, dict]:
		url = '/management-rest/inventory/list-unmanaged-devices'
		url_params = list()
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if sorting:
			url_params.append('sorting=' + sorting)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)


	'''
	class SystemInventory: This API call move collector between groups.
	'''
	def move_collectors(self, collectors : dict, targetCollectorGroup : str, organization :str = None, forceAssign :bool = None) -> tuple[bool, None]:
		url = '/management-rest/inventory/move-collectors'
		url_params = list()
		if collectors:
			url_params.append('collectors=' + collectors)
		if organization:
			url_params.append('organization=' + organization)
		if targetCollectorGroup:
			url_params.append('targetCollectorGroup=' + targetCollectorGroup)
		if forceAssign:
			url_params.append('forceAssign=' + forceAssign)
		url += '?' + '&'.join(url_params)
		return fortiedr.insert(url)


	'''
	class SystemInventory: This API call retrieves a system logs.
	'''
	def system_logs(self) -> tuple[bool, None]:
		url = '/management-rest/inventory/system-logs'
		return fortiedr.get(url)


	'''
	class SystemInventory: This API call enables/disables a Collector(s). You must specify whether the Collector is to be enabled or disabled.
	'''
	def toggle_collectors(self, enable : bool, devicesIds :dict = None, devices :dict = None, collectorGroups :dict = None, ips :dict = None, operatingSystems :dict = None, osFamilies :dict = None, states :dict = None, versions :dict = None, pageNumber :int = None, strictMode :bool = None, itemsPerPage :int = None, sorting :str = None, organization :str = None, firstSeen :str = None, lastSeenStart :str = None, lastSeenEnd :str = None, showExpired :bool = None, loggedUser :str = None, hasCrashDumps :bool = None) -> tuple[bool, str]:
		url = '/management-rest/inventory/toggle-collectors'
		url_params = list()
		if devicesIds:
			url_params.append('devicesIds=' + devicesIds)
		if devices:
			url_params.append('devices=' + devices)
		if collectorGroups:
			url_params.append('collectorGroups=' + collectorGroups)
		if ips:
			url_params.append('ips=' + ips)
		if operatingSystems:
			url_params.append('operatingSystems=' + operatingSystems)
		if osFamilies:
			url_params.append('osFamilies=' + osFamilies)
		if states:
			url_params.append('states=' + states)
		if versions:
			url_params.append('versions=' + versions)
		if pageNumber:
			url_params.append('pageNumber=' + pageNumber)
		if strictMode:
			url_params.append('strictMode=' + strictMode)
		if itemsPerPage:
			url_params.append('itemsPerPage=' + itemsPerPage)
		if sorting:
			url_params.append('sorting=' + sorting)
		if organization:
			url_params.append('organization=' + organization)
		if firstSeen:
			url_params.append('firstSeen=' + firstSeen)
		if lastSeenStart:
			url_params.append('lastSeenStart=' + lastSeenStart)
		if lastSeenEnd:
			url_params.append('lastSeenEnd=' + lastSeenEnd)
		if showExpired:
			url_params.append('showExpired=' + showExpired)
		if loggedUser:
			url_params.append('loggedUser=' + loggedUser)
		if hasCrashDumps:
			url_params.append('hasCrashDumps=' + hasCrashDumps)
		if enable:
			url_params.append('enable=' + enable)
		url += '?' + '&'.join(url_params)
		return fortiedr.insert(url)


	'''
	class SystemInventory: This API call isolate collector functionality.
	'''
	def unisolate_collectors(self, devicesIds :dict = None, devices :dict = None, organization :str = None) -> tuple[bool, None]:
		url = '/management-rest/inventory/unisolate-collectors'
		url_params = list()
		if devicesIds:
			url_params.append('devicesIds=' + devicesIds)
		if devices:
			url_params.append('devices=' + devices)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr.insert(url)

class ThreatHunting:

	'''
	class ThreatHunting: This API call outputs EDR total events for every EDR category.
	'''
	def counts(self, category: str = None, devices: dict = None, filters: dict = None, fromTime: str = None, itemsPerPage: int = None, organization: str = None, pageNumber: int = None, query: str = None, sorting: dict = None, time: str = None, toTime: str = None) -> tuple[bool, None]:
		url = '/management-rest/threat-hunting/counts'
		url_params = list()
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
		return fortiedr.send(url, edrRequest)


	'''
	class ThreatHunting: This API creates or edits the saved queries tag.
	'''
	def create_or_edit_tag(self, newTagName: str, organization: str = None, tagId: int = None, tagName: str = None) -> tuple[bool, None]:
		url = '/management-rest/threat-hunting/create-or-edit-tag'
		url_params = list()
		url += '?' + '&'.join(url_params)
		createOrEditTagRequest = {
			'newTagName': newTagName,
			'organization': organization,
			'tagId': tagId,
			'tagName': tagName
		}
		return fortiedr.send(url, createOrEditTagRequest)


	'''
	class ThreatHunting: This API customizes the scheduling properties of a Fortinet query.
	'''
	def customize_fortinet_query(self, id :int = None, queryToEdit :str = None, dayOfMonth: int = None, dayOfWeek: int = None, forceSaving: bool = None, frequency: int = None, frequencyUnit: str = None, fromTime: str = None, hour: int = None, organization: str = None, scheduled: bool = None, state: bool = None, time: str = None, toTime: str = None) -> tuple[bool, None]:
		url = '/management-rest/threat-hunting/customize-fortinet-query'
		url_params = list()
		if id:
			url_params.append('id=' + id)
		if queryToEdit:
			url_params.append('queryToEdit=' + queryToEdit)
		url += '?' + '&'.join(url_params)
		ootbQueryCustomizeRequest = {
			'dayOfMonth': dayOfMonth,
			'dayOfWeek': dayOfWeek,
			'forceSaving': forceSaving,
			'frequency': frequency,
			'frequencyUnit': frequencyUnit,
			'fromTime': fromTime,
			'hour': hour,
			'organization': organization,
			'scheduled': scheduled,
			'state': state,
			'time': time,
			'toTime': toTime
		}
		return fortiedr.send(url, ootbQueryCustomizeRequest)


	'''
	class ThreatHunting: This API deletes the saved queries.
	'''
	def delete_saved_queries(self, source :dict = None, queryIds :dict = None, queryNames :dict = None, organization :str = None, scheduled :bool = None, deleteFromCommunity :bool = None, deleteAll :bool = None) -> tuple[bool, None]:
		url = '/management-rest/threat-hunting/delete-saved-queries'
		url_params = list()
		if source:
			url_params.append('source=' + source)
		if queryIds:
			url_params.append('queryIds=' + queryIds)
		if queryNames:
			url_params.append('queryNames=' + queryNames)
		if organization:
			url_params.append('organization=' + organization)
		if scheduled:
			url_params.append('scheduled=' + scheduled)
		if deleteFromCommunity:
			url_params.append('deleteFromCommunity=' + deleteFromCommunity)
		if deleteAll:
			url_params.append('deleteAll=' + deleteAll)
		url += '?' + '&'.join(url_params)
		return fortiedr.delete(url)


	'''
	class ThreatHunting: This API deletes the saved queries tags.
	'''
	def delete_tags(self, tagIds :dict = None, tagNames :dict = None, organization :str = None) -> tuple[bool, None]:
		url = '/management-rest/threat-hunting/delete-tags'
		url_params = list()
		if tagIds:
			url_params.append('tagIds=' + tagIds)
		if tagNames:
			url_params.append('tagNames=' + tagNames)
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr.delete(url)


	'''
	class ThreatHunting: This API retrieves EDR total events for every EDR facet item.
	'''
	def facets(self, facets: dict, category: str = None, devices: dict = None, filters: dict = None, fromTime: str = None, itemsPerPage: int = None, organization: str = None, pageNumber: int = None, query: str = None, sorting: dict = None, time: str = None, toTime: str = None) -> tuple[bool, dict]:
		url = '/management-rest/threat-hunting/facets'
		url_params = list()
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
		return fortiedr.send(url, facetsRequest)


	'''
	class ThreatHunting: This API retrieves the existing saved queries list.
	'''
	def list_saved_queries(self, source :dict = None, organization :str = None, scheduled :bool = None) -> tuple[bool, dict]:
		url = '/management-rest/threat-hunting/list-saved-queries'
		url_params = list()
		if source:
			url_params.append('source=' + source)
		if organization:
			url_params.append('organization=' + organization)
		if scheduled:
			url_params.append('scheduled=' + scheduled)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)


	'''
	class ThreatHunting: This API retrieves the existing saved queries tag list.
	'''
	def list_tags(self, organization :str = None) -> tuple[bool, dict]:
		url = '/management-rest/threat-hunting/list-tags'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)


	'''
	class ThreatHunting: This API saves the query.
	'''
	def save_query(self, id :int = None, queryToEdit :str = None, category: str = None, classification: str = None, collectorNames: dict = None, community: bool = None, dayOfMonth: int = None, dayOfWeek: int = None, description: str = None, forceSaving: bool = None, frequency: int = None, frequencyUnit: str = None, fromTime: str = None, hour: int = None, name: str = None, organization: str = None, query: str = None, scheduled: bool = None, state: bool = None, tagIds: dict = None, tagNames: dict = None, time: str = None, toTime: str = None) -> tuple[bool, None]:
		url = '/management-rest/threat-hunting/save-query'
		url_params = list()
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
		return fortiedr.send(url, saveQueryRequest)


	'''
	class ThreatHunting: This API call outputs a list of Activity events from middleware..
	'''
	def search(self, category: str = None, devices: dict = None, filters: dict = None, fromTime: str = None, itemsPerPage: int = None, organization: str = None, pageNumber: int = None, query: str = None, sorting: dict = None, time: str = None, toTime: str = None) -> tuple[bool, dict]:
		url = '/management-rest/threat-hunting/search'
		url_params = list()
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
		return fortiedr.send(url, edrRequest)


	'''
	class ThreatHunting: This API updates the scheduled saved query state.
	'''
	def set_query_state(self, state : bool, source :dict = None, queryIds :dict = None, queryNames :dict = None, organization :str = None, markAll :bool = None) -> tuple[bool, None]:
		url = '/management-rest/threat-hunting/set-query-state'
		url_params = list()
		if source:
			url_params.append('source=' + source)
		if queryIds:
			url_params.append('queryIds=' + queryIds)
		if queryNames:
			url_params.append('queryNames=' + queryNames)
		if organization:
			url_params.append('organization=' + organization)
		if state:
			url_params.append('state=' + state)
		if markAll:
			url_params.append('markAll=' + markAll)
		url += '?' + '&'.join(url_params)
		return fortiedr.insert(url)

class ThreatHuntingExclusions:

	'''
	class ThreatHuntingExclusions: Creates exclusions..
	'''
	def send_exclusions(self, exclusionListName: str, exclusions: dict, organization: str) -> tuple[bool, dict]:
		url = '/management-rest/threat-hunting-exclusions/exclusion'
		url_params = list()
		url += '?' + '&'.join(url_params)
		createExclusionsRequest = {
			'exclusionListName': exclusionListName,
			'exclusions': exclusions,
			'organization': organization
		}
		return fortiedr.send(url, createExclusionsRequest)

	'''
	class ThreatHuntingExclusions: Creates exclusions..
	'''
	def insert_exclusions(self, exclusionListName: str, exclusions: dict, organization: str) -> tuple[bool, dict]:
		url = '/management-rest/threat-hunting-exclusions/exclusion'
		url_params = list()
		url += '?' + '&'.join(url_params)
		updateExclusionsRequest = {
			'exclusionListName': exclusionListName,
			'exclusions': exclusions,
			'organization': organization
		}
		return fortiedr.insert(url, updateExclusionsRequest)

	'''
	class ThreatHuntingExclusions: Creates exclusions..
	'''
	def delete_exclusion(self, exclusionIds: dict, organization: str) -> tuple[bool, str]:
		url = '/management-rest/threat-hunting-exclusions/exclusion'
		url_params = list()
		url += '?' + '&'.join(url_params)
		deleteExclusionsRequest = {
			'exclusionIds': exclusionIds,
			'organization': organization
		}
		return fortiedr.delete(url, deleteExclusionsRequest)


	'''
	class ThreatHuntingExclusions: Get the list of Exclusions lists..
	'''
	def get_exclusions_list(self, organization : str) -> tuple[bool, dict]:
		url = '/management-rest/threat-hunting-exclusions/exclusions-list'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)

	'''
	class ThreatHuntingExclusions: Get the list of Exclusions lists..
	'''
	def send_exclusions_list(self, name: str, organization: str, collectorGroupIds: dict = None) -> tuple[bool, None]:
		url = '/management-rest/threat-hunting-exclusions/exclusions-list'
		url_params = list()
		url += '?' + '&'.join(url_params)
		createExclusionListRequest = {
			'collectorGroupIds': collectorGroupIds,
			'name': name,
			'organization': organization
		}
		return fortiedr.send(url, createExclusionListRequest)

	'''
	class ThreatHuntingExclusions: Get the list of Exclusions lists..
	'''
	def insert_exclusions_list(self, collectorGroupIds: dict, listName: str, organization: str, newName: str = None) -> tuple[bool, None]:
		url = '/management-rest/threat-hunting-exclusions/exclusions-list'
		url_params = list()
		url += '?' + '&'.join(url_params)
		updateExclusionListRequest = {
			'collectorGroupIds': collectorGroupIds,
			'listName': listName,
			'newName': newName,
			'organization': organization
		}
		return fortiedr.insert(url, updateExclusionListRequest)

	'''
	class ThreatHuntingExclusions: Get the list of Exclusions lists..
	'''
	def delete_exclusions_list(self, organization : str, listName : str) -> tuple[bool, None]:
		url = '/management-rest/threat-hunting-exclusions/exclusions-list'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if listName:
			url_params.append('listName=' + listName)
		url += '?' + '&'.join(url_params)
		return fortiedr.delete(url)


	'''
	class ThreatHuntingExclusions: Get the metadata and available properties for exclusions configuration. When creating/modifying an exclusion, use the response of this API as a guide for the valid attribute names and values, and their corresponding EDR event types. Every attribute corresponds to an EDR category (for example, Filename attribute corresponds with the File category), and each category is a set of EDR event types. .
	'''
	def exclusions_metadata(self) -> tuple[bool, None]:
		url = '/management-rest/threat-hunting-exclusions/exclusions-metadata'
		return fortiedr.get(url)


	'''
	class ThreatHuntingExclusions: Free-text search of exclusions.
	'''
	def exclusions_search(self, searchText : str, os :dict = None, organization :str = None) -> tuple[bool, dict]:
		url = '/management-rest/threat-hunting-exclusions/exclusions-search'
		url_params = list()
		if os:
			url_params.append('os=' + os)
		if organization:
			url_params.append('organization=' + organization)
		if searchText:
			url_params.append('searchText=' + searchText)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)

class ThreatHuntingSettings:

	'''
	class ThreatHuntingSettings: Get the Threat Hunting Settings metadata object, listing the available configuration options (Category and Event Types)..
	'''
	def threat_hunting_metadata(self) -> tuple[bool, dict]:
		url = '/management-rest/threat-hunting-settings/threat-hunting-metadata'
		return fortiedr.get(url)


	'''
	class ThreatHuntingSettings: Get the list of Threat Hunting Setting profiles..
	'''
	def get_threat_hunting_profile(self, organization : str) -> tuple[bool, dict]:
		url = '/management-rest/threat-hunting-settings/threat-hunting-profile'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)

	'''
	class ThreatHuntingSettings: Get the list of Threat Hunting Setting profiles..
	'''
	def send_threat_hunting_profile(self, associatedCollectorGroupIds: dict, name: str, organization: str, threatHuntingCategoryList: dict, newName: str = None) -> tuple[bool, None]:
		url = '/management-rest/threat-hunting-settings/threat-hunting-profile'
		url_params = list()
		url += '?' + '&'.join(url_params)
		threatHuntingUpdateRequest = {
			'associatedCollectorGroupIds': associatedCollectorGroupIds,
			'name': name,
			'newName': newName,
			'organization': organization,
			'threatHuntingCategoryList': threatHuntingCategoryList
		}
		return fortiedr.send(url, threatHuntingUpdateRequest)

	'''
	class ThreatHuntingSettings: Get the list of Threat Hunting Setting profiles..
	'''
	def delete_threat_hunting_profile(self, organization : str, name : str) -> tuple[bool, None]:
		url = '/management-rest/threat-hunting-settings/threat-hunting-profile'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if name:
			url_params.append('name=' + name)
		url += '?' + '&'.join(url_params)
		return fortiedr.delete(url)


	'''
	class ThreatHuntingSettings: Clone a Threat Hunting Settings profile..
	'''
	def threat_hunting_profile_clone(self, organization : str, existingProfileName : str, cloneProfileName : str) -> tuple[bool, None]:
		url = '/management-rest/threat-hunting-settings/threat-hunting-profile-clone'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if existingProfileName:
			url_params.append('existingProfileName=' + existingProfileName)
		if cloneProfileName:
			url_params.append('cloneProfileName=' + cloneProfileName)
		url += '?' + '&'.join(url_params)
		return fortiedr.send(url)


	'''
	class ThreatHuntingSettings: Update Threat Hunting profile assigned collector groups. Returns the updated list of assigned collector groups..
	'''
	def threat_hunting_profile_assign_collector_groups(self, associatedCollectorGroupIds: dict, name: str, organization: str = None) -> tuple[bool, dict]:
		url = '/management-rest/threat-hunting-settings/threat-hunting-profile/collector-groups'
		url_params = list()
		url += '?' + '&'.join(url_params)
		threatHuntingAssignGroupsRequest = {
			'associatedCollectorGroupIds': associatedCollectorGroupIds,
			'name': name,
			'organization': organization
		}
		return fortiedr.send(url, threatHuntingAssignGroupsRequest)

class Users:

	'''
	class Users: This API create user in the system. (only for Admin role.
	'''
	def create_user(self, confirmPassword: str, email: str, firstName: str, lastName: str, password: str, role: str, username: str, organization :str = None, customScript: bool = None, remoteShell: bool = None, restApi: bool = None, title: str = None) -> tuple[bool, None]:
		url = '/management-rest/users/create-user'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if len(url_params) > 0:
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
		return fortiedr.send(url, userRequest)


	'''
	class Users: Delete SAML authentication settings per organization.
	'''
	def delete_saml_settings(self, organizationNameRequest : str) -> tuple[bool, None]:
		url = '/management-rest/users/delete-saml-settings'
		url_params = list()
		if organizationNameRequest:
			url_params.append('organizationNameRequest=' + organizationNameRequest)
		url += '?' + '&'.join(url_params)
		return fortiedr.delete(url)


	'''
	class Users: This API delete user from the system. Use the input parameters to filter organization.
	'''
	def delete_user(self, username : str, organization :str = None) -> tuple[bool, None]:
		url = '/management-rest/users/delete-user'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if username:
			url_params.append('username=' + username)
		url += '?' + '&'.join(url_params)
		return fortiedr.delete(url)


	'''
	class Users: This API call retrieve the FortiEdr metadata by organization.
	'''
	def get_sp_metadata(self, organization : str) -> tuple[bool, str]:
		url = '/management-rest/users/get-sp-metadata'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)


	'''
	class Users: This API call outputs a list of the users in the system. Use the input parameters to filter the list.
	'''
	def list_users(self, organization :str = None) -> tuple[bool, dict]:
		url = '/management-rest/users/list-users'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		url += '?' + '&'.join(url_params)
		return fortiedr.get(url)


	'''
	class Users: This API reset user password. Use the input parameters to filter organization.
	'''
	def reset_password(self, username : str, confirmPassword: str, password: str, organization :str = None) -> tuple[bool, None]:
		url = '/management-rest/users/reset-password'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if username:
			url_params.append('username=' + username)
		url += '?' + '&'.join(url_params)
		userRequest = {
			'confirmPassword': confirmPassword,
			'password': password
		}
		return fortiedr.insert(url, userRequest)


	'''
	class Users: Create / Update SAML authentication settings per organization.
	'''
	def update_saml_settings(self, groupAttribute : str, enabled : bool, ssoUrl : str, organization :str = None, metadataUrl :str = None, idpMetadataFile :object = None, apiGroupName :str = None, hostGroupName :str = None, localAdminGroupName :str = None, usersGroupName :str = None, description :str = None) -> tuple[bool, None]:
		url = '/management-rest/users/update-saml-settings'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if metadataUrl:
			url_params.append('metadataUrl=' + metadataUrl)
		if idpMetadataFile:
			url_params.append('idpMetadataFile=' + idpMetadataFile)
		if groupAttribute:
			url_params.append('groupAttribute=' + groupAttribute)
		if apiGroupName:
			url_params.append('apiGroupName=' + apiGroupName)
		if hostGroupName:
			url_params.append('hostGroupName=' + hostGroupName)
		if localAdminGroupName:
			url_params.append('localAdminGroupName=' + localAdminGroupName)
		if usersGroupName:
			url_params.append('usersGroupName=' + usersGroupName)
		if enabled:
			url_params.append('enabled=' + enabled)
		if description:
			url_params.append('description=' + description)
		if ssoUrl:
			url_params.append('ssoUrl=' + ssoUrl)
		url += '?' + '&'.join(url_params)
		return fortiedr.send(url)


	'''
	class Users: This API update user in the system. Use the input parameters to filter organization.
	'''
	def update_user(self, username : str, email: str, firstName: str, lastName: str, role: str, organization :str = None, customScript: bool = None, remoteShell: bool = None, restApi: bool = None, title: str = None) -> tuple[bool, None]:
		url = '/management-rest/users/update-user'
		url_params = list()
		if organization:
			url_params.append('organization=' + organization)
		if username:
			url_params.append('username=' + username)
		url += '?' + '&'.join(url_params)
		userRequest = {
			'customScript': customScript,
			'email': email,
			'firstName': firstName,
			'lastName': lastName,
			'remoteShell': remoteShell,
			'restApi': restApi,
			'role': role,
			'title': title,
			'username': username
		}
		return fortiedr.insert(url, userRequest)


def auth( host: str, user: str, passw: str, org: str = None):
	global fortiedr
	login = fedrAuth()
	headers, host = login.get_headers(
		fedr_host=host,
		fedr_user=user,
		fedr_pass=passw,
		fedr_org=org
	)

	if headers is None:
		return False, host
	else:
		fortiedr = FortiEDR_API_GW(headers, host)
		return True
	