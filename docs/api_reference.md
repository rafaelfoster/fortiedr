# API Reference

This reference documents every public class and function shipped in the repository, including helper classes under `fortiedr/api`. Names match the FortiEDR REST endpoints they wrap.

## Core client

### `FortiEDR`

`FortiEDR(host, user, password, organization=None, enable_debug=False, enable_ssl=True)`

- Builds Basic Auth headers and probes the management host via `Auth.test_authentication`. The result is exposed on `auth` as `{"status": bool, "data": ...}`.
- Exposes per-area wrappers as attributes after authentication succeeds.
- `enable_debug()`: Turns on verbose `requests` logging and prints URL, headers, and payload for each call.
- `get(url, params=None, request_type=None)`: Issues a GET.
- `send(url, params=None, request_type=None)`: Issues a POST.
- `insert(url, params=None, request_type=None)`: Issues a PUT.
- `update(url, params=None, request_type=None)`: Issues a PATCH.
- `delete(url, params=None, request_type=None)`: Issues a DELETE.
- `download(url, params=None, request_type=None, file_format="zip", download_folder="")`: Streams a GET response to disk and returns its file path in `data`.
- `upload(url, file, params=None, request_type=None)`: Sends multipart form data (pass a `requests`-style `file` mapping).
- All helpers return `{"status": bool, "data": response|error}`. When `status=False`, `data` contains `status_code` and `error_message`.

> The client keeps TLS verification enabled by default. Set `enable_ssl=False` only if you need to skip verification.

### `Auth`

- `convert_to_base64(string)`: Encodes a credential string to Base64.
- `test_authentication(headers, host)`: Tries two probe URLs (`admin/list-system-summary`, `events/list-events`) to verify credentials; returns `(status, data, response_headers)`.
- `get_headers(fedr_host, fedr_user, fedr_pass, fedr_org=None)`: Creates the Basic Auth header, calls `test_authentication`, and returns `(headers, host)` on success or `(None, error_text)` on failure.

## Primary wrappers (attached to `FortiEDR`)

Each wrapper is instantiated for you on the client (for example `fedr.inventory`). All methods accept an optional `organization` argument where applicable.

### Administrator (`FortiEDR.administrator`)

- `list_system_summary(organization: str | None = None) -> dict`: Returns management hostname, version, external/internal IPs, and license expiration for the given or default organization.
- `upload_license(licenseBlob: bytes) -> dict`: Uploads a FortiEDR license file; supply raw bytes or a file-like object mapped to `licenseBlob`.
- `list_users(organization: str | None = None) -> dict`: Lists FortiEDR management users in scope.
- `get_user(username: str, organization: str | None = None) -> dict`: Retrieves a single user record by username.
- `delete_user(username: str, organization: str | None = None) -> dict`: Deletes the specified management user.
- `create_user(firstName: str, lastName: str, password: str, confirmPassword: str, email: str, username: str, title: str, role: str, restApi: bool, customScript: bool, remoteShell: bool, organization: str | None = None) -> dict`: Creates a user and sets capability flags (REST API, custom scripts, remote shell).
- `update_user(username: str, firstName: str | None = None, lastName: str | None = None, password: str | None = None, confirmPassword: str | None = None, email: str | None = None, title: str | None = None, role: str | None = None, restApi: bool | None = None, customScript: bool | None = None, remoteShell: bool | None = None, organization: str | None = None) -> dict`: Updates identity details, password, role, and capability flags for an existing user.

### ApplicationControl (`FortiEDR.application_control`)

- `add_app_to_app_group(application: str, applicationGroup: str, organization: str | None = None) -> dict`: Places an application into a named application group.
- `add_app_group(applicationGroup: str, organization: str | None = None) -> dict`: Creates a new application group for policy targeting.
- `delete_app_from_app_group(application: str, applicationGroup: str, organization: str | None = None) -> dict`: Removes an application from the specified group.
- `delete_app_group(applicationGroup: str, organization: str | None = None) -> dict`: Deletes an application group and its membership.
- `list_app_groups(organization: str | None = None) -> dict`: Lists all application groups.
- `list_apps_in_app_group(applicationGroup: str, organization: str | None = None) -> dict`: Lists applications belonging to a given group.
- `list_collectors_for_app(application: str, organization: str | None = None) -> dict`: Shows collectors where a particular app is installed.
- `list_installed_apps(collectorId: str, organization: str | None = None) -> dict`: Returns installed applications on a specific collector.

### Audit (`FortiEDR.audit`)

- `get_system_audit(startDate: str, endDate: str, organization: str | None = None) -> dict`: Pulls audit log entries between two timestamps (string format accepted by FortiEDR).

### AvScannerFileController (`FortiEDR.av_scanner_file_controller`)

- `upload_file(file: bytes, organization: str | None = None) -> dict`: Uploads a file for AV scanning; pass a `{"file": open(..., "rb")}` style mapping.

### CommunicationControl (`FortiEDR.communication_control`)

- `add_exception(ruleName: str, organization: str | None = None) -> dict`: Creates a communication-control exception rule by name.
- `delete_exception(ruleName: str, organization: str | None = None) -> dict`: Deletes a communication-control exception rule.
- `list_exceptions(organization: str | None = None) -> dict`: Lists communication-control exceptions.

### Events (`FortiEDR.events`)

- `acknowledge_event(eventId: int, organization: str | None = None) -> dict`: Marks an event as acknowledged in FortiEDR.
- `add_comment_to_event(eventId: int, comment: str, organization: str | None = None) -> dict`: Adds a textual comment to an event record.
- `get_event(eventId: int, organization: str | None = None) -> dict`: Retrieves full details for a single event.
- `get_event_process_info(eventId: int, organization: str | None = None) -> dict`: Returns process details associated with the event.
- `list_event_comments(eventId: int, organization: str | None = None) -> dict`: Lists comments posted to the event.
- `list_events(organization: str | None = None) -> dict`: Lists events for the tenant with default paging.
- `unacknowledge_event(eventId: int, organization: str | None = None) -> dict`: Reverts an event to an unacknowledged state.

### Exclusions (`FortiEDR.exclusions`)

- `add_exclusion(ruleName: str, organization: str | None = None) -> dict`: Adds an exclusion rule by name.
- `delete_exclusion(ruleName: str, organization: str | None = None) -> dict`: Removes an exclusion rule.
- `list_exclusions(organization: str | None = None) -> dict`: Lists all exclusion rules.

### Features (`FortiEDR.features`)

- `get_feature_parameters(featureName: str, organization: str | None = None) -> dict`: Fetches configurable parameters for the named feature (e.g., `threat_hunting`).

### ForensicAnalysis (`FortiEDR.forensic_analysis`)

- `get_file_from_collector(collectorId: str, filePath: str, organization: str | None = None) -> dict`: Requests and downloads a specific file from a collector.
- `get_process_info_from_collector(collectorId: str, processId: int, organization: str | None = None) -> dict`: Retrieves process information directly from the collector host.
- `list_running_processes_from_collector(collectorId: str, organization: str | None = None) -> dict`: Lists currently running processes on a collector.
- `abort_request(collectorId: str, requestId: str, organization: str | None = None) -> dict`: Cancels a previously issued forensic request.
- `get_file_from_collector_ext(collectorId: str, filePath: str, organization: str | None = None) -> dict`: Extended variant of file retrieval.
- `get_process_info_from_collector_ext(collectorId: str, processId: int, organization: str | None = None) -> dict`: Extended variant of process details.
- `list_running_processes_from_collector_ext(collectorId: str, organization: str | None = None) -> dict`: Extended variant of process listing.

### Forensics (`FortiEDR.forensics`)

- `get_file(collectorId: str, filePath: str, organization: str | None = None) -> dict`: Downloads a file via the forensics API (management-mediated).
- `get_process_details(collectorId: str, processId: int, organization: str | None = None) -> dict`: Retrieves process details via forensics.
- `list_processes(collectorId: str, organization: str | None = None) -> dict`: Lists processes on a collector via forensics.

### HashSearch (`FortiEDR.hash_search`)

- `search(hash: str, organization: str | None = None) -> dict`: Searches FortiEDR telemetry for the provided file hash.

### Incidents (`FortiEDR.incidents`)

- `add_comment_to_incident(incidentId: int, comment: str, organization: str | None = None) -> dict`: Adds an analyst comment to an incident.
- `get_incident(incidentId: int, organization: str | None = None) -> dict`: Retrieves detailed information for an incident.
- `list_incidents(organization: str | None = None) -> dict`: Lists incidents visible to the tenant.
- `update_incident(incidentId: int, organization: str | None = None) -> dict`: Updates incident state or metadata (fields defined by the server).
- `list_incident_comments(incidentId: int, organization: str | None = None) -> dict`: Lists comments attached to an incident.

### IntegrationsSupport (`FortiEDR.integrations_support`)

- `get_ems_settings(organization: str | None = None) -> dict`: Retrieves the EMS connector settings.
- `get_hoster_details(hosterType: str, organization: str | None = None) -> dict`: Returns connection details for a given hoster type.
- `get_hoster_types(organization: str | None = None) -> dict`: Lists supported hoster types.

### Integrations (`FortiEDR.integrations`)

- `add_integration(organization: str | None = None) -> dict`: Creates a new integration entry.
- `delete_integration(integrationId: int, organization: str | None = None) -> dict`: Deletes an integration by ID.
- `get_integration(integrationId: int, organization: str | None = None) -> dict`: Retrieves integration details.
- `list_integrations(organization: str | None = None) -> dict`: Lists configured integrations.
- `update_integration(integrationId: int, organization: str | None = None) -> dict`: Updates integration fields.

### Inventory (`FortiEDR.inventory`)

- `get_collector_details(collectorId: str, organization: str | None = None) -> dict`: Returns hardware, OS, and status details for a collector.
- `list_collectors(organization: str | None = None) -> dict`: Lists collectors enrolled under the tenant.
- `list_groups(organization: str | None = None) -> dict`: Lists collector groups.
- `move_collectors_to_group(collectorIds: int | list[int], groupId: int, organization: str | None = None) -> dict`: Moves one or many collectors into the target group; single IDs auto-wrap to a list.
- `uninstall_collector(collectorId: str, organization: str | None = None) -> dict`: Initiates a collector uninstall workflow.
- `create_group(groupName: str, organization: str | None = None) -> dict`: Creates a new collector group.
- `delete_group(groupName: str, organization: str | None = None) -> dict`: Deletes a collector group.
- `disable_collector(collectorId: str, organization: str | None = None) -> dict`: Disables a collector.
- `enable_collector(collectorId: str, organization: str | None = None) -> dict`: Enables a collector.
- `restart_collector(collectorId: str, organization: str | None = None) -> dict`: Restarts a collector service.
- `scan_collector(collectorId: str, organization: str | None = None) -> dict`: Triggers an on-demand scan on the collector.
- `set_collector_policy(collectorId: str, policyName: str, organization: str | None = None) -> dict`: Assigns a specific policy to a collector.
- `assign_policy_to_group(groupId: int, policyName: str, organization: str | None = None) -> dict`: Assigns a policy to an entire collector group.
- `get_collectors_by_group(groupName: str, organization: str | None = None) -> dict`: Lists collectors belonging to a named group.
- `get_group_policy(groupName: str, organization: str | None = None) -> dict`: Retrieves the policy currently applied to a group.

### IoT (`FortiEDR.iot`)

- `create_iot_group(groupName: str, organization: str | None = None) -> dict`: Creates an IoT device group for segmentation.
- `delete_iot_group(groupName: str, organization: str | None = None) -> dict`: Deletes an IoT group.
- `list_iot_devices(organization: str | None = None) -> dict`: Lists IoT devices.
- `list_iot_groups(organization: str | None = None) -> dict`: Lists IoT groups.
- `move_iot_devices_to_group(deviceIds: int | list[int], groupId: int, organization: str | None = None) -> dict`: Moves devices to a group; accepts a single int or list of ints.

### IPSets (`FortiEDR.ip_sets`)

- `add_ip_set(name: str, description: str, ips: str | list[str], organization: str | None = None) -> dict`: Creates an IP set with description and members (single string or list accepted).
- `delete_ip_set(name: str, organization: str | None = None) -> dict`: Deletes a named IP set.
- `list_ip_sets(organization: str | None = None) -> dict`: Lists configured IP sets.
- `update_ip_set(name: str, new_name: str | None = None, description: str | None = None, ips: str | list[str] | None = None, organization: str | None = None) -> dict`: Renames, re-describes, or replaces members of an IP set.

### Mobile (`FortiEDR.mobile`)

- `get_incident(incidentId: int, organization: str | None = None) -> dict`: Retrieves details for a mobile incident.
- `list_incidents(organization: str | None = None) -> dict`: Lists mobile incidents.

### Organizations (`FortiEDR.organizations`)

- `add_organization(organizationName: str, organizationId: int | None = None) -> dict`: Creates an organization (ID optional if the server assigns one).
- `delete_organization(organizationId: int) -> dict`: Deletes an organization by ID.
- `get_organization(organizationId: int) -> dict`: Retrieves an organization record.
- `list_organizations() -> dict`: Lists organizations on the management server.
- `update_organization(organizationId: int, organizationName: str | None = None) -> dict`: Renames an organization.

### PlaybooksPolicies (`FortiEDR.playbooks_policies`)

- `add_playbook_policy(policyName: str, organization: str | None = None) -> dict`: Creates a playbook policy container.
- `delete_playbook_policy(policyName: str, organization: str | None = None) -> dict`: Deletes a playbook policy by name.
- `get_playbook_policy(policyName: str, organization: str | None = None) -> dict`: Retrieves a playbook policy definition.
- `list_playbook_policies(organization: str | None = None) -> dict`: Lists playbook policies.
- `update_playbook_policy(policyName: str, organization: str | None = None) -> dict`: Updates an existing playbook policy.

### Policies (`FortiEDR.policies`)

- `assign_policy_to_group(policyName: str, groupName: str, organization: str | None = None) -> dict`: Assigns a policy to a collector group.
- `clone(policyName: str, newPolicyName: str, organization: str | None = None) -> dict`: Clones an existing policy into a new named policy.
- `create_policy(policyName: str, organization: str | None = None) -> dict`: Creates a new policy.
- `delete_policy(policyName: str, organization: str | None = None) -> dict`: Deletes a policy by name.
- `get_policy(policyName: str, organization: str | None = None) -> dict`: Retrieves detailed information about a policy.
- `list_policies(organization: str | None = None) -> dict`: Lists policies.
- `update_policy(policyName: str, organization: str | None = None) -> dict`: Updates policy details (payload handled server-side).
- `unassign_policy_from_group(policyName: str, groupName: str, organization: str | None = None) -> dict`: Removes a policy assignment from a group.

### ThreatHunting (`FortiEDR.threat_hunting`)

- `add_comment_to_event(eventId: int, comment: str, organization: str | None = None) -> dict`: Adds an analyst comment to a threat-hunting event.
- `get_event(eventId: int, organization: str | None = None) -> dict`: Retrieves detailed information for an event.
- `list_events(organization: str | None = None) -> dict`: Lists threat-hunting events.
- `get_event_process_info(eventId: int, organization: str | None = None) -> dict`: Retrieves process details linked to the event.
- `list_event_comments(eventId: int, organization: str | None = None) -> dict`: Lists comments on an event.

### Users (`FortiEDR.users`)

- `create_user(firstName: str, lastName: str, password: str, confirmPassword: str, email: str, username: str, title: str, role: str, restApi: bool, customScript: bool, remoteShell: bool, organization: str | None = None) -> dict`: Creates a FortiEDR user (same fields as Administrator).
- `delete_user(username: str, organization: str | None = None) -> dict`: Deletes a user.
- `list_users(organization: str | None = None) -> dict`: Lists users.
- `update_user(username: str, organization: str | None = None) -> dict`: Updates a user; the FortiEDR API determines which payload fields are applied.
- `get_user(username: str, organization: str | None = None) -> dict`: Retrieves a user record.

## Additional/experimental wrappers (manual use)

These modules live under `fortiedr/api` but are not attached to `FortiEDR`. Some rely on HTTP verb helpers (`post`, `put`) that are not currently defined on `FortiEDR`; you can still use them by either:

```python
from fortiedr.api.system_components import SystemComponents

fedr = FortiEDR(...)
fedr.post = fedr.send       # alias POST
fedr.put = fedr.insert      # alias PUT
system_components = SystemComponents(fedr)
```

### Admin (`fortiedr.api.admin.Admin`)

- `admin_tab_indication()`: Indicates whether the admin tab should be shown.
- `set_enable_default_application_control_state(adminSetEnableDefaultApplicationControlRequest)`: Updates default application control state.
- `set_tray_notification_settings(adminSetTrayNotificationSettingsRequest)`: Updates tray notification settings.
- `av_scan(avScanDisplayItem, accountId=None)`: Configures AV scan settings.
- `av_scan_collectors_and_groups_options(accountId=None, field=None, filterCollectorStatus=None, search=None)`: Lists collectors/groups for AV scan selection.
- `get_av_scan_mobile(json=None, organizationId=None)`: Retrieves mobile AV scan settings.
- `update_av_scan_mobile(mobileSaveScan)`: Saves mobile AV scan settings.
- `av_scan_mobile_collectors_and_groups_options(organizationId=None, searchType=None, searchValue=None)`: Options for mobile AV scans.
- `trigger_scan(requestBody, accountId=None)`: Triggers an AV scan.
- `default_application_control_state(adminSetEnableDefaultApplicationControlRequest)`: Updates default application control state (alternate endpoint).

### CollectorInventory (`fortiedr.api.collector_inventory.CollectorInventory`)

- `collectors(collectors, organization=None)`: Bulk operations on collectors via `/api/collector-inventory/collectors`.

### Dashboard (`fortiedr.api.dashboard.Dashboard`)

- `events_and_incidents_by_os(organization=None)`: Dashboard breakdown by OS.
- `events_and_incidents_progress(organization=None)`: Dashboard trend data.
- `events_severities(organization=None)`: Event severity counts.
- `incidents_severities(organization=None)`: Incident severity counts.
- `top_ten_collectors_by_events(organization=None)`: Top collectors by event volume.
- `top_ten_events(organization=None)`: Top event types.

### MobileInventory (`fortiedr.api.mobile_inventory.MobileInventory`)

- `devices(devices, organization=None)`: Mobile inventory operations at `/api/mobile-inventory/devices`.

### Notifications (`fortiedr.api.notifications.Notifications`)

- `count(organization=None)`: Returns unread notification count.
- `mark_as_read(notificationIds, organization=None)`: Marks notifications as read.

### Reputation (`fortiedr.api.reputation.Reputation`)

- `get_file_reputation(fileHash, organization=None)`: Retrieves reputation info for a file hash.
- `get_ip_reputation(ip, organization=None)`: Retrieves reputation info for an IP.
- `get_url_reputation(url, organization=None)`: Retrieves reputation info for a URL.

### SecureBrowser (`fortiedr.api.secure_browser.SecureBrowser`)

- `disable(organization=None)`: Disables Secure Browser.
- `enable(organization=None)`: Enables Secure Browser.

### SecureBrowserService (`fortiedr.api.secure_browser_service.SecureBrowserService`)

- `get_settings(organization=None)`: Retrieves Secure Browser service settings.
- `update_settings(settings, organization=None)`: Updates Secure Browser service settings.

### SendableEntities (`fortiedr.api.sendable_entities.SendableEntities`)

- `create(entity, organization=None)`: Creates a sendable entity (for alert forwarding).
- `test(entity, organization=None)`: Tests a sendable entity configuration.

### Support (`fortiedr.api.support.Support`)

- `get_logs(organization=None)`: Retrieves support logs.

### SystemComponents (`fortiedr.api.system_components.SystemComponents`)

- `aggregator_logs(aggregatorId=None, organizationId=None)`: Downloads logs from an aggregator.
- `get_aggregators(...)`: Lists aggregators with filters (IDs, names, IP, status, version, paging).
- `delete_aggregators(...)`: Deletes aggregators with filters.
- `core_logs(coreId=None, organizationId=None)`: Downloads logs from a core.
- `get_cores(...)`: Lists cores with filters (deployment modes, status, paging, etc.).
- `delete_cores(...)`: Deletes cores with filters.
- `management_logs(organizationId)`: Retrieves management logs.
- `get_repositories()`: Lists deployment repositories.
- `update_core_functionality(coreFunctionality)`: Updates core functionality flags.

### SystemEvents (`fortiedr.api.system_events.SystemEvents`)

- `list(organization=None)`: Lists system events.

### ThreatHuntingExclusions (`fortiedr.api.threat_hunting_exclusions.ThreatHuntingExclusions`)

- `add_exclusion(ruleName, organization=None)`: Adds a threat-hunting exclusion.
- `delete_exclusion(ruleName, organization=None)`: Deletes a threat-hunting exclusion.
- `list_exclusions(organization=None)`: Lists threat-hunting exclusions.

### ThreatHuntingSettings (`fortiedr.api.threat_hunting_settings.ThreatHuntingSettings`)

- `get_settings(organization=None)`: Retrieves threat-hunting settings.
- `update_settings(settings, organization=None)`: Updates threat-hunting settings.

### WorkloadGroups (`fortiedr.api.workload_groups.WorkloadGroups`)

- `add_workload_group(groupName, organization=None)`: Creates a workload group.
- `delete_workload_group(groupName, organization=None)`: Deletes a workload group.
- `get_workload_group(groupName, organization=None)`: Retrieves a workload group.
- `list_workload_groups(organization=None)`: Lists workload groups.
- `update_workload_group(groupName, newGroupName, organization=None)`: Renames or updates a workload group.

### WorkloadsDeployment (`fortiedr.api.workloads_deployment.WorkloadsDeployment`)

- `connect_account(request)`: Connects a cloud account to workloads deployment.
- `delete_accounts(accountIds=None, deleteAll=None, organizationId=None, search=None)`: Deletes accounts by ID, search, or delete-all flag.
- `discover_clusters(request)`: Discovers clusters in connected accounts.
- `get_account(accountId=None, organizationId=None)`: Retrieves account details.
- `install_agents(request)`: Installs agents.
- `installer_versions(organizationId)`: Lists installer versions.
- `list_accounts(maxResult=None, organizationId=None, page=None, search=None, sorting=None)`: Lists accounts with paging and filters.
- `list_clusters(accountNames=None, cloudProviders=None, maxResult=None, organizationId=None, page=None, search=None, sorting=None, statuses=None)`: Lists clusters with filters.
- `refresh_clusters(organizationId)`: Refreshes cluster data.
- `uninstall_agents(accountNames=None, cloudProviders=None, clusterIds=None, organizationId=None, search=None)`: Uninstalls agents based on filters.
- `upgrade_agents(request)`: Upgrades deployed agents.

## Typing helpers

Several files define `IntOrListOfInt` (a small Pydantic model that accepts either an int or a list of ints). It is not currently used in the request payloads but remains as a helper for future validation.
