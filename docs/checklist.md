# Documentation Checklist

Use this list to verify nothing was missed when publishing the documentation or packaging for PyPI/GitHub Pages.

- [ ] Installation instructions in `docs/index.md` and `README.md` reflect the current Python and dependency versions.
- [ ] Authentication flow is explained (`FortiEDR` constructor args, `Auth` probe behavior, TLS verification toggle, `enable_debug`).
- [ ] Response structure (`{"status": bool, "data": ...}`) and error handling notes are documented.
- [ ] File transfer behavior is covered (`download` saves to disk with timestamped names; `upload` expects a `requests`-style `file` mapping).
- [ ] Primary wrappers are documented in `docs/api_reference.md`: Administrator, ApplicationControl, Audit, AvScannerFileController, CommunicationControl, Events, Exclusions, Features, ForensicAnalysis, Forensics, HashSearch, Incidents, IntegrationsSupport, Integrations, Inventory, IoT, IPSets, Mobile, Organizations, PlaybooksPolicies, Policies, ThreatHunting, Users.
- [ ] Additional/experimental wrappers are documented with usage guidance (Admin, CollectorInventory, Dashboard, MobileInventory, Notifications, Reputation, SecureBrowser, SecureBrowserService, SendableEntities, Support, SystemComponents, SystemEvents, ThreatHuntingExclusions, ThreatHuntingSettings, WorkloadGroups, WorkloadsDeployment).
- [ ] Quickstart example in `docs/index.md` and `example.py` use consistent constructor arguments and attribute names.
- [ ] README links to the docs folder for GitHub Pages/PyPI long description.
- [ ] Any new endpoints or wrappers added after this version have been appended to `docs/api_reference.md` and validated against the checklist.
