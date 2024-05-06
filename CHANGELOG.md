# Changelog

All notable changes to this project will be documented in this file.

## 3.6.5 - 2024-05-03

### Fixed
- Fixing some minor bugs and incompatibilities with Pypi build

## 3.1 - 2024-04-03

### Added
- Added validate_params() to each function to validate whether the parameters have been defined correctly according to their types.
- A new connector method has been created - upload() to handle functions that require file uploading, such as Administrator.upload_content(), Administrator.upload_license(), etc.
- The following functions have been added from the new FortiEDR Central Manager 6.2 version:
  - Administrator.set_tray_notification_settings()
  - ApplicationControl.get_applications()
  - ApplicationControl.send_applications()
  - ApplicationControl.insert_applications()
  - ApplicationControl.delete_applications()
  - ApplicationControl.force_update_ootb_application_controls()
  - ApplicationControl.tags()
  - Dashboard.most_targeted_items()
  - Dashboard.unhandled_items()
  - SystemInventory.check_custom_installer()
  - SystemInventory.create_ems_custom_installer()
  - Policies.scan_files()

### Changed
- **disable_ssl()** function has been renamed to **ignore_certificate()**
- Adding an upload file example to example.py

### Fixed
- Fixed functions that required uploading data.
