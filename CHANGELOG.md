# Changelog

All notable changes to this project will be documented in this file.

## 3.8 - 2024-07-05

### Added
- The following functions have been added from the new FortiEDR Central Manager 6.2.0.0451 version:
  -  Administrator.set_enable_default_application_control_state()

### Changed
- We have changed how to handle lists. If the API requires a list, but a single item was specified, such as a string or an integer, it will handle this and parse correctly to the API.

### Fixed
- Fixing how to handle boleans. Thanks to Mr. Algaba for the feedback and suggestion.
- Fixing lots of errors when handling parameters expecting lists but containing other variable types. 
- Removing unecessary URLs and functions from API.

## 3.6.8 - 2024-05-28

### Fixed
- Fixing some errors when handling lists of integers

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
