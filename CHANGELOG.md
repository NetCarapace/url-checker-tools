# Changes
All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-05-05
Initial public release of URLChecker-Tools.

### Added
- Added support for discovering provider keys from shell environment variables.
- Added initial support for the first deployment flow using VirusTotal.
- Added CLI provider selection support.

### Changed
- Improved provider availability checks to use the configured runtime environment.
- Refined key handling for external providers.

### Removed
- Not relevant

### Fixed
- Fixed provider key discovery for the tool subprocess environment.
- Fixed provider selection and availability handling when launching checks from the platform.

### Known issues
- Automated tests are still incomplete and require refactoring.
- The provider key handling remains fragile when multiple providers are selected from the CLI.
- Further refactoring is needed to improve maintainability and future evolution.

## [0.2.0] - 2026-02-26
This is the pre-release. No changes notes.
### New Features
-

### Bug and various fixes
-

### Known issues
-
## [X.Y.Z] - YYYY-MM-DD

### New Features
-

### Bug and various fixes
-

### Known issues
-
