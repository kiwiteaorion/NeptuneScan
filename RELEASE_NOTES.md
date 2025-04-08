# Neptune Scanner Release Notes

## Version 4.0.0 (2023)

### New Features

- Added support for port list scanning (e.g., -p 80,443,8080)
- Implemented single port scanning functionality
- Added debugging output for scan targets and port ranges
- Improved service version detection

### Major Improvements

- Enhanced code structure and organization
- Switched to clangd for better development experience
- Added comprehensive build system with PowerShell script
- Implemented proper cleanup for memory management

### Bug Fixes

- Fixed multiple function definition conflicts
- Resolved service detection issues
- Addressed memory leaks in port scanning
- Fixed format string warnings

### Development Environment

- Added clangd support with complete configuration
- Created compile_commands.json for better code intelligence
- Added .clang-tidy for code style enforcement
- Improved build process with dedicated build.ps1 script
