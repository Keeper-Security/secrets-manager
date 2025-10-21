# Changelog

## [17.0.5] - 2025-10-21

### Fixed
- ECC key generation now correctly returns 32-byte raw private keys (was returning 121-byte DER format)
- Client version now dynamically uses VERSION constant instead of hardcoded value
- Fixed Tests

### Changed
- Client version reporting improved to match other KSM SDKs pattern

## [17.0.4] - 2025-10-20

### Changed
- Maintenance release with internal improvements

## [17.0.3] - 2025-06-25

### Changed
- Cleaned up directory structure
- Removed development and debug files from distribution

## [17.0.2] - 2025-06-25

### Security
- Updated all examples to use environment variables or placeholders

## [17.0.1] - 2025-06-25

### Fixed
- Added missing files to gem package (folder_manager, notation_enhancements, totp)

## [17.0.0] - 2025-06-25

### Added
- Initial release of Keeper Secrets Manager Ruby SDK
- Ruby 2.6+ compatibility

### Security
- Zero-knowledge encryption using AES-GCM
- Secure key management
- SSL certificate verification

### Notes
- Version 17.0.0 to align with other Keeper SDKs
- No runtime dependencies (base32 is optional)