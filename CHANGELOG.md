# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.1-dev (Unreleased)

### Added
 - setOptions() method to overwrite or set the options later.

## 1.0.0 (2020-02-19)

### Changed since split from asm89/stack-cors

- Renamed Asm89\Stack namespace to Fruitcake\Cors
- Removed HttpKernel middleware

### New Features
- Allow underscore options (both `allowed_origins` and `allowedOrigins` are allowed)
- Support wildcard patterns on AllowedOrigins (eg `https://*.example.com` will be converted to an allowedOriginPattern)
- Validate input (so invalid options are caught immediately)
- Bump PHPStan to Level 9
- Ensure 100% Code Coverage
