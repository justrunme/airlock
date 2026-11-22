# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- PyPI distribution as `justrunme-airlock`
- GitHub Actions workflow for Trusted Publishing to PyPI
- Comprehensive package metadata with keywords and classifiers

## [0.1.0] - 2024-11-22

### Added
- Initial release
- Policy engine with fail-closed authorization
- Docker + gVisor sandbox runner
- Post-execution verifier with cleanup checks
- Ed25519 receipt signing with hash chain
- FastAPI web interface with live demo
- CLI tools: `airlock`, `airlock-web`
- Support for Python and shell script execution
- Comprehensive test corpus with security cases
