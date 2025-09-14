# Development Utilities

This directory contains helper scripts and utilities for development, setup, and maintenance.

## Setup and Configuration
- `setup_oauth.py` - Interactive OAuth application setup helper
- `test_setup.py` - Test environment setup and validation

## Development Servers
- `run_production.py` - Production server configuration and startup
- `deploy.py` - Deployment utility script

## Debugging and Verification
- `verify_tokens.py` - Token verification and debugging utility
- `demo_standardized_api.py` - API demonstration and testing script

## Maintenance
- `cleanup_for_production.py` - Clean up development files for production deployment
- `improve_accessibility.py` - Accessibility improvement utilities

## Usage Examples

### Setup OAuth Applications
```bash
python dev/utils/setup_oauth.py
```

### Verify Token Storage
```bash
python dev/utils/verify_tokens.py <session_id>
```

### Start Production Server
```bash
python dev/utils/run_production.py
```

### Clean for Production
```bash
python dev/utils/cleanup_for_production.py
```

## Requirements

These utilities may require:
- OAuth credentials configured
- Flask application dependencies
- Network access for OAuth provider communication