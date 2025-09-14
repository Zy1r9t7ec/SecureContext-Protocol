# Development Files

This directory contains all development, testing, and debugging files that are useful during development but not needed for production deployment.

## Directory Structure

```
dev/
├── tests/          # Standalone test files for specific features
├── utils/          # Development utilities and helper scripts
├── reports/        # Task completion reports and summaries
└── README.md       # This file
```

## Usage

### Running Tests
```bash
# Run comprehensive test suite
python dev/tests/comprehensive_test.py

# Run specific feature tests
python dev/tests/core_functionality_test.py
python dev/tests/security_test.py
python dev/tests/performance_scalability_test_comprehensive.py
```

### Development Utilities
```bash
# Setup OAuth applications
python dev/utils/setup_oauth.py

# Verify tokens
python dev/utils/verify_tokens.py <session_id>

# Clean up for production
python dev/utils/cleanup_for_production.py
```

### Development Servers
```bash
# Start development server
python start.py
# or
python run.py

# Start production server
python dev/utils/run_production.py
```

## Note

These files are kept in the repository for ongoing development but are excluded from production builds. The main application code is in the root directory and core subdirectories (`authentication_proxy/`, `scp_sdk/`, etc.).