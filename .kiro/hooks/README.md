# Kiro Hooks

This directory contains agent hooks that automatically trigger when specific events occur in the IDE.

## Available Hooks

### Development Hooks
- **test-runner.hook** - Automatically runs tests when code files are saved
- **oauth-validator.hook** - Validates OAuth configuration changes
- **deployment-checker.hook** - Checks deployment readiness before commits

### Quality Assurance Hooks  
- **code-formatter.hook** - Formats code according to project standards
- **security-scanner.hook** - Scans for security vulnerabilities
- **documentation-updater.hook** - Updates documentation when API changes

## Hook Configuration

Hooks are configured using JSON files that specify:
- Trigger events (file save, git commit, etc.)
- Target file patterns
- Agent execution parameters
- Success/failure actions

## Usage

Hooks can be:
- Automatically triggered by IDE events
- Manually executed via the Agent Hooks panel
- Configured through the Kiro Hook UI (Command Palette > "Open Kiro Hook UI")