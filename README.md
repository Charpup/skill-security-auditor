# Skill Security Auditor

OpenClaw skill security auditor integrating Cisco AI Skill Scanner for comprehensive skill security assessment.

## Overview

This tool provides static security analysis for OpenClaw skills, detecting potential security threats before installation.

## Features

- **Cisco AI Skill Scanner Integration**: Primary static analysis engine
- **AITech Threat Classification**: Industry-standard attack categorization
- **SARIF 2.1.0 Output**: GitHub Code Scanning compatible reports
- **CVE Database Integration**: Check against known vulnerabilities
- **Bulk Scanning**: Scan entire skill directories in parallel
- **Auto-remediation**: Optional quarantine of suspicious skills

## Installation

```bash
# Install Cisco AI Skill Scanner
pip install cisco-ai-skill-scanner[all]

# Clone this repository
git clone <repository-url>
cd skill-security-auditor

# Make CLI executable
chmod +x tools/claw-audit.py
```

## Usage

### Scan a Single Skill

```bash
# Basic scan
./tools/claw-audit.py scan /path/to/skill

# With detailed output
./tools/claw-audit.py scan /path/to/skill --detailed

# Generate SARIF report
./tools/claw-audit.py scan /path/to/skill -o report.sarif -f sarif

# Generate Markdown report
./tools/claw-audit.py scan /path/to/skill -o report.md -f markdown
```

### Scan All Skills

```bash
# Scan all skills in default directory
./tools/claw-audit.py scan-all

# Scan specific directory
./tools/claw-audit.py scan-all /path/to/skills

# With parallel workers
./tools/claw-audit.py scan-all --workers 8
```

### Check Status

```bash
./tools/claw-audit.py status
```

## AITech Threat Categories

The scanner detects the following attack types:

- **Prompt Injection**: Malicious prompt manipulation
- **Data Exfiltration**: Unauthorized data transmission
- **Credential Harvesting**: API key/password theft
- **Command Injection**: OS command execution
- **Dependency Confusion**: Package namespace attacks
- **Malicious Code Execution**: Arbitrary code execution
- **Network Egress**: Unauthorized network calls
- **Privilege Escalation**: Permission bypass
- **Obfuscation**: Code hiding techniques
- **Backdoor**: Hidden access mechanisms
- **Supply Chain Attack**: Build process compromise

## Exit Codes

- `0`: No issues or only low/info findings
- `1`: High severity findings detected
- `2`: Critical severity findings detected

## Configuration

Environment variables:

- `OPENCLAW_SKILLS_DIR`: Default skills directory
- `CISCO_SCANNER_THRESHOLD`: Minimum severity (default: medium)
- `CLAWSEC_FEED_URL`: Threat intelligence feed URL
- `AUDIT_AUTO_REMEDIATE`: Enable auto-quarantine (default: false)

## Architecture

```
skill-security-auditor/
├── lib/
│   ├── scanner_orchestrator.py    # Main controller
│   ├── cisco_scanner.py           # Cisco Scanner wrapper
│   ├── clawsec_integration.py     # Threat intelligence
│   └── report_generator.py        # Report generation
├── tools/
│   └── claw-audit.py              # CLI entry point
├── config/
│   ├── default.yaml               # Default configuration
│   └── cve_cache.json             # CVE database cache
└── tests/
    ├── unit/                      # Unit tests
    └── fixtures/                  # Test samples
```

## Testing

Run tests with pytest:

```bash
pytest tests/ -v
```

## License

MIT License - See LICENSE file
