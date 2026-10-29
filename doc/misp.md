# MISP Integration for URLChecker

This document describes how to set up and use MISP (Malware Information Sharing Platform) integration with URLChecker.

## Prerequisites

1. **Running MISP Instance**
   - Local MISP Docker instance on `localhost` (default)
   - Or remote MISP server (configure URL in config)

2. **API Key Setup**
   ```bash
   # Store your MISP API key in the system keyring
   python -c "import keyring; keyring.set_password('urlchecker', 'misp', 'YOUR_API_KEY_HERE')"

   # Or use the keys.py tool:
   python tools/manage_keys.py add --account misp
   # Then enter your API key when prompted
   ```

## Usage

### Basic MISP Reporting
```bash
# Enable MISP reporting for suspicious or higher threats
python src/url_checker_tools.py https://suspicious-site.com --misp --robot --sid test_001
```

### Robot Mode with MISP (Recommended for Automation)
```bash
# Automated scanning with MISP reporting
python src/url_checker_tools.py https://target.com --robot --misp --sid automation_001
```

### Configuration Options

Set environment variables to customize MISP behavior:
```bash
export URLCHECKER_MISP_URL="http://your-misp-server"
export URLCHECKER_MISP_VERIFY_SSL="true"
export URLCHECKER_MISP_MINIMUM_SEVERITY="MALICIOUS"  # Only report MALICIOUS+ threats
```

## What Gets Reported

MISP events are created automatically when URLChecker detects threats at or above the configured severity level (default: SUSPICIOUS).

### Event Content
- **Target URL and domain**
- **VirusTotal detections** (malicious/suspicious engine counts)
- **YARA rule matches** (rule names, categories, severity)
- **Google Safe Browsing threats** (threat types and platforms)
- **URLScan.io indicators** (malicious/threat indicators)
- **Redirect analysis** (suspicious redirect chains)
- **Threat assessment** (score, verdict, confidence, reasoning)

### Event Structure
- **Info**: "URLChecker Threat Detection: [URL]"
- **Analysis Level**: Completed
- **Threat Level**: Mapped from url_checker_tools verdict
- **Tags**: Automated classification and session tracking
- **Distribution**: Organization only (can be configured)

## Output Examples

### Successful Reporting
```
SID: automation_001
RESULT: MALICIOUS (75/100)
MISP: Event 1234 created
```

### Skipped Reporting (Below Threshold)
```
SID: automation_002
RESULT: SUSPICIOUS (35/100)
MISP: Skipped - Verdict SUSPICIOUS below minimum severity MALICIOUS
```

### Error Handling
```
SID: automation_003
RESULT: MALICIOUS (80/100)
MISP: Failed - Connection timeout
```

## Integration Architecture

The MISP integration is designed to be **easily removable**:

- **Standalone module**: `src/urlchecker/integrations/misp_reporter.py`
- **Minimal coupling**: Only hooks into robot mode execution
- **No dependencies**: Main URLChecker works without MISP
- **Optional dependency**: PyMISP is already in requirements

## Troubleshooting

### API Key Issues
```bash
# Verify API key is stored
python -c "import keyring; print('Key exists:', bool(keyring.get_password('urlchecker', 'misp')))"

# Update API key
python -c "import keyring; keyring.set_password('urlchecker', 'misp', 'NEW_API_KEY')"
```

### Connection Issues
- Verify MISP is running: `curl http://localhost/servers/getVersion`
- Check firewall/network connectivity
- Validate SSL settings if using HTTPS

### Threshold Configuration
- Default: Reports SUSPICIOUS and higher
- Adjust via `URLCHECKER_MISP_MINIMUM_SEVERITY` environment variable
- Options: `SUSPICIOUS`, `MALICIOUS`, `CRITICAL`

## Security Notes

- API keys are stored securely in system keyring
- SSL verification can be enabled for production
- Events are marked as organization-only by default
- No sensitive scan data is logged in clear text

---

## Local Development Testing

This section describes how to run a local MISP instance for development and integration testing using the official [MISP Docker image](https://github.com/MISP/misp-docker).

### Start the MISP container

```bash
docker compose -f docker/docker-compose.misp.yml up -d
```

The instance exposes two ports:
- `https://localhost:8443` — HTTPS (self-signed certificate)
- `http://localhost:8080` — HTTP

### First-time setup

On first boot MISP runs its initialisation. Wait until the container is healthy, then log in at `https://localhost:8443` with the default credentials:

| Field    | Value             |
|----------|-------------------|
| Email    | `admin@admin.test` |
| Password | `admin`           |

You will be prompted to change the password on first login.

Retrieve your automation API key at:  
**Administration → My Profile → Auth keys**  
(or directly at `https://localhost:8443/auth_keys/index`)

### Configure the dev environment

Copy the template and fill in the key:

```bash
cp .envdev.template .envdev
```

`.envdev` should contain:

```bash
MISP_URL=https://localhost:8443
MISP_API_KEY=<your_auth_key>
```

### Run the test scan

`run_eicar.sh` sources `.envdev` and runs a scan against the EICAR test URL with MISP reporting enabled:

```bash
bash run_eicar.sh
```

This will create a MISP event at `https://localhost:8443/events/index`. The YARA provider will fire on the EICAR payload even without any external API keys configured, so it provides a reliable threat signal for end-to-end testing of the reporting path.

### SSL note

The vanilla docker-MISP uses a self-signed certificate. `verify_ssl` is set to `False` by default in `get_misp_config()`, so no extra configuration is needed for local testing.
