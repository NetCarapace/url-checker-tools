# MISP Integration for URLChecker

This document describes how to set up and use MISP (Malware Information Sharing Platform) integration with URLChecker.

## Prerequisites

1. **Running MISP Instance**
   - Local MISP Docker instance (see [Local Development Testing](#local-development-testing))
   - Or remote MISP server (configure its URL, see below)

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
# Create a MISP event when at least one provider detects a threat
uv run url-checker https://suspicious-site.com --misp-report --robot --sid test_001
```

Note: argparse accepts unambiguous prefixes, so `--misp` is the same as `--misp-report` and also creates events.

### Robot Mode with MISP (Recommended for Automation)
```bash
# Automated scanning with MISP reporting
uv run url-checker https://target.com --robot --misp-report --sid automation_001
```

### Configuration Options

Environment variables (they take precedence over the keyring):
```bash
export URLCHECKERTOOLS_MISP_URL="https://your-misp-server"
export URLCHECKERTOOLS_MISP_APIKEY="your-auth-key"
# TLS certificate verification is on by default. Set to "false" to disable it,
# or to the path of a CA bundle to trust a self-signed certificate.
export URLCHECKERTOOLS_MISP_VERIFYSSL="true"
```

The older names `MISP_URL` and `MISP_API_KEY` are still read as a fallback. In the keyring, the URL can be stored under the account `misp_url` and the key under `misp`.

## What Gets Reported

A MISP event is created when at least one provider result is a threat. There is no severity threshold.

### Event Content
MISP objects added to the event, when the data is available:
- **url**: the scanned target (URL, domain, path, query)
- **domain-ip**: resolved IP addresses
- **whois**: registrar, creation date, name servers
- **annotations**: link analysis, YARA results, consolidated provider verdicts, overall assessment

### Event Structure
- **Info**: "Threat Analysis: [URL] [CRITICAL] - SID: [session id]"
- **Threat Level**: High
- **Analysis**: Ongoing
- **Tags**: `tlp:white`, `urlchecker:score=…`, `urlchecker:threats=…`, `urlchecker:providers=…`, confidence and coverage tags
- **Distribution**: Your organisation only
- **Published**: No

## Output Examples

### Successful Reporting
```
SID: automation_001
RESULT: CRITICAL (88/100)
MISP event created: 8
```

With `--verbose`: `[INFO] MISP event created: Event ID 8 (UUID: …)`.

### Skipped Reporting (No Threat)
With `--verbose`: `[INFO] No threats detected - skipping MISP report`.

### Error Handling
```
MISP reporting error: <error message>
```

## Integration Architecture

The MISP integration is designed to be **easily removable**:

- **Standalone module**: `src/url_checker_tools/integrations/misp_reporter.py`
- **Minimal coupling**: Only hooks into the CLI after scanning
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
- Verify MISP is running: `curl https://your-misp-server/users/login`
- Check firewall/network connectivity
- `CERTIFICATE_VERIFY_FAILED`: the server uses a certificate your system does not trust. Point `URLCHECKERTOOLS_MISP_VERIFYSSL` to its CA bundle.

## Security Notes

- API keys are stored in the system keyring or passed through environment variables
- TLS certificate verification is enabled by default
- Events are marked as organization-only by default

---

## Local Development Testing

This section describes how to run a local MISP instance for development and integration testing using the official [MISP Docker image](https://github.com/MISP/misp-docker). See its README for details.

### Start the MISP container

Clone misp-docker outside this repository and prepare its `.env`:

```bash
git clone https://github.com/MISP/misp-docker.git ~/misp-docker
cd ~/misp-docker
cp template.env .env
```

In `.env`, set the base URL and bind the ports to localhost only (the default publishes them on all interfaces, with the default admin password):

```bash
BASE_URL=https://localhost:8443
NGINX_HTTP_PORT=127.0.0.1:8080
NGINX_HTTPS_PORT=127.0.0.1:8443
```

Generate a self-signed certificate (without it, HTTPS is disabled) and let the nginx container user (UID 101) read the key:

```bash
mkdir -p ./ssl/ && openssl req -x509 -subj '/CN=localhost' -nodes -newkey rsa:4096 -keyout ssl/key.pem -out ssl/cert.pem -days 365 -addext "subjectAltName = DNS:localhost, IP:127.0.0.1, IP:::1"
setfacl -m u:101:r ssl/key.pem
```

Start it:

```bash
docker compose pull
docker compose up -d
```

The first boot takes a few minutes. If `up -d` reports `misp-core` as unhealthy, wait until `docker compose ps` shows it healthy, then run `docker compose up -d` again to start nginx.

The instance then exposes:
- `https://localhost:8443` — HTTPS (self-signed certificate)
- `http://localhost:8080` — HTTP (redirects to HTTPS)

Data is kept in Docker volumes (`misp-docker_mysql_data`, …), so a new clone with the same folder name reuses an earlier instance's users, keys and events.

### First-time setup

Log in at `https://localhost:8443` with the default credentials:

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
URLCHECKERTOOLS_MISP_URL=https://localhost:8443
URLCHECKERTOOLS_MISP_APIKEY=<your_auth_key>
URLCHECKERTOOLS_MISP_VERIFYSSL=<path to ~/misp-docker/ssl/cert.pem>
```

### Run the test scan

`run_eicar.sh` sources `.envdev` and runs a scan against the EICAR test URL with MISP reporting enabled:

```bash
bash run_eicar.sh
```

This will create a MISP event at `https://localhost:8443/events/index`. The YARA provider will fire on the EICAR payload even without any external API keys configured, so it provides a reliable threat signal for end-to-end testing of the reporting path.

Protective DNS resolvers (Pi-hole, Quad9, many organisation networks) block `malware.wicar.org`. Then link analysis and YARA cannot download the payload and only report errors.

### SSL note

The local MISP uses a self-signed certificate, and TLS verification is on by default. Set `URLCHECKERTOOLS_MISP_VERIFYSSL` to the path of `ssl/cert.pem` to trust it (recommended), or to `false` to disable verification. Do not use `REQUESTS_CA_BUNDLE` for this: it replaces the trusted CAs for every HTTPS request, which breaks the other providers.
