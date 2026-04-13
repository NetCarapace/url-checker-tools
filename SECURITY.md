# Security and vulnerability disclosure policy

Security is an important concern for URLChecker-tools so we welcome responsible reports of vulnerabilities.

## Scope

This policy applies to:

- The URLChecker-tools source code and default configuration shipped in the public repositories.
- Supporting documentation and example configuration files.

It does **not** cover specific deployments operated by third parties; in these case, please refer to the considered
stakeholders.

## Reporting a vulnerability

If you believe you have found a security vulnerability in URLChecker-tools, please contact:

- **Primary contact:** cedric.renzi+github_perso@restena.lu
- **Suggested subject line:** `Security issue in URLChecker-tools`

Whenever possible, please encrypt your message using the following GnuPG key:

- **Fingerprint:** `4741 F2E1 56DC E719 89A7 4BAD 44AC 149A B8F6 2937`

You can obtain the corresponding public key from standard key servers.

- **Other contact:** https://restena.lu/fr/csirt

### What to include

To help us understand and reproduce the issue, please include, where available:

- A short description of the issue and its potential impact.
- The affected component, file or feature.
- Steps to reproduce (a minimal proof-of-concept, if possible).
- Relevant logs, configuration details or environment notes (redacted if needed).
- Whether the issue has already been disclosed elsewhere.

Please **do not** share detailed vulnerability information in public GitHub issues, pull requests, forums or
mailing lists before we have had a chance to assess the report.

## Our approach

URLChecker-tools is developed and maintained on a best-effort basis:

- We will review reasonable security reports as soon as we can.
- Where an issue is confirmed, we will work towards an appropriate fix or mitigation.
- We may contact you for clarification and, if you agree, to credit you in release notes.

We do **not** guarantee that vulnerabilities will be fixed within a specific timeframe, but security issues
are treated with higher priority than ordinary feature requests.

## Responsible disclosure

When handling security reports, we kindly ask that you:

- Give us a reasonable opportunity to investigate and address the vulnerability before public disclosure.
- Avoid accessing, altering or deleting data that does not belong to you.
- Avoid actions that could degrade the availability or integrity of services for others (for example,
  no denial-of-service testing against live systems). But we may be interested to cocreate and organize specific
  experiences--together--on these topics if you think some potential issues may require collaborative testing.

In return, we will treat your report seriously and in good faith, and we will not pursue legal action against
good-faith security research that respects these boundaries and complies with applicable law.
