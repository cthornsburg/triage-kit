# Security Policy

## Reporting a security concern

If you discover sensitive information in this repository, please **do not** open a public issue.

Sensitive information includes:

- Credentials, tokens, API keys, or private keys
- Private IPs or internal architecture details
- Unredacted incident data or endpoint artifacts
- Personal data from real users, systems, or cases
- Collection behavior that could unexpectedly expose secrets

Instead, contact the maintainer via GitHub private reporting if available, or through the repository owner's GitHub profile.

Include:

- A link to the file/location
- What you found
- Why it is sensitive
- Suggested remediation if you have one

## Tooling safety expectations

SEKER is intended for rapid triage. Changes that expand collection scope should be reviewed carefully, especially anything involving credentials, browser data, memory capture, elevated access, or broad file enumeration.
