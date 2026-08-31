# Security Policy

## Supported version

Security fixes are applied to the current `main` branch and the latest published Process Tree Lab release.

## Reporting a vulnerability

Do not disclose suspected vulnerabilities, credentials, tokens, private event data, or exploit details in a public GitHub issue.

Use GitHub private vulnerability reporting:

https://github.com/G0TH3R/spl-process-tree-lab/security/advisories/new

Include:

- affected app version and Splunk version;
- the relevant dashboard, SPL, JavaScript, packaging, or deployment path;
- clear reproduction steps using sanitized or synthetic data;
- expected versus observed behavior; and
- impact and any known workaround.

Do not include live Splunk credentials, session keys, HEC/MCP tokens, cookies, private event payloads, or proprietary datasets.

## Scope

Security-sensitive areas include:

- Simple XML token escaping and scope enforcement;
- optional filter-SPL validation;
- custom field-mapping validation;
- custom-command and visualization output bounds;
- package traversal, symlink, inventory, permission, and reproducibility checks;
- credential and raw-event scanning; and
- authenticated Splunk Web rendering behavior.

## Response

Reports will be triaged privately. Valid findings will be reproduced with synthetic data, fixed on a private branch when appropriate, and disclosed after a corrected release is available.
