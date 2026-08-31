# Splunk Process Tree Lab

A standalone Splunk Classic Simple XML app for bounded Windows process-tree investigation across selectable indexes, sourcetypes, sources, and event codes.

Process Tree Lab supports:

- Sysmon EventCode 1
- Windows Security EventCode 4688
- Validated custom process-field mappings
- Process Events Over Time
- Sankey process flow
- Force Directed process relationships
- Process edge tables
- Selected-PID `pstree` output
- Bounded process-tree content hunts
- A validated, collapsible optional filter-SPL editor

The repository contains no BOTS archives, indexed buckets, raw events, credentials, tokens, or deployment secrets.

## Repository layout

```text
apps/spl_process_tree_lab/       Installable Splunk app source
tools/process_tree/              Contracts and deterministic package verifier
docs/process-tree-lab/           Prerequisites and screenshot gallery
docs/screenshots/process-tree-lab/ Sanitized UI screenshots
```

## Prerequisites

Read [docs/process-tree-lab/prerequisites.md](docs/process-tree-lab/prerequisites.md) before installation. Required dependencies include:

- Splunk Enterprise 10.4.1 (tested runtime)
- `sankey_diagram_app`
- `force_directed_viz`
- `splunk_pstree_app` 2.1.0 or newer
- A searchable process-create source with the documented Sysmon, Security 4688, or custom field contract

## Screenshots

See [docs/process-tree-lab/screenshots.md](docs/process-tree-lab/screenshots.md).

## Validate and package

Run from the repository root:

```bash
python3 -m unittest tools.process_tree.test_app_contracts tools.process_tree.test_verify_and_package -q
node tools/process_tree/test_process_tree_editor.js
node --check apps/spl_process_tree_lab/appserver/static/js/process_tree_104.js
python3 -O tools/process_tree/verify_and_package.py
```

The deterministic package and local verification report are written to ignored paths under `apps/_packages/` and `apps/_reports/`.

## Install

Package and validate the app first, then install the generated archive through your approved Splunk app lifecycle. Back up the currently installed app and verify the package checksum before replacement. Restart Splunk only through the environment's supported service-management path.

After installation, verify the authenticated dashboard route:

```text
/en-US/app/spl_process_tree_lab/process_tree
```

## Safety

- Searches require explicit data-source, host, and time selections.
- Relationship and tree outputs have fixed bounds.
- Filter SPL permits only non-writing `search` and `where` pipelines.
- Custom field names are validated before mapping tokens are submitted.
- The app contains no scheduled searches, inputs, or index-writing commands.

## Version

Current app version: **1.0.4**
