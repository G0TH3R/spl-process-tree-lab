# Process Tree Lab — Splunk Prerequisites

Process Tree Lab is a read-only Splunk Classic Simple XML app. It does not package process events, indexes, inputs, field extractions, custom visualizations, or the `pstree` command.

## Supported Splunk environment

- **Tested:** Splunk Enterprise 10.4.1, build `5a009d941268`.
- Splunk Web must support Classic Simple XML 1.1 and app-local JavaScript/CSS.
- JavaScript must be allowed for the signed-in Splunk user; no external browser assets are loaded.
- Install the app on the search tier that will execute its searches and serve the dashboard.

Compatibility with other Splunk versions is not asserted until separately tested.

## Required Splunk apps

Install and enable these dependencies before Process Tree Lab:

| App ID | Required capability | Verified version/context |
|---|---|---|
| `sankey_diagram_app` | Custom visualization `sankey_diagram_app.sankey_diagram` | Must accept `source`, `target`, `value` |
| `force_directed_viz` | Custom visualization `force_directed_viz.force_directed` | Must accept `src_ip`, `dest_ip`, `count` |
| `splunk_pstree_app` | Chunked custom search command `pstree` | Version 2.1.0 or newer; Python 3 |

The `pstree` command registration must provide:

```conf
[pstree]
filename = pstree.py
chunked = true
python.version = python3
```

## User permissions

Dashboard users need permission to:

- read the `spl_process_tree_lab` app and its default view;
- search every selected index;
- read the selected `host`, `source`, `sourcetype`, and `EventCode` values;
- use the installed `pstree` custom command; and
- load the Sankey and Force Directed custom visualizations.

Installing or replacing the app and restarting Splunk requires the normal administrator/service-manager privileges for the deployment.

## Required event fields

Every usable source must provide:

- `_time`
- `host`
- `source`
- `sourcetype`
- `EventCode`
- parent process name or path
- child process name or path
- parent process ID
- child process ID

Command line and user fields are optional for basic relationships but recommended for useful tree details and hunts.

### Sysmon EventCode 1 preset

| Meaning | Expected field |
|---|---|
| Parent process | `ParentImage` |
| Child process | `Image` |
| Parent PID | `ParentProcessId` |
| Child PID | `ProcessId` |
| Parent GUID | `ParentProcessGuid` |
| Child GUID | `ProcessGuid` |
| Command line | `CommandLine` |
| User | `User` |

Recommended source contract:

```spl
sourcetype=XmlWinEventLog
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
```

The index name is selectable and does not need to be `botsv3`.

### Windows Security EventCode 4688 preset

| Meaning | Expected field |
|---|---|
| Parent process | `Creator_Process_Name` |
| Child process | `New_Process_Name` |
| Parent PID | `Creator_Process_ID` |
| Child PID | `New_Process_ID` |
| Command line | `Process_Command_Line` |
| User | `SubjectUserName` |

Recommended source contract:

```spl
sourcetype=WinEventLog
source="WinEventLog:Security"
EventCode=4688
```

Security 4688 lineage is PID-based. Keep host and time bounds narrow enough to reduce PID-reuse ambiguity.

### Custom mapping

For another process-event schema, select **Custom field mapping** and provide six search-time field names. Each identifier must match:

```regex
^[A-Za-z_][A-Za-z0-9_.]*$
```

The process panels remain gated until the custom mapping validates and is applied.

## Search-time field visibility

Preset or custom fields must be available in the `spl_process_tree_lab` app search context. If extractions, aliases, calculated fields, or lookups are app-local elsewhere, export them appropriately or provide equivalent globally visible knowledge objects.

## Data and index readiness

- At least one enabled, searchable, non-internal index must contain compatible process-create events.
- Empty indexes can appear in the index selector but produce no dependent sourcetype/source/EventCode values.
- The index selector excludes internal, disabled, underscore-prefixed, and audit-named indexes.
- The app performs bounded search-time discovery for sourcetype/source values so normalized values remain selectable.

## Pre-install verification

From the Splunk host, verify the three dependency apps and the `pstree` command before installing Process Tree Lab:

```bash
$SPLUNK_HOME/bin/splunk btool commands list pstree --debug
$SPLUNK_HOME/bin/splunk btool check --debug
```

Then verify representative fields with bounded searches in Search & Reporting before using the dashboard. Do not use broad `index=*` validation when a known index, source, host, and time range are available.

## Post-install verification

1. Open `en-US/app/spl_process_tree_lab/process_tree` as an authorized user.
2. Select a known process-event index, sourcetype, source, EventCode, host, and explicit time range.
3. Confirm Timeline, Sankey, Force Directed, and Process Edges return bounded results.
4. Select one PID and verify the gated process tree.
5. Enter a literal tree-content term and verify the bounded content hunt.
6. Check recent `_internal` WARN/ERROR events for `spl_process_tree_lab`.
