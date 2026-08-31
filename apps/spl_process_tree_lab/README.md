# Process Tree Lab

A compact Splunk Classic dashboard for bounded process-relationship analysis across selectable Splunk indexes and Windows process-event schemas. It defaults to the imported BOTS v3 Sysmon data.

## Author

**G0TH3R** — CTF Lead, Cloud Village<br>
GitHub: [@G0TH3R](https://github.com/G0TH3R)

Version 1.0.4 adds cascading index, sourcetype, source, and EventCode selectors; Sysmon EventCode 1 and Windows Security 4688 presets; validated custom process-field mapping; and a collapsible optional filter-SPL editor. Selector resets bind after Simple XML readiness so defaults initialize cleanly, while later upstream changes clear stale downstream values. Sourcetype and source choices use bounded search-time discovery, and the selected schema preset is applied after readiness so URL-prefilled Security 4688 searches normalize correctly. Custom-command panels remain gated and output bounded. The browser stores filter text and collapse state only for the active tab and never stores result rows.

## Views

- **Sankey Diagram** — aggregates parent-to-child executable/PID flows into `source`, `target`, and `value`.
- **Force Directed Visualization** — emits `src_ip`, `dest_ip`, and `count` for relationship exploration.
- **Process Edges** — tabular event time, parent/child process, PID, user, command line, and GUID lineage.
- **Process Events Over Time** — line chart of process-create event counts split by the ten busiest child executables.
- **Selected PID Process Tree** — the full `pstree` root containing the selected PID.
- **Process Tree Content Hunt** — the complete tree containing a case-insensitive command-line or process-text match, applying the filter after `pstree` as described by Splunk.

## Investigation controls

- Cascading data source: index → sourcetype → source → EventCode
- Process schema: Sysmon 1, Windows Security 4688, or Custom
- Host and dashboard time range
- Root process entity selector (GUID when present, otherwise PID)
- Process-path wildcard filter
- Minimum repeated-edge count: 1, 2, 5, or 10
- Application-only or application-plus-PID node labels
- Optional filter SPL with Apply, Reset, and Cmd/Ctrl+Enter
- Host/time-scoped PID selector; narrow the time range when Windows PID reuse is possible
- Free-text tree-content hunt; for example, `powershell.exe`, `git status`, or a document name

## Supported mappings

| Schema | Parent process | Child process | Parent PID | Child PID | Command line | User |
|---|---|---|---|---|---|---|
| Sysmon EventCode 1 | `ParentImage` | `Image` | `ParentProcessId` | `ProcessId` | `CommandLine` | `User` |
| Windows Security 4688 | `Creator_Process_Name` | `New_Process_Name` | `Creator_Process_ID` | `New_Process_ID` | `Process_Command_Line` | `SubjectUserName` |

Custom mode requires six Splunk field identifiers. The browser validates each name against `^[A-Za-z_][A-Za-z0-9_.]*$` before setting effective search tokens. Process panels stay gated until the custom mapping is applied.

The filter editor accepts only pipelines beginning with `|` and the non-writing commands `search` and `where`. Index, sourcetype, source, and EventCode constraints belong in the cascading selectors. Field-writing commands such as `eval` and `rex`, macros, subsearches, comments, transforming commands, write commands, and fan-out commands are rejected.

## Runtime dependencies

- Splunk Enterprise 10.4.1 is the tested runtime; other versions are not asserted until tested
- Classic Simple XML 1.1 and app-local JavaScript/CSS support on the search tier
- User search permission for every selected index and access to the `pstree` custom command
- At least one searchable non-internal index with process-creation events
- `sankey_diagram_app.sankey_diagram`
- `force_directed_viz.force_directed`
- `splunk_pstree_app` 2.1.0 or newer, providing the `pstree` custom search command

The custom visualization and `pstree` dependencies must already be installed and enabled. This app does not package or modify them.

The complete environment, permission, dependency, field, and validation requirements are documented in [Process Tree Lab prerequisites](../../docs/process-tree-lab/prerequisites.md).

## Screenshots

See the [Process Tree Lab screenshot gallery](../../docs/process-tree-lab/screenshots.md) for the controls, Timeline, Sankey, Force Directed, Process Edges, selected-PID tree, content hunt, custom mapping, and collapsed filter states.

The content-hunt panel adapts the post-`pstree` filtering pattern from [Process Hunting with PSTree](https://www.splunk.com/en_us/blog/security/process-hunting-with-a-process.html) (Splunk, March 26, 2024) to the verified BOTS v3 host/source scope. No code or assets from the article are packaged.

## Safety

- Searches require selected index/sourcetype/source/EventCode/host values, explicit dashboard time bounds, and fixed output caps.
- Index discovery uses the local Splunk index REST inventory and excludes internal indexes and names containing `audit`.
- Client-side validation blocks action-capable and fan-out commands as defense in depth; Splunk role capabilities remain authoritative.
- The app ships no scheduled searches, inputs, raw events, credentials, or BOTS buckets.
- The dashboard is read-only and runs searches as the signed-in Splunk user.


## Development

Run the structural contracts from the repository root:

```bash
python3 -m unittest tools/process_tree/test_app_contracts.py -v
```

Live installation, replacement, restart, rollback, or remote publication requires separate explicit approval.
