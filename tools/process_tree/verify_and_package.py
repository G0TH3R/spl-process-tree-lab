from __future__ import annotations

import configparser
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import tempfile
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]
APP_ID = "spl_process_tree_lab"
VERSION = "1.0.4"
PACKAGE_MTIME = 1_577_836_800
EXPECTED_EDITOR_SHA256 = "ab3f8fa275fd56335ce6a5833434617af13ce99fa3402dd549256fd534410eea"
APP = ROOT / "apps" / APP_ID
PACKAGE = ROOT / "apps/_packages" / f"{APP_ID}-{VERSION}.tgz"
REPORT = ROOT / "apps/_reports" / f"{APP_ID}-{VERSION}-local-verification.json"

REQUIRED = [
    "appserver/static/css/process_tree_104.css",
    "appserver/static/js/process_tree_104.js",
    "default/app.conf",
    "default/macros.conf",
    "default/data/ui/nav/default.xml",
    "default/data/ui/views/process_tree.xml",
    "metadata/default.meta",
    "README.md",
]

CREDENTIAL_PATTERNS = {
    "private_key": re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"),
    "bearer_header": re.compile(r"(?i)authorization\s*[:=]\s*bearer\s+\S+"),
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "splunk_token_assignment": re.compile(
        r"(?i)(?:splunk|hec|mcp)[_-]?token\s*[:=]\s*[A-Za-z0-9._~+/=-]{16,}"
    ),
    "credential_assignment": re.compile(
        r"(?im)^\s*(?:password|passwd|secret|api[_-]?key|token|"
        r"access[_-]?token|auth[_-]?token|session[_-]?(?:key|token))"
        r"\s*[:=]\s*[^\s#;]+"
    ),
    "json_credential_assignment": re.compile(
        r"(?i)\"(?:password|passwd|secret|api[_-]?key|token|"
        r"access[_-]?token|auth[_-]?token|session[_-]?(?:key|token))\""
        r"\s*:\s*\"[^\"\r\n]{4,}\""
    ),
}

RAW_EVENT_PATTERNS = {
    "timestamped_sysmon_fields": re.compile(
        r"(?im)^\s*(?:\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}|"
        r"\d{1,2}/\d{1,2}/\d{4}\s+\d{2}:\d{2}:\d{2})[^\n]*"
        r"(?:\bComputerName\s*=.*\bEventCode\s*=|\bEventCode\s*=.*\bComputerName\s*=)"
    ),
    "windows_event_xml": re.compile(
        r"(?is)<Event(?:\s[^>]*)?>.*?<EventID\b[^>]*>\s*\"?\d+\"?\s*</EventID>.*?</Event>"
    ),
    "windows_event_json": re.compile(
        r"(?is)\{(?=[^{}]*\"(?:EventCode|EventID)\"\s*:\s*\"?\d+\"?)"
        r"(?=[^{}]*\"ComputerName\"\s*:)[^{}]*\}"
    ),
    "windows_event_key_value": re.compile(
        r"(?im)^(?=[^\n]*\bComputerName\s*=)(?=[^\n]*\bEventCode\s*=)[^\n]+$"
    ),
    "windows_event_multiline_key_value": re.compile(
        r"(?is)(?:\bComputerName\s*=[^\n]*(?:\n[^\n]*){0,10}?\bEventCode\s*=|"
        r"\bEventCode\s*=[^\n]*(?:\n[^\n]*){0,10}?\bComputerName\s*=)"
    ),
}


class VerificationError(RuntimeError):
    """Raised when an app or package contract fails closed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def require_element(element: Optional[ET.Element], message: str) -> ET.Element:
    if element is None:
        raise VerificationError(message)
    return element


def parse_conf(path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.read(path, encoding="utf-8")
    return parser


def require_safe_output_path(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        output_mode = path.lstat().st_mode
    except FileNotFoundError:
        return
    require(
        stat.S_ISREG(output_mode),
        f"output path must be absent or a regular file: {path}",
    )


def atomic_write_bytes(path: Path, content: bytes) -> None:
    require_safe_output_path(path)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def atomic_write_text(path: Path, content: str) -> None:
    atomic_write_bytes(path, content.encode("utf-8"))


def normalized_pipeline_segments(query: str) -> List[str]:
    normalized_query = " ".join(query.split())
    return [
        " ".join(segment.split())
        for segment in re.split(r"\s+\|\s+", normalized_query)
    ]


def validate_visualization_contracts(view: ET.Element) -> None:
    contracts = {
        "sankey_diagram_app.sankey_diagram": "table source target value",
        "force_directed_viz.force_directed": "table src_ip dest_ip count",
    }
    for viz_type, expected_final_table in contracts.items():
        visualizations = view.findall(f".//viz[@type='{viz_type}']")
        require(
            len(visualizations) == 1,
            f"expected exactly one {viz_type} visualization",
        )
        query_element = visualizations[0].find("./search/query")
        if query_element is None:
            raise VerificationError(f"{viz_type} visualization query is missing")
        segments = normalized_pipeline_segments(query_element.text or "")
        require(
            bool(segments) and segments[-1] == expected_final_table,
            f"{viz_type} visualization must end with {expected_final_table}",
        )


def package_files() -> List[Path]:
    return sorted(
        path
        for path in APP.rglob("*")
        if path.is_file()
        and path.name != ".DS_Store"
        and not path.name.startswith("._")
        and "__pycache__" not in path.parts
    )


def create_package(files: List[Path]) -> List[str]:
    PACKAGE.parent.mkdir(parents=True, exist_ok=True)
    expected_names = [str(Path(APP_ID) / path.relative_to(APP)) for path in files]
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for path, arcname in zip(files, expected_names):
            info = archive.gettarinfo(str(path), arcname=arcname)
            info.type = tarfile.REGTYPE
            info.linkname = ""
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            info.mtime = PACKAGE_MTIME
            with path.open("rb") as handle:
                archive.addfile(info, handle)
    tar_buffer.seek(0)
    compressed_buffer = io.BytesIO()
    with gzip.GzipFile(
        filename="", mode="wb", fileobj=compressed_buffer, mtime=0
    ) as compressed:
        compressed.write(tar_buffer.getvalue())
    atomic_write_bytes(PACKAGE, compressed_buffer.getvalue())
    with tarfile.open(PACKAGE, "r:gz") as archive:
        members = archive.getmembers()
    require(
        [member.name for member in members] == expected_names,
        "package member names must exactly match the app-root inventory",
    )
    for member in members:
        require(member.isfile(), f"package member must be a regular file: {member.name}")
        require(member.linkname == "", f"package member linkname must be empty: {member.name}")
        require(member.mtime == PACKAGE_MTIME, f"package member mtime is not fixed: {member.name}")
        require(member.mode == 0o644, f"package member mode must be 0644: {member.name}")
    return [member.name for member in members]


def validate_spl_contracts(view: ET.Element, macros: configparser.ConfigParser) -> None:
    definition = " ".join(
        macros["process_tree_sysmon_base"]["definition"].split()
    )
    expected_definition = (
        'index=botsv3 sourcetype=XmlWinEventLog '
        'source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1'
    )
    require(
        definition == expected_definition,
        "Sysmon macro definition must equal the approved fixed base search",
    )
    require(
        view.attrib.get("script") == "js/process_tree_104.js"
        and view.attrib.get("stylesheet") == "css/process_tree_104.css",
        "process_tree must use the approved versioned assets",
    )
    init_token = require_element(
        view.find("./init/set[@token='filter_spl']"),
        "filter_spl initialization is missing",
    )
    require(
        " ".join((init_token.text or "").split()) == "| search *",
        "filter_spl must initialize to a neutral event-preserving filter",
    )
    serialized_view = ET.tostring(view, encoding="unicode")
    for element_id in (
        "process-tree-base-spl",
        "process-tree-apply-spl",
        "process-tree-reset-spl",
        "process-tree-editor-status",
        "custom-parent-image",
        "custom-image",
        "custom-parent-pid",
        "custom-pid",
        "custom-command-line",
        "custom-user",
        "apply-custom-mapping",
        "custom-mapping-status",
    ):
        require(f'id="{element_id}"' in serialized_view, f"missing editor element {element_id}")

    host_input = view.find(".//input[@token='host']")
    if host_input is None:
        raise VerificationError("host population input is missing")
    host_query_element = host_input.find("./search/query")
    if host_query_element is None:
        raise VerificationError("host population query is missing")
    host_query = " ".join((host_query_element.text or "").split())
    expected_host_query = (
        "index=$data_index|s$ sourcetype=$data_sourcetype|s$ "
        "source=$data_source|s$ EventCode=$data_eventcode|s$ "
        "| stats count by host | sort 0 host | head 100"
    )
    require(
        host_query == expected_host_query,
        "host population query must use the exact selected process-event scope",
    )

    root_input = require_element(
        view.find(".//input[@token='root_guid']"), "root_guid input is missing"
    )
    root_query_element = require_element(
        root_input.find("./search/query"), "root_guid population query is missing"
    )
    root_query = " ".join((root_query_element.text or "").split())
    require(
        root_query.startswith(
            "index=$data_index|s$ sourcetype=$data_sourcetype|s$ "
            "source=$data_source|s$ EventCode=$data_eventcode|s$"
        )
        and "$filter_spl$" in root_query
        and "by pt_entity" in root_query
        and root_query.endswith("head 100"),
        "root entity query must use the approved normalized bounded scope",
    )
    require(
        len(root_input.findall("./search/earliest")) == 1
        and (root_input.findtext("./search/earliest") or "").strip() == "$time.earliest$"
        and len(root_input.findall("./search/latest")) == 1
        and (root_input.findtext("./search/latest") or "").strip() == "$time.latest$",
        "root_guid query must use dashboard time bounds",
    )

    controls = {
        element.attrib["token"]: element
        for element in view.findall(".//input")
        if "token" in element.attrib
    }
    require(
        set(controls)
        == {
            "data_index", "data_sourcetype", "data_source", "data_eventcode",
            "schema_mode", "host", "time", "root_guid", "process_filter",
            "min_count", "node_mode", "pstree_pid", "pstree_hunt",
        },
        "dashboard controls do not match the approved inventory",
    )
    require(
        {choice.attrib.get("value") for choice in controls["min_count"].findall("./choice")}
        == {"1", "2", "5", "10"},
        "min_count choices are not allowlisted",
    )
    require(
        {choice.attrib.get("value") for choice in controls["node_mode"].findall("./choice")}
        == {"application", "pid"},
        "node_mode choices are not allowlisted",
    )
    selector_queries = {
        token: " ".join((controls[token].findtext("./search/query") or "").split())
        for token in ("data_index", "data_sourcetype", "data_source", "data_eventcode")
    }
    require(
        selector_queries["data_index"]
        == '| rest splunk_server=local count=0 /services/data/indexes | search disabled=0 isInternal=0 | rename title as index | fields index | where NOT match(index,"(?i)(^_|audit)") | sort 0 index | head 200',
        "index selector must use exact non-internal REST inventory scope",
    )
    require(
        selector_queries["data_sourcetype"]
        == "index=$data_index|s$ | stats count by sourcetype | sort 0 - count | head 200",
        "sourcetype selector query is not approved",
    )
    require(
        selector_queries["data_source"]
        == "index=$data_index|s$ sourcetype=$data_sourcetype|s$ | stats count by source | sort 0 - count | head 500",
        "source selector query is not approved",
    )
    require(
        selector_queries["data_eventcode"]
        == "index=$data_index|s$ sourcetype=$data_sourcetype|s$ source=$data_source|s$ | stats count by EventCode | sort 0 - count | head 500",
        "EventCode selector query is not approved",
    )
    for selector_token in ("data_sourcetype", "data_source", "data_eventcode"):
        require(
            (controls[selector_token].findtext("./search/earliest") or "").strip()
            == "$time.earliest$"
            and (controls[selector_token].findtext("./search/latest") or "").strip()
            == "$time.latest$",
            f"{selector_token} selector must use exact dashboard time bounds",
        )
    schema_input = controls["schema_mode"]
    require(
        {choice.attrib.get("value") for choice in schema_input.findall("./choice")}
        == {"sysmon", "security4688", "custom"},
        "schema mode choices are not allowlisted",
    )
    schema_conditions = {
        condition.attrib.get("value", "default"): condition
        for condition in schema_input.findall("./change/condition")
    }
    expected_presets = {
        "sysmon": {
            "pt_parent_image_field": "ParentImage", "pt_image_field": "Image",
            "pt_parent_pid_field": "ParentProcessId", "pt_pid_field": "ProcessId",
            "pt_command_line_field": "CommandLine", "pt_user_field": "User",
            "mapping_ready": "true",
        },
        "security4688": {
            "pt_parent_image_field": "Creator_Process_Name", "pt_image_field": "New_Process_Name",
            "pt_parent_pid_field": "Creator_Process_ID", "pt_pid_field": "New_Process_ID",
            "pt_command_line_field": "Process_Command_Line", "pt_user_field": "SubjectUserName",
            "mapping_ready": "true",
        },
    }
    init_mapping = {
        item.attrib.get("token"): (item.text or "").strip()
        for item in view.findall("./init/set")
        if item.attrib.get("token") in expected_presets["sysmon"]
    }
    require(
        init_mapping == expected_presets["sysmon"],
        "default Sysmon mapping tokens are not exact",
    )
    for mode, expected_tokens in expected_presets.items():
        condition = require_element(schema_conditions.get(mode), f"missing {mode} schema condition")
        actual_tokens = {
            item.attrib.get("token"): (item.text or "").strip()
            for item in condition.findall("./set")
        }
        require(actual_tokens == expected_tokens, f"{mode} schema mapping is not exact")
        require(
            condition.find("./unset[@token='custom_mapping']") is not None,
            f"{mode} schema must hide custom mapping controls",
        )
    custom_condition = require_element(
        schema_conditions.get("custom"), "missing custom schema condition"
    )
    require(
        custom_condition.find("./unset[@token='mapping_ready']") is not None
        and (custom_condition.findtext("./set[@token='custom_mapping']") or "").strip()
        == "true",
        "custom schema must clear mapping readiness and expose custom controls",
    )
    custom_panel = require_element(
        view.find(".//panel[@id='custom_mapping_panel']"),
        "custom mapping panel is missing",
    )
    require(
        custom_panel.attrib.get("depends") == "$custom_mapping$",
        "custom mapping panel must remain gated by custom schema mode",
    )
    pid_input = controls["pstree_pid"]
    pid_query = " ".join((pid_input.findtext("./search/query") or "").split())
    require(
        pid_query.startswith(
            "index=$data_index|s$ sourcetype=$data_sourcetype|s$ "
            "source=$data_source|s$ EventCode=$data_eventcode|s$"
        )
        and "$filter_spl$" in pid_query
        and "by pt_pid" in pid_query
        and pid_query.endswith("head 1000"),
        "pstree PID selector query is not approved",
    )
    require(
        (pid_input.findtext("./default") or "").strip() == "__select__"
        and any(
            choice.attrib.get("value") == "__select__"
            and (choice.text or "").strip() == "Select a PID"
            for choice in pid_input.findall("./choice")
        ),
        "pstree PID selector must default to a non-executing selection",
    )
    require(
        pid_input.find("./change/condition/unset[@token='show_pstree']") is not None
        and pid_input.find("./change/condition/set[@token='show_pstree']") is not None,
        "pstree PID selector must explicitly gate the pstree panel",
    )
    require(
        (pid_input.findtext("./search/earliest") or "").strip() == "$time.earliest$"
        and (pid_input.findtext("./search/latest") or "").strip() == "$time.latest$",
        "pstree PID selector must use exact dashboard time bounds",
    )
    hunt_input = controls["pstree_hunt"]
    require(
        hunt_input.attrib.get("type") == "text"
        and hunt_input.find("./default") is None,
        "pstree content hunt must remain an unset text input",
    )

    all_searches = view.findall(".//search")
    require(
        len(all_searches) == 13,
        "dashboard search inventory must contain four data selectors, host, root, PID, two pstree panels, timeline, and three relationship searches",
    )

    sankey = require_element(
        view.find(".//viz[@type='sankey_diagram_app.sankey_diagram']/search"),
        "Sankey search is missing",
    )
    force = require_element(
        view.find(".//viz[@type='force_directed_viz.force_directed']/search"),
        "Force Directed search is missing",
    )
    process_edges = None
    process_timeline = None
    selected_pid_tree = None
    selected_pid_panel = None
    content_hunt_tree = None
    content_hunt_panel = None
    for panel in view.findall(".//panel"):
        title = (panel.findtext("./title") or "").strip()
        if title == "Process Edges":
            process_edges = panel.find("./table/search")
        elif title == "Process Events Over Time":
            process_timeline = panel.find("./chart/search")
        elif title == "Selected PID Process Tree":
            selected_pid_panel = panel
            selected_pid_tree = panel.find("./table/search")
        elif title == "Process Tree Content Hunt":
            content_hunt_panel = panel
            content_hunt_tree = panel.find("./table/search")
    process_panel_titles = {
        "Selected PID Process Tree", "Process Tree Content Hunt",
        "Process Events Over Time", "Sankey Process Flow",
        "Force Directed Process Relationships", "Process Edges",
    }
    for panel in view.findall(".//panel"):
        title = (panel.findtext("./title") or "").strip()
        if title in process_panel_titles:
            require(
                "$mapping_ready$" in panel.attrib.get("depends", ""),
                f"{title} must remain gated by mapping readiness",
            )
    process_edges = require_element(process_edges, "Process Edges search is missing")
    process_timeline = require_element(
        process_timeline, "Process Events Over Time search is missing"
    )
    selected_pid_tree = require_element(
        selected_pid_tree, "Selected PID Process Tree search is missing"
    )
    selected_pid_panel = require_element(
        selected_pid_panel, "Selected PID Process Tree panel is missing"
    )
    require(
        "$mapping_ready$" in selected_pid_panel.attrib.get("depends", "")
        and "$show_pstree$" in selected_pid_panel.attrib.get("depends", ""),
        "Selected PID Process Tree panel must remain gated by PID selection",
    )
    content_hunt_tree = require_element(
        content_hunt_tree, "Process Tree Content Hunt search is missing"
    )
    content_hunt_panel = require_element(
        content_hunt_panel, "Process Tree Content Hunt panel is missing"
    )
    require(
        "$mapping_ready$" in content_hunt_panel.attrib.get("depends", "")
        and "$pstree_hunt$" in content_hunt_panel.attrib.get("depends", ""),
        "Process Tree Content Hunt panel must remain gated by hunt text",
    )
    relationship_searches = [
        ("Sankey", sankey),
        ("Force Directed", force),
        ("Process Edges", process_edges),
    ]
    selected_scope = (
        "index=$data_index|s$ sourcetype=$data_sourcetype|s$ "
        "source=$data_source|s$ EventCode=$data_eventcode|s$"
    )
    base_filter = (
        'search host=$host|s$ pt_parent_entity=$root_guid|s$ '
        '(pt_image=$process_filter|s$ OR pt_parent_image=$process_filter|s$)'
    )
    normalized_tokens = {
        "$pt_parent_image_field$", "$pt_image_field$", "$pt_parent_pid_field$",
        "$pt_pid_field$", "$pt_command_line_field$", "$pt_user_field$",
    }
    forbidden_commands = {
        "append", "appendcols", "appendpipe", "collect", "delete", "dump",
        "join", "map", "mcollect", "meventcollect", "multisearch", "outputcsv",
        "outputlookup", "run", "runshellscript", "script", "sendalert", "sendemail",
        "set", "tscollect", "union",
    }
    timeline_query = " ".join((process_timeline.findtext("./query") or "").split())
    require(
        timeline_query.startswith(selected_scope)
        and "$filter_spl$" in timeline_query
        and normalized_tokens.issubset(set(re.findall(r"\$[^$]+\$", timeline_query)))
        and base_filter in timeline_query
        and "eventstats count as edge_count by pt_parent_image pt_image" in timeline_query
        and "timechart span=1h cont=false count as events by child_name limit=10 useother=true" in timeline_query,
        "Process Events Over Time query must retain selected scope, normalization, and bounded timechart",
    )
    require(
        (process_timeline.findtext("./earliest") or "").strip() == "$time.earliest$"
        and (process_timeline.findtext("./latest") or "").strip() == "$time.latest$",
        "Process Events Over Time must use exact dashboard time bounds",
    )
    pstree_query = " ".join((selected_pid_tree.findtext("./query") or "").split())
    require(
        pstree_query.startswith(selected_scope)
        and "$filter_spl$" in pstree_query
        and normalized_tokens.issubset(set(re.findall(r"\$[^$]+\$", pstree_query)))
        and "where isnotnull(pt_parent_image)" in pstree_query
        and "pstree child=child parent=parent detail=detail spaces=50" in pstree_query
        and "mvfind(tree" in pstree_query
        and pstree_query.endswith("table tree"),
        "Selected PID Process Tree query must retain selected scope, normalization, and approved pstree pipeline",
    )
    require(
        (selected_pid_tree.findtext("./earliest") or "").strip() == "$time.earliest$"
        and (selected_pid_tree.findtext("./latest") or "").strip() == "$time.latest$",
        "Selected PID Process Tree must use exact dashboard time bounds",
    )
    content_hunt_query = " ".join((content_hunt_tree.findtext("./query") or "").split())
    require(
        content_hunt_query.startswith(selected_scope)
        and "$filter_spl$" in content_hunt_query
        and normalized_tokens.issubset(set(re.findall(r"\$[^$]+\$", content_hunt_query)))
        and "where isnotnull(pt_parent_image)" in content_hunt_query
        and "pstree child=child parent=parent detail=detail spaces=50" in content_hunt_query
        and "like(lower(mvjoin(tree" in content_hunt_query
        and "head 3" in content_hunt_query
        and "eval tree=mvindex(tree,0,199)" in content_hunt_query
        and content_hunt_query.endswith("table tree"),
        "Process Tree Content Hunt query must retain selected scope, normalization, and bounded post-pstree filter",
    )
    require(
        (content_hunt_tree.findtext("./earliest") or "").strip() == "$time.earliest$"
        and (content_hunt_tree.findtext("./latest") or "").strip() == "$time.latest$",
        "Process Tree Content Hunt must use exact dashboard time bounds",
    )
    for panel_name, search in relationship_searches:
        query_element = require_element(
            search.find("./query"), f"{panel_name} query is missing"
        )
        query = " ".join((query_element.text or "").split())
        earliest = search.findall("./earliest")
        latest = search.findall("./latest")
        require(
            len(earliest) == 1
            and (earliest[0].text or "").strip() == "$time.earliest$"
            and len(latest) == 1
            and (latest[0].text or "").strip() == "$time.latest$",
            "relationship search must use exact dashboard time bounds",
        )
        segments = normalized_pipeline_segments(query)
        require(
            query.startswith(selected_scope)
            and "$filter_spl$" in query
            and normalized_tokens.issubset(set(re.findall(r"\$[^$]+\$", query)))
            and base_filter in segments,
            f"{panel_name} must retain selected scope, normalization, and exact bounded filters",
        )
        require("edge_limit" not in query, "relationship search must not use edge_limit")
        head_commands = [
            segment
            for segment in segments
            if re.match(r"(?i)^head(?:\s|$)", segment)
        ]
        require(
            head_commands == ["head 80"],
            "relationship search must contain exactly one complete head 80 command",
        )
        require("index=*" not in query, "relationship search must not use index=*")

        command_names = {
            segment.split(None, 1)[0].lower()
            for segment in segments[1:]
            if segment
        }
        detected_forbidden = sorted(command_names & forbidden_commands)
        require(
            not detected_forbidden,
            f"relationship search contains forbidden fan-out commands: {detected_forbidden}",
        )
        require("$node_mode|s$" in query, f"{panel_name} must use the node_mode allowlist")
        require("tonumber($min_count|s$)" in query, f"{panel_name} must safely convert min_count")

    sankey_segments = normalized_pipeline_segments(sankey.findtext("./query") or "")
    force_segments = normalized_pipeline_segments(force.findtext("./query") or "")
    edge_segments = normalized_pipeline_segments(process_edges.findtext("./query") or "")
    require(sankey_segments[-1] == "table source target value", "Sankey schema is invalid")
    require("stats count as value by source target" in sankey_segments, "Sankey aggregation is missing")
    require(force_segments[-1] == "table src_ip dest_ip count", "Force Directed schema is invalid")
    require("stats count by src_ip dest_ip" in force_segments, "Force Directed aggregation is missing")
    require(
        "table _time parent_process child_process edge_count pt_user pt_command_line lineage_key"
        in edge_segments,
        "Process Edges table schema is invalid",
    )


def build_and_verify() -> Dict[str, object]:
    missing = []
    for relative in REQUIRED:
        path = APP / relative
        try:
            source_mode = path.lstat().st_mode
        except FileNotFoundError:
            missing.append(relative)
            continue
        require(
            stat.S_ISREG(source_mode),
            f"required source must be a regular file: {relative}",
        )
    if missing:
        raise VerificationError(f"missing required files: {missing}")
    files = package_files()
    inventory = {str(path.relative_to(APP)) for path in files}
    required_inventory = set(REQUIRED)
    unexpected = sorted(inventory - required_inventory)
    if unexpected:
        raise VerificationError(f"unexpected app files: {unexpected}")
    require(inventory == required_inventory, "package inventory must equal required files")

    checks: Dict[str, object] = {}
    editor_digest = hashlib.sha256(
        (APP / "appserver/static/js/process_tree_104.js").read_bytes()
    ).hexdigest()
    require(
        editor_digest == EXPECTED_EDITOR_SHA256,
        "editor guard asset does not match the reviewed digest",
    )
    checks["editor_guard_digest"] = "passed"
    app_conf = parse_conf(APP / "default/app.conf")
    macros = parse_conf(APP / "default/macros.conf")
    require(app_conf["id"]["name"] == APP_ID, "app id name does not match")
    require(app_conf["id"]["version"] == VERSION, "app version does not match")
    require(app_conf["package"]["id"] == APP_ID, "package id does not match")
    require(app_conf["ui"].getboolean("is_visible") is True, "app must remain visible")
    checks["app_identity"] = "passed"

    nav = ET.parse(APP / "default/data/ui/nav/default.xml").getroot()
    view = ET.parse(APP / "default/data/ui/views/process_tree.xml").getroot()
    nav_view = nav.find("view")
    if nav_view is None:
        raise VerificationError("default navigation view is missing")
    require(
        nav_view.attrib == {"name": "process_tree", "default": "true"},
        "default navigation must open process_tree",
    )
    require(
        view.tag == "form" and view.attrib.get("version") == "1.1",
        "process_tree must remain a Simple XML 1.1 form",
    )
    validate_visualization_contracts(view)
    checks["xml_and_visualizations"] = "passed"

    validate_spl_contracts(view, macros)
    checks["spl_contracts"] = "passed"

    scanned = 0
    for path in files:
        body = path.read_text(encoding="utf-8")
        for name, pattern in CREDENTIAL_PATTERNS.items():
            if pattern.search(body):
                raise VerificationError(
                    f"potential {name} in {path.relative_to(ROOT)}"
                )
        for name, pattern in RAW_EVENT_PATTERNS.items():
            if pattern.search(body):
                raise VerificationError(
                    f"potential raw event ({name}) in {path.relative_to(ROOT)}"
                )
        scanned += 1
    checks["credential_scan"] = "passed"
    checks["credential_scan_files"] = scanned
    checks["credential_scan_patterns"] = sorted(CREDENTIAL_PATTERNS)
    checks["raw_event_scan"] = "passed"
    checks["raw_event_scan_files"] = scanned
    checks["raw_event_scan_patterns"] = sorted(RAW_EVENT_PATTERNS)

    members = create_package(files)
    require(bool(members), "package must not be empty")
    require(
        all(member.startswith(APP_ID + "/") for member in members),
        "package members must be rooted under the app id",
    )
    require(
        all("._" not in member and ".DS_Store" not in member for member in members),
        "package must not contain macOS metadata",
    )
    for relative in REQUIRED:
        require(f"{APP_ID}/{relative}" in members, f"package is missing {relative}")
    first_package_bytes = PACKAGE.read_bytes()
    repeated_members = create_package(files)
    require(repeated_members == members, "repeated package inventory changed")
    require(
        PACKAGE.read_bytes() == first_package_bytes,
        "two package builds were not byte-identical",
    )
    checks["package"] = {
        "status": "passed",
        "files": len(members),
        "reproducible": "passed",
    }

    digest = hashlib.sha256(PACKAGE.read_bytes()).hexdigest()
    report: Dict[str, object] = {
        "app_id": APP_ID,
        "version": VERSION,
        "status": "local-package-validated-not-installed",
        "checks": checks,
        "package": str(PACKAGE.relative_to(ROOT)),
        "sha256": digest,
        "live_install_performed": False,
        "live_render_verified": False,
    }
    atomic_write_text(REPORT, json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main() -> None:
    print(json.dumps(build_and_verify(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
