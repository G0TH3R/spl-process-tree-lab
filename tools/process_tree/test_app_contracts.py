from __future__ import annotations

import configparser
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "apps" / "spl_process_tree_lab"
VIEW = APP / "default/data/ui/views/process_tree.xml"


class ProcessTreeAppContracts(unittest.TestCase):
    def test_required_app_files_exist(self) -> None:
        required = [
            "appserver/static/css/process_tree_104.css",
            "appserver/static/js/process_tree_104.js",
            "default/app.conf",
            "default/macros.conf",
            "default/data/ui/nav/default.xml",
            "default/data/ui/views/process_tree.xml",
            "metadata/default.meta",
            "README.md",
        ]

        missing = [relative for relative in required if not (APP / relative).is_file()]

        self.assertEqual(missing, [])

    def test_app_identity_and_visibility(self) -> None:
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        parser.read(APP / "default/app.conf", encoding="utf-8")

        self.assertEqual(parser["id"]["name"], "spl_process_tree_lab")
        self.assertEqual(parser["id"]["version"], "1.0.4")
        self.assertEqual(parser["package"]["id"], "spl_process_tree_lab")
        self.assertTrue(parser["ui"].getboolean("is_visible"))
        self.assertEqual(parser["ui"]["label"], "Process Tree Lab")

    def test_navigation_opens_process_tree(self) -> None:
        nav = ET.parse(APP / "default/data/ui/nav/default.xml").getroot()
        view = nav.find("view")

        if view is None:
            self.fail("default navigation view is missing")
        self.assertEqual(view.attrib, {"name": "process_tree", "default": "true"})

    def test_dashboard_contains_both_relationship_visualizations(self) -> None:
        root = ET.parse(VIEW).getroot()

        self.assertEqual(root.tag, "form")
        self.assertEqual(root.attrib.get("version"), "1.1")
        self.assertEqual(root.attrib.get("theme"), "dark")
        self.assertEqual(root.attrib.get("script"), "js/process_tree_104.js")
        self.assertEqual(root.attrib.get("stylesheet"), "css/process_tree_104.css")
        contracts = {
            "sankey_diagram_app.sankey_diagram": "table source target value",
            "force_directed_viz.force_directed": "table src_ip dest_ip count",
        }
        for viz_type, expected_final_table in contracts.items():
            visualizations = root.findall(f".//viz[@type='{viz_type}']")
            self.assertEqual(len(visualizations), 1)
            query_element = visualizations[0].find("./search/query")
            if query_element is None:
                self.fail(f"{viz_type} query is missing")
            query = " ".join((query_element.text or "").split())
            segments = re.split(r"\s+\|\s+", query)
            self.assertEqual(segments[-1], expected_final_table)

    def test_dashboard_has_editor_and_requested_controls(self) -> None:
        root = ET.parse(VIEW).getroot()
        body = ET.tostring(root, encoding="unicode")
        tokens = {element.attrib.get("token") for element in root.findall(".//input")}

        self.assertIn('id="process-tree-base-spl"', body)
        self.assertIn('id="process-tree-apply-spl"', body)
        self.assertIn('id="process-tree-reset-spl"', body)
        self.assertIn("root_guid", tokens)
        self.assertIn("process_filter", tokens)
        self.assertIn("min_count", tokens)
        self.assertIn("node_mode", tokens)
        self.assertIn("host", tokens)
        self.assertIn("time", tokens)

    def test_dashboard_has_bounded_cascading_data_source_selectors(self) -> None:
        root = ET.parse(VIEW).getroot()
        inputs = {
            element.attrib.get("token"): element for element in root.findall(".//input")
        }
        for token in ("data_index", "data_sourcetype", "data_source", "data_eventcode"):
            self.assertIn(token, inputs)

        index_input = inputs["data_index"]
        index_query = " ".join((index_input.findtext("./search/query") or "").split())
        self.assertIn("| rest splunk_server=local count=0 /services/data/indexes", index_query)
        self.assertIn("isInternal=0", index_query)
        self.assertIn('NOT match(index,"(?i)(^_|audit)")', index_query)
        self.assertTrue(index_query.endswith("sort 0 index | head 200"))
        self.assertEqual(index_input.findtext("./default"), "botsv3")

        sourcetype_input = inputs["data_sourcetype"]
        sourcetype_query = " ".join(
            (sourcetype_input.findtext("./search/query") or "").split()
        )
        self.assertEqual(
            sourcetype_query,
            "index=$data_index|s$ | stats count by sourcetype | sort 0 - count | head 200",
        )
        self.assertEqual(sourcetype_input.findtext("./default"), "XmlWinEventLog")

        source_input = inputs["data_source"]
        source_query = " ".join((source_input.findtext("./search/query") or "").split())
        self.assertEqual(
            source_query,
            "index=$data_index|s$ sourcetype=$data_sourcetype|s$ | stats count by source | sort 0 - count | head 500",
        )
        self.assertEqual(
            source_input.findtext("./default"),
            "WinEventLog:Microsoft-Windows-Sysmon/Operational",
        )

        event_input = inputs["data_eventcode"]
        event_query = " ".join((event_input.findtext("./search/query") or "").split())
        self.assertEqual(
            event_query,
            "index=$data_index|s$ sourcetype=$data_sourcetype|s$ source=$data_source|s$ | stats count by EventCode | sort 0 - count | head 500",
        )
        self.assertEqual(event_input.findtext("./default"), "1")
        for token in ("data_sourcetype", "data_source", "data_eventcode"):
            self.assertEqual(inputs[token].findtext("./search/earliest"), "$time.earliest$")
            self.assertEqual(inputs[token].findtext("./search/latest"), "$time.latest$")
        fieldset_tokens = [
            element.attrib.get("token")
            for element in root.findall("./fieldset/input")
        ]
        self.assertLess(fieldset_tokens.index("time"), fieldset_tokens.index("data_index"))

    def test_cascading_selectors_defer_resets_until_simplexml_ready(self) -> None:
        root = ET.parse(VIEW).getroot()
        inputs = {
            element.attrib.get("token"): element
            for element in root.findall(".//input")
            if element.attrib.get("token")
        }
        for upstream in ("data_index", "data_sourcetype", "data_source", "data_eventcode"):
            self.assertIsNone(inputs[upstream].find("./change"))
        javascript = (
            APP / "appserver/static/js/process_tree_104.js"
        ).read_text(encoding="utf-8")
        self.assertIn("RESET_CHAINS", javascript)
        self.assertIn('defaultTokens.on("change:" + upstream', javascript)

    def test_dashboard_has_process_schema_presets_and_custom_mapping_gate(self) -> None:
        root = ET.parse(VIEW).getroot()
        schema_input = root.find(".//input[@token='schema_mode']")
        if schema_input is None:
            self.fail("schema_mode input is missing")
        self.assertEqual(schema_input.findtext("./default"), "sysmon")
        self.assertEqual(
            {choice.attrib.get("value") for choice in schema_input.findall("./choice")},
            {"sysmon", "security4688", "custom"},
        )

        init_tokens = {
            element.attrib.get("token"): (element.text or "").strip()
            for element in root.findall("./init/set")
        }
        self.assertEqual(init_tokens.get("pt_parent_image_field"), "ParentImage")
        self.assertEqual(init_tokens.get("pt_image_field"), "Image")
        self.assertEqual(init_tokens.get("pt_parent_pid_field"), "ParentProcessId")
        self.assertEqual(init_tokens.get("pt_pid_field"), "ProcessId")
        self.assertEqual(init_tokens.get("pt_command_line_field"), "CommandLine")
        self.assertEqual(init_tokens.get("pt_user_field"), "User")
        self.assertEqual(init_tokens.get("mapping_ready"), "true")

        serialized = ET.tostring(schema_input, encoding="unicode")
        for value in (
            "Creator_Process_Name",
            "New_Process_Name",
            "Creator_Process_ID",
            "New_Process_ID",
            "Process_Command_Line",
            "SubjectUserName",
        ):
            self.assertIn(value, serialized)
        self.assertIn('token="custom_mapping"', serialized)
        self.assertIn('token="mapping_ready"', serialized)

        custom_panel = root.find(".//panel[@id='custom_mapping_panel']")
        if custom_panel is None:
            self.fail("custom mapping panel is missing")
        self.assertEqual(custom_panel.attrib.get("depends"), "$custom_mapping$")
        custom_body = ET.tostring(custom_panel, encoding="unicode")
        for element_id in (
            "custom-parent-image",
            "custom-image",
            "custom-parent-pid",
            "custom-pid",
            "custom-command-line",
            "custom-user",
            "apply-custom-mapping",
            "custom-mapping-status",
        ):
            self.assertIn(f'id="{element_id}"', custom_body)

    def test_process_searches_use_selected_scope_and_normalized_fields(self) -> None:
        root = ET.parse(VIEW).getroot()
        body = ET.tostring(root, encoding="unicode")
        self.assertIn('<set token="filter_spl">| search *</set>', body)

        process_titles = {
            "Selected PID Process Tree",
            "Process Tree Content Hunt",
            "Process Events Over Time",
            "Sankey Process Flow",
            "Force Directed Process Relationships",
            "Process Edges",
        }
        process_queries = []
        for panel in root.findall(".//panel"):
            title = (panel.findtext("./title") or "").strip()
            if title in process_titles:
                query = " ".join((panel.findtext(".//search/query") or "").split())
                process_queries.append((title, query, panel.attrib.get("depends", "")))

        self.assertEqual({item[0] for item in process_queries}, process_titles)
        scope = (
            "index=$data_index|s$ sourcetype=$data_sourcetype|s$ "
            "source=$data_source|s$ EventCode=$data_eventcode|s$"
        )
        normalized_tokens = (
            "$pt_parent_image_field$",
            "$pt_image_field$",
            "$pt_parent_pid_field$",
            "$pt_pid_field$",
            "$pt_command_line_field$",
            "$pt_user_field$",
        )
        for title, query, depends in process_queries:
            self.assertTrue(query.startswith(scope), title)
            self.assertIn("$filter_spl$", query, title)
            for token in normalized_tokens:
                self.assertIn(token, query, title)
            self.assertIn("pt_parent_image", query, title)
            self.assertIn("pt_image", query, title)
            self.assertIn("pt_parent_pid", query, title)
            self.assertIn("pt_pid", query, title)
            self.assertIn("$mapping_ready$", depends, title)



    def test_dashboard_has_bounded_process_events_over_time_chart(self) -> None:
        root = ET.parse(VIEW).getroot()
        timeline = None
        for panel in root.findall(".//panel"):
            if (panel.findtext("./title") or "").strip() == "Process Events Over Time":
                timeline = panel.find("./chart")
                break

        if timeline is None:
            self.fail("Process Events Over Time chart is missing")
        query = " ".join((timeline.findtext("./search/query") or "").split())
        self.assertTrue(query.startswith("index=$data_index|s$ sourcetype=$data_sourcetype|s$"))
        self.assertIn("pt_parent_entity=$root_guid|s$", query)
        self.assertIn("pt_image=$process_filter|s$", query)
        self.assertIn("pt_parent_image=$process_filter|s$", query)
        self.assertIn("tonumber($min_count|s$)", query)
        self.assertIn(
            "timechart span=1h cont=false count as events by child_name limit=10 useother=true",
            query,
        )
        self.assertEqual(timeline.findtext("./option[@name='charting.chart']"), "line")
        self.assertEqual(timeline.findtext("./search/earliest"), "$time.earliest$")
        self.assertEqual(timeline.findtext("./search/latest"), "$time.latest$")

    def test_dashboard_has_host_scoped_pid_selector_and_pstree_panel(self) -> None:
        root = ET.parse(VIEW).getroot()
        pid_input = root.find(".//input[@token='pstree_pid']")
        if pid_input is None:
            self.fail("pstree_pid input is missing")
        pid_query = " ".join((pid_input.findtext("./search/query") or "").split())
        self.assertTrue(pid_query.startswith("index=$data_index|s$ sourcetype=$data_sourcetype|s$"))
        self.assertIn(
            "stats earliest(_time) as first_seen latest(pt_image) as pt_image latest(pt_entity) as pt_entity by pt_pid",
            pid_query,
        )
        self.assertIn("head 1000", pid_query)
        self.assertEqual(pid_input.findtext("./fieldForValue"), "pt_pid")
        self.assertEqual(pid_input.findtext("./default"), "__select__")
        self.assertIn(
            ("__select__", "Select a PID"),
            [
                (choice.attrib.get("value"), (choice.text or "").strip())
                for choice in pid_input.findall("./choice")
            ],
        )
        self.assertIsNotNone(pid_input.find("./change/condition/unset[@token='show_pstree']"))
        self.assertIsNotNone(pid_input.find("./change/condition/set[@token='show_pstree']"))
        self.assertEqual(pid_input.findtext("./search/earliest"), "$time.earliest$")
        self.assertEqual(pid_input.findtext("./search/latest"), "$time.latest$")

        tree_table = None
        for panel in root.findall(".//panel"):
            if (panel.findtext("./title") or "").strip() == "Selected PID Process Tree":
                self.assertIn("$show_pstree$", panel.attrib.get("depends", ""))
                tree_table = panel.find("./table")
                break
        if tree_table is None:
            self.fail("Selected PID Process Tree panel is missing")
        tree_query = " ".join((tree_table.findtext("./search/query") or "").split())
        self.assertTrue(tree_query.startswith("index=$data_index|s$ sourcetype=$data_sourcetype|s$"))
        self.assertIn("sort 0 _time", tree_query)
        self.assertIn("fields child parent detail", tree_query)
        self.assertIn("pstree child=child parent=parent detail=detail spaces=50", tree_query)
        self.assertIn("mvfind(tree", tree_query)
        self.assertIn("$pstree_pid|s$", tree_query)
        self.assertNotIn('$pstree_pid|s$="*" OR', tree_query)
        self.assertTrue(tree_query.endswith("table tree"))
        self.assertEqual(tree_table.findtext("./search/earliest"), "$time.earliest$")
        self.assertEqual(tree_table.findtext("./search/latest"), "$time.latest$")

    def test_dashboard_has_gated_article_style_pstree_content_hunt(self) -> None:
        root = ET.parse(VIEW).getroot()
        hunt_input = root.find(".//input[@token='pstree_hunt']")
        if hunt_input is None:
            self.fail("pstree_hunt input is missing")
        self.assertEqual(hunt_input.attrib.get("type"), "text")
        self.assertIsNone(hunt_input.find("./default"))

        hunt_table = None
        for panel in root.findall(".//panel"):
            if (panel.findtext("./title") or "").strip() == "Process Tree Content Hunt":
                self.assertIn("$pstree_hunt$", panel.attrib.get("depends", ""))
                hunt_table = panel.find("./table")
                break
        if hunt_table is None:
            self.fail("Process Tree Content Hunt panel is missing")
        query = " ".join((hunt_table.findtext("./search/query") or "").split())
        self.assertTrue(query.startswith("index=$data_index|s$ sourcetype=$data_sourcetype|s$"))
        self.assertIn("sort 0 _time", query)
        self.assertIn("fields child parent detail", query)
        self.assertIn("pstree child=child parent=parent detail=detail spaces=50", query)
        self.assertIn("mvjoin(tree", query)
        self.assertIn("$pstree_hunt|s$", query)
        self.assertIn("head 3", query)
        self.assertIn("eval tree=mvindex(tree,0,199)", query)
        self.assertTrue(query.endswith("table tree"))
        self.assertEqual(hunt_table.findtext("./search/earliest"), "$time.earliest$")
        self.assertEqual(hunt_table.findtext("./search/latest"), "$time.latest$")

    def test_pstree_result_panels_have_scoped_scrollable_viewports(self) -> None:
        root = ET.parse(VIEW).getroot()
        self.assertEqual(root.attrib.get("stylesheet"), "css/process_tree_104.css")
        panels = {panel.attrib.get("id"): panel for panel in root.findall(".//panel")}
        self.assertIn("pstree_selected_panel", panels)
        self.assertIn("pstree_content_hunt_panel", panels)
        for panel_id in ("pstree_selected_panel", "pstree_content_hunt_panel"):
            self.assertRegex(panel_id, r"^[A-Za-z_][A-Za-z0-9_]*$")

        stylesheet = APP / "appserver/static/css/process_tree_104.css"
        self.assertTrue(stylesheet.is_file())
        css = stylesheet.read_text(encoding="utf-8")
        self.assertIn("#pstree_selected_panel .panel-body", css)
        self.assertIn("#pstree_content_hunt_panel .panel-body", css)
        self.assertIn("max-height: 520px", css)
        self.assertIn("overflow-y: auto", css)
        self.assertIn("overflow-x: auto", css)
        self.assertIn("overscroll-behavior: contain", css)

    def test_editor_asset_boots_as_a_classic_simple_xml_script(self) -> None:
        javascript = (
            APP / "appserver/static/js/process_tree_104.js"
        ).read_text(encoding="utf-8")

        self.assertIn("DOMContentLoaded", javascript)
        self.assertIn("root.require(", javascript)
        self.assertNotIn("define([", javascript)

    def test_optional_filter_editor_has_accessible_whole_cell_collapse(self) -> None:
        root = ET.parse(VIEW).getroot()
        shell = root.find(".//div[@id='process-tree-filter-shell']")
        toggle = root.find(".//button[@id='process-tree-toggle-spl']")
        body = root.find(".//div[@id='process-tree-filter-body']")
        self.assertIsNotNone(shell)
        self.assertIsNotNone(toggle)
        self.assertIsNotNone(body)
        if toggle is None:
            self.fail("collapse toggle is missing")
        self.assertEqual(toggle.attrib.get("type"), "button")
        self.assertEqual(toggle.attrib.get("aria-controls"), "process-tree-filter-body")
        self.assertEqual(toggle.attrib.get("aria-expanded"), "true")
        self.assertEqual((toggle.text or "").strip(), "Collapse")

    def test_relationship_searches_hardcode_safe_edge_limit(self) -> None:
        root = ET.parse(VIEW).getroot()
        queries = [
            " ".join((query.text or "").split())
            for query in root.findall(".//search/query")
        ]
        relationship_queries = [
            query
            for query in queries
            if query.startswith("index=$data_index|s$") and "head 80" in query
        ]

        self.assertEqual(len(relationship_queries), 3)
        self.assertNotIn("edge_limit", ET.tostring(root, encoding="unicode"))
        for query in relationship_queries:
            self.assertTrue(query.startswith("index=$data_index|s$ sourcetype=$data_sourcetype|s$"))
            self.assertIn("pt_parent_entity=$root_guid|s$", query)
            self.assertIn("pt_image=$process_filter|s$", query)
            self.assertIn("pt_parent_image=$process_filter|s$", query)
            self.assertIn("tonumber($min_count|s$)", query)
            self.assertIn("$node_mode|s$", query)
            segments = re.split(r"\s+\|\s+", query)
            head_commands = [
                segment
                for segment in segments
                if re.match(r"(?i)^head(?:\s|$)", segment)
            ]
            self.assertEqual(head_commands, ["head 80"])
            self.assertNotIn("index=*", query)
            self.assertNotIn("| map", query)

    def test_host_population_uses_exact_selected_process_scope(self) -> None:
        root = ET.parse(VIEW).getroot()
        host_input = root.find(".//input[@token='host']")

        if host_input is None:
            self.fail("host input is missing")
        query_element = host_input.find("./search/query")
        if query_element is None:
            self.fail("host population query is missing")
        query = " ".join((query_element.text or "").split())

        self.assertTrue(query.startswith("index=$data_index|s$"))
        self.assertNotIn("| tstats", query)
        self.assertIn("sourcetype=$data_sourcetype|s$", query)
        self.assertIn("source=$data_source|s$", query)
        self.assertIn("EventCode=$data_eventcode|s$", query)
        self.assertIn("| stats count by host", query)
        self.assertIn("| head 100", query)
        self.assertNotIn("index=*", query)

    def test_sysmon_macro_uses_verified_bots_source(self) -> None:
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        parser.read(APP / "default/macros.conf", encoding="utf-8")
        definition = parser["process_tree_sysmon_base"]["definition"]

        self.assertIn("index=botsv3", definition)
        self.assertIn("sourcetype=XmlWinEventLog", definition)
        self.assertIn(
            'source="WinEventLog:Microsoft-Windows-Sysmon/Operational"',
            definition,
        )
        self.assertIn("EventCode=1", definition)
        self.assertNotIn("index=*", definition)


if __name__ == "__main__":
    unittest.main()
