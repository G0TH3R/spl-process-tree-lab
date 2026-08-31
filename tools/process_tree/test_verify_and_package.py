from __future__ import annotations

from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

from tools.process_tree.verify_and_package import PACKAGE_MTIME, build_and_verify


class ProcessTreePackagingTests(unittest.TestCase):
    def test_verifier_rejects_generalized_selector_and_mapping_mutations(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source_app = root / "apps/spl_process_tree_lab"
        mutations = [
            (
                "<earliest>$time.earliest$</earliest>",
                "",
                "data_sourcetype selector",
            ),
            (
                '<condition value="custom">\n          <unset token="mapping_ready"/>',
                '<condition value="custom">',
                "custom schema",
            ),
            (
                '<condition value="sysmon">\n          <set token="pt_parent_image_field">ParentImage</set>',
                '<condition value="sysmon">\n          <set token="pt_parent_image_field">UnsafeField</set>',
                "sysmon schema mapping",
            ),
            (
                '<panel depends="$mapping_ready$">\n      <title>Process Events Over Time</title>',
                '<panel>\n      <title>Process Events Over Time</title>',
                "mapping readiness",
            ),
        ]
        for old, new, expected_error in mutations:
            with self.subTest(expected_error=expected_error), tempfile.TemporaryDirectory() as directory:
                temporary_root = Path(directory)
                temporary_app = temporary_root / "spl_process_tree_lab"
                shutil.copytree(source_app, temporary_app)
                view = temporary_app / "default/data/ui/views/process_tree.xml"
                body = view.read_text(encoding="utf-8")
                self.assertIn(old, body)
                view.write_text(body.replace(old, new, 1), encoding="utf-8")
                script = f"""
from pathlib import Path
from tools.process_tree import verify_and_package as verifier
verifier.ROOT = Path({str(temporary_root)!r})
verifier.APP = Path({str(temporary_app)!r})
verifier.PACKAGE = Path({str(temporary_root / 'package.tgz')!r})
verifier.REPORT = Path({str(temporary_root / 'report.json')!r})
verifier.build_and_verify()
"""
                result = subprocess.run(
                    [sys.executable, "-O", "-c", script],
                    cwd=root,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(expected_error, result.stderr.lower())

    def test_verifier_rejects_replaced_pstree_content_hunt(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source_app = root / "apps/spl_process_tree_lab"
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            temporary_app = temporary_root / "spl_process_tree_lab"
            shutil.copytree(source_app, temporary_app)
            view = temporary_app / "default/data/ui/views/process_tree.xml"
            body = view.read_text(encoding="utf-8")
            body = re.sub(
                r'\| where like\(lower\(mvjoin\(tree,"\\n"\)\).*?\n\| table tree',
                "| collect index=main\n| table tree",
                body,
                count=1,
                flags=re.DOTALL,
            )
            view.write_text(body, encoding="utf-8")
            script = f"""
from pathlib import Path
from tools.process_tree import verify_and_package as verifier
verifier.ROOT = Path({str(temporary_root)!r})
verifier.APP = Path({str(temporary_app)!r})
verifier.PACKAGE = Path({str(temporary_root / 'package.tgz')!r})
verifier.REPORT = Path({str(temporary_root / 'report.json')!r})
verifier.build_and_verify()
"""
            result = subprocess.run(
                [sys.executable, "-O", "-c", script],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("content hunt", result.stderr.lower())

    def test_verifier_rejects_replaced_selected_pid_pstree(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source_app = root / "apps/spl_process_tree_lab"
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            temporary_app = temporary_root / "spl_process_tree_lab"
            shutil.copytree(source_app, temporary_app)
            view = temporary_app / "default/data/ui/views/process_tree.xml"
            view.write_text(
                view.read_text(encoding="utf-8").replace(
                    "| pstree child=child parent=parent detail=detail spaces=50",
                    "| collect index=main",
                    1,
                ),
                encoding="utf-8",
            )
            script = f"""
from pathlib import Path
from tools.process_tree import verify_and_package as verifier
verifier.ROOT = Path({str(temporary_root)!r})
verifier.APP = Path({str(temporary_app)!r})
verifier.PACKAGE = Path({str(temporary_root / 'package.tgz')!r})
verifier.REPORT = Path({str(temporary_root / 'report.json')!r})
verifier.build_and_verify()
"""
            result = subprocess.run(
                [sys.executable, "-O", "-c", script],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("selected pid process tree", result.stderr.lower())

    def test_verifier_rejects_replaced_process_events_timeline(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source_app = root / "apps/spl_process_tree_lab"
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            temporary_app = temporary_root / "spl_process_tree_lab"
            shutil.copytree(source_app, temporary_app)
            view = temporary_app / "default/data/ui/views/process_tree.xml"
            view.write_text(
                view.read_text(encoding="utf-8").replace(
                    "| timechart span=1h cont=false count as events by child_name limit=10 useother=true",
                    "| collect index=main",
                    1,
                ),
                encoding="utf-8",
            )
            script = f"""
from pathlib import Path
from tools.process_tree import verify_and_package as verifier
verifier.ROOT = Path({str(temporary_root)!r})
verifier.APP = Path({str(temporary_app)!r})
verifier.PACKAGE = Path({str(temporary_root / 'package.tgz')!r})
verifier.REPORT = Path({str(temporary_root / 'report.json')!r})
verifier.build_and_verify()
"""
            result = subprocess.run(
                [sys.executable, "-O", "-c", script],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("events over time", result.stderr.lower())

    def test_verifier_rejects_disabled_editor_guard(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source_app = root / "apps/spl_process_tree_lab"
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            temporary_app = temporary_root / "spl_process_tree_lab"
            shutil.copytree(source_app, temporary_app)
            editor = temporary_app / "appserver/static/js/process_tree_104.js"
            editor.write_text(
                editor.read_text(encoding="utf-8").replace(
                    "if (FORBIDDEN_COMMANDS.has(command))", "if (false)", 1
                ),
                encoding="utf-8",
            )
            script = f"""
from pathlib import Path
from tools.process_tree import verify_and_package as verifier
verifier.ROOT = Path({str(temporary_root)!r})
verifier.APP = Path({str(temporary_app)!r})
verifier.PACKAGE = Path({str(temporary_root / 'package.tgz')!r})
verifier.REPORT = Path({str(temporary_root / 'report.json')!r})
verifier.build_and_verify()
"""
            result = subprocess.run(
                [sys.executable, "-O", "-c", script],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("editor guard", result.stderr.lower())

    def test_verifier_rejects_structured_credentials_and_windows_events(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source_app = root / "apps/spl_process_tree_lab"
        payloads = {
            "json_token": '{"token":"0123456789abcdef0123456789abcdef"}',
            "json_event": '{"EventID":"1","ComputerName":"BSTOLL-L"}',
            "xml_event_id_attributes": (
                '<Event><System><EventID Qualifiers="0">1</EventID></System></Event>'
            ),
            "multiline_key_value": (
                "ComputerName=BSTOLL-L\nEventCode=1\nImage=C:\\Windows\\cmd.exe"
            ),
        }
        for label, payload in payloads.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                temporary_root = Path(directory)
                temporary_app = temporary_root / "spl_process_tree_lab"
                shutil.copytree(source_app, temporary_app)
                readme = temporary_app / "README.md"
                readme.write_text(
                    readme.read_text(encoding="utf-8") + "\n" + payload + "\n",
                    encoding="utf-8",
                )
                script = f"""
from pathlib import Path
from tools.process_tree import verify_and_package as verifier
verifier.ROOT = Path({str(temporary_root)!r})
verifier.APP = Path({str(temporary_app)!r})
verifier.PACKAGE = Path({str(temporary_root / 'package.tgz')!r})
verifier.REPORT = Path({str(temporary_root / 'report.json')!r})
verifier.build_and_verify()
"""
                result = subprocess.run(
                    [sys.executable, "-O", "-c", script],
                    cwd=root,
                    capture_output=True,
                    text=True,
                    check=False,
                )

            self.assertNotEqual(
                result.returncode, 0, label + ": " + result.stdout + result.stderr
            )

    def test_verifier_rejects_package_output_symlink_without_overwrite(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source_app = root / "apps/spl_process_tree_lab"
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            temporary_app = temporary_root / "spl_process_tree_lab"
            shutil.copytree(source_app, temporary_app)
            target = temporary_root / "target.txt"
            target.write_text("sentinel\n", encoding="utf-8")
            package = temporary_root / "package.tgz"
            package.symlink_to(target)
            script = f"""
from pathlib import Path
from tools.process_tree import verify_and_package as verifier
verifier.ROOT = Path({str(temporary_root)!r})
verifier.APP = Path({str(temporary_app)!r})
verifier.PACKAGE = Path({str(package)!r})
verifier.REPORT = Path({str(temporary_root / 'report.json')!r})
verifier.build_and_verify()
"""
            result = subprocess.run(
                [sys.executable, "-O", "-c", script],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(target.read_text(encoding="utf-8"), "sentinel\n")

    def test_verifier_rejects_required_file_symlink(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source_app = root / "apps/spl_process_tree_lab"
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            temporary_app = temporary_root / "spl_process_tree_lab"
            shutil.copytree(source_app, temporary_app)
            readme = temporary_app / "README.md"
            readme.unlink()
            readme.symlink_to("/etc/hosts")
            script = f"""
from pathlib import Path
from tools.process_tree import verify_and_package as verifier
verifier.ROOT = Path({str(temporary_root)!r})
verifier.APP = Path({str(temporary_app)!r})
verifier.PACKAGE = Path({str(temporary_root / 'package.tgz')!r})
verifier.REPORT = Path({str(temporary_root / 'report.json')!r})
verifier.build_and_verify()
"""
            result = subprocess.run(
                [sys.executable, "-O", "-c", script],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("regular file", result.stderr)

    def test_verifier_rejects_generic_password_assignment(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source_app = root / "apps/spl_process_tree_lab"
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            temporary_app = temporary_root / "spl_process_tree_lab"
            shutil.copytree(source_app, temporary_app)
            readme = temporary_app / "README.md"
            readme.write_text(
                readme.read_text(encoding="utf-8")
                + "\npassword = example-hardcoded-value\n",
                encoding="utf-8",
            )
            script = f"""
from pathlib import Path
from tools.process_tree import verify_and_package as verifier
verifier.ROOT = Path({str(temporary_root)!r})
verifier.APP = Path({str(temporary_app)!r})
verifier.PACKAGE = Path({str(temporary_root / 'package.tgz')!r})
verifier.REPORT = Path({str(temporary_root / 'report.json')!r})
verifier.build_and_verify()
"""
            result = subprocess.run(
                [sys.executable, "-O", "-c", script],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("credential", result.stderr)

    def test_verifier_rejects_generic_token_assignment(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source_app = root / "apps/spl_process_tree_lab"
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            temporary_app = temporary_root / "spl_process_tree_lab"
            shutil.copytree(source_app, temporary_app)
            readme = temporary_app / "README.md"
            readme.write_text(
                readme.read_text(encoding="utf-8")
                + "\ntoken = 0123456789abcdef0123456789abcdef\n",
                encoding="utf-8",
            )
            script = f"""
from pathlib import Path
from tools.process_tree import verify_and_package as verifier
verifier.ROOT = Path({str(temporary_root)!r})
verifier.APP = Path({str(temporary_app)!r})
verifier.PACKAGE = Path({str(temporary_root / 'package.tgz')!r})
verifier.REPORT = Path({str(temporary_root / 'report.json')!r})
verifier.build_and_verify()
"""
            result = subprocess.run(
                [sys.executable, "-O", "-c", script],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("credential", result.stderr)

    def test_verifier_rejects_representative_raw_event_line(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source_app = root / "apps/spl_process_tree_lab"
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            temporary_app = temporary_root / "spl_process_tree_lab"
            shutil.copytree(source_app, temporary_app)
            readme = temporary_app / "README.md"
            readme.write_text(
                readme.read_text(encoding="utf-8")
                + "\n2020-01-01 12:34:56 ComputerName=BSTOLL-L EventCode=1 Image=cmd.exe\n",
                encoding="utf-8",
            )
            script = f"""
from pathlib import Path
from tools.process_tree import verify_and_package as verifier
verifier.ROOT = Path({str(temporary_root)!r})
verifier.APP = Path({str(temporary_app)!r})
verifier.PACKAGE = Path({str(temporary_root / 'package.tgz')!r})
verifier.REPORT = Path({str(temporary_root / 'report.json')!r})
verifier.build_and_verify()
"""
            result = subprocess.run(
                [sys.executable, "-O", "-c", script],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("raw event", result.stderr)

    def test_verifier_rejects_representative_sysmon_xml_event(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source_app = root / "apps/spl_process_tree_lab"
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            temporary_app = temporary_root / "spl_process_tree_lab"
            shutil.copytree(source_app, temporary_app)
            readme = temporary_app / "README.md"
            readme.write_text(
                readme.read_text(encoding="utf-8")
                + "\n<Event><System><EventID>1</EventID></System>"
                + "<EventData><Data Name=\"Image\">cmd.exe</Data></EventData></Event>\n",
                encoding="utf-8",
            )
            script = f"""
from pathlib import Path
from tools.process_tree import verify_and_package as verifier
verifier.ROOT = Path({str(temporary_root)!r})
verifier.APP = Path({str(temporary_app)!r})
verifier.PACKAGE = Path({str(temporary_root / 'package.tgz')!r})
verifier.REPORT = Path({str(temporary_root / 'report.json')!r})
verifier.build_and_verify()
"""
            result = subprocess.run(
                [sys.executable, "-O", "-c", script],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("raw event", result.stderr)

    def test_verifier_rejects_head_800_as_relationship_limit(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source_app = root / "apps/spl_process_tree_lab"
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            temporary_app = temporary_root / "spl_process_tree_lab"
            shutil.copytree(source_app, temporary_app)
            view = temporary_app / "default/data/ui/views/process_tree.xml"
            view.write_text(
                view.read_text(encoding="utf-8").replace("| head 80", "| head 800", 1),
                encoding="utf-8",
            )
            script = f"""
from pathlib import Path
from tools.process_tree import verify_and_package as verifier
verifier.ROOT = Path({str(temporary_root)!r})
verifier.APP = Path({str(temporary_app)!r})
verifier.PACKAGE = Path({str(temporary_root / 'package.tgz')!r})
verifier.REPORT = Path({str(temporary_root / 'report.json')!r})
verifier.build_and_verify()
"""
            result = subprocess.run(
                [sys.executable, "-O", "-c", script],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("head 80", result.stderr)

    def test_verifier_rejects_swapped_visualization_bindings(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source_app = root / "apps/spl_process_tree_lab"
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            temporary_app = temporary_root / "spl_process_tree_lab"
            shutil.copytree(source_app, temporary_app)
            view = temporary_app / "default/data/ui/views/process_tree.xml"
            body = view.read_text(encoding="utf-8")
            body = body.replace(
                "sankey_diagram_app.sankey_diagram", "temporary_viz_type", 1
            )
            body = body.replace(
                "force_directed_viz.force_directed",
                "sankey_diagram_app.sankey_diagram",
                1,
            )
            body = body.replace(
                "temporary_viz_type", "force_directed_viz.force_directed", 1
            )
            view.write_text(body, encoding="utf-8")
            script = f"""
from pathlib import Path
from tools.process_tree import verify_and_package as verifier
verifier.ROOT = Path({str(temporary_root)!r})
verifier.APP = Path({str(temporary_app)!r})
verifier.PACKAGE = Path({str(temporary_root / 'package.tgz')!r})
verifier.REPORT = Path({str(temporary_root / 'report.json')!r})
verifier.build_and_verify()
"""
            result = subprocess.run(
                [sys.executable, "-O", "-c", script],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("visualization", result.stderr)

    def test_package_normalizes_and_validates_regular_file_metadata(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source_app = root / "apps/spl_process_tree_lab"
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            temporary_app = temporary_root / "spl_process_tree_lab"
            shutil.copytree(source_app, temporary_app)
            (temporary_app / "README.md").chmod(0o755)
            package = temporary_root / "package.tgz"
            script = f"""
from pathlib import Path
from tools.process_tree import verify_and_package as verifier
verifier.ROOT = Path({str(temporary_root)!r})
verifier.APP = Path({str(temporary_app)!r})
verifier.PACKAGE = Path({str(package)!r})
verifier.REPORT = Path({str(temporary_root / 'report.json')!r})
verifier.build_and_verify()
"""
            result = subprocess.run(
                [sys.executable, "-O", "-c", script],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            with tarfile.open(package, "r:gz") as archive:
                members = archive.getmembers()

        expected_names = {
            f"spl_process_tree_lab/{relative}"
            for relative in (
                "appserver/static/css/process_tree_104.css",
                "appserver/static/js/process_tree_104.js",
                "default/app.conf",
                "default/macros.conf",
                "default/data/ui/nav/default.xml",
                "default/data/ui/views/process_tree.xml",
                "metadata/default.meta",
                "README.md",
            )
        }
        self.assertEqual({member.name for member in members}, expected_names)
        self.assertTrue(all(member.isfile() for member in members))
        self.assertTrue(all(member.linkname == "" for member in members))
        self.assertTrue(all(member.mtime == PACKAGE_MTIME for member in members))
        self.assertTrue(all(member.mode == 0o644 for member in members))

    def test_identity_validation_remains_fail_closed_under_python_optimization(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source_app = root / "apps/spl_process_tree_lab"
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            temporary_app = temporary_root / "spl_process_tree_lab"
            shutil.copytree(source_app, temporary_app)
            app_conf = temporary_app / "default/app.conf"
            app_conf.write_text(
                app_conf.read_text(encoding="utf-8").replace(
                    "name = spl_process_tree_lab", "name = injected_app", 1
                ),
                encoding="utf-8",
            )
            script = f"""
from pathlib import Path
from tools.process_tree import verify_and_package as verifier
verifier.ROOT = Path({str(temporary_root)!r})
verifier.APP = Path({str(temporary_app)!r})
verifier.PACKAGE = Path({str(temporary_root / 'package.tgz')!r})
verifier.REPORT = Path({str(temporary_root / 'report.json')!r})
verifier.build_and_verify()
"""
            result = subprocess.run(
                [sys.executable, "-O", "-c", script],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("app id name", result.stderr)

    def test_host_scope_validation_remains_fail_closed_under_python_optimization(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source_app = root / "apps/spl_process_tree_lab"
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            temporary_app = temporary_root / "spl_process_tree_lab"
            shutil.copytree(source_app, temporary_app)
            view = temporary_app / "default/data/ui/views/process_tree.xml"
            view.write_text(
                view.read_text(encoding="utf-8").replace(
                    "EventCode=$data_eventcode|s$ | stats count by host",
                    "EventCode=3 | stats count by host",
                    1,
                ),
                encoding="utf-8",
            )
            script = f"""
from pathlib import Path
from tools.process_tree import verify_and_package as verifier
verifier.ROOT = Path({str(temporary_root)!r})
verifier.APP = Path({str(temporary_app)!r})
verifier.PACKAGE = Path({str(temporary_root / 'package.tgz')!r})
verifier.REPORT = Path({str(temporary_root / 'report.json')!r})
verifier.build_and_verify()
"""
            result = subprocess.run(
                [sys.executable, "-O", "-c", script],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("host population", result.stderr)

    def test_verifier_rejects_broadened_macro_scope(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source_app = root / "apps/spl_process_tree_lab"
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            temporary_app = temporary_root / "spl_process_tree_lab"
            shutil.copytree(source_app, temporary_app)
            macros = temporary_app / "default/macros.conf"
            macros.write_text(
                macros.read_text(encoding="utf-8").replace(
                    "index=botsv3", "index=botsv3 OR index=other", 1
                ),
                encoding="utf-8",
            )
            script = f"""
from pathlib import Path
from tools.process_tree import verify_and_package as verifier
verifier.ROOT = Path({str(temporary_root)!r})
verifier.APP = Path({str(temporary_app)!r})
verifier.PACKAGE = Path({str(temporary_root / 'package.tgz')!r})
verifier.REPORT = Path({str(temporary_root / 'report.json')!r})
verifier.build_and_verify()
"""
            result = subprocess.run(
                [sys.executable, "-O", "-c", script],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("macro", result.stderr.lower())

    def test_verifier_rejects_broadened_relationship_host_scope(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source_app = root / "apps/spl_process_tree_lab"
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            temporary_app = temporary_root / "spl_process_tree_lab"
            shutil.copytree(source_app, temporary_app)
            view = temporary_app / "default/data/ui/views/process_tree.xml"
            body = view.read_text(encoding="utf-8")
            marker = "| search host=$host|s$ pt_parent_entity=$root_guid|s$"
            view.write_text(
                body.replace(marker, "| search host=$host|s$ OR host=* pt_parent_entity=$root_guid|s$", 1),
                encoding="utf-8",
            )
            script = f"""
from pathlib import Path
from tools.process_tree import verify_and_package as verifier
verifier.ROOT = Path({str(temporary_root)!r})
verifier.APP = Path({str(temporary_app)!r})
verifier.PACKAGE = Path({str(temporary_root / 'package.tgz')!r})
verifier.REPORT = Path({str(temporary_root / 'report.json')!r})
verifier.build_and_verify()
"""
            result = subprocess.run(
                [sys.executable, "-O", "-c", script],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("events over time", result.stderr.lower())

    def test_verifier_rejects_missing_relationship_time_bound(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source_app = root / "apps/spl_process_tree_lab"
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            temporary_app = temporary_root / "spl_process_tree_lab"
            shutil.copytree(source_app, temporary_app)
            view = temporary_app / "default/data/ui/views/process_tree.xml"
            body = view.read_text(encoding="utf-8")
            panel_start = body.index("<title>Process Events Over Time</title>")
            earliest = "<earliest>$time.earliest$</earliest>"
            earliest_start = body.index(earliest, panel_start)
            view.write_text(
                body[:earliest_start] + body[earliest_start:].replace(earliest, "", 1),
                encoding="utf-8",
            )
            script = f"""
from pathlib import Path
from tools.process_tree import verify_and_package as verifier
verifier.ROOT = Path({str(temporary_root)!r})
verifier.APP = Path({str(temporary_app)!r})
verifier.PACKAGE = Path({str(temporary_root / 'package.tgz')!r})
verifier.REPORT = Path({str(temporary_root / 'report.json')!r})
verifier.build_and_verify()
"""
            result = subprocess.run(
                [sys.executable, "-O", "-c", script],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("time", result.stderr.lower())

    def test_verifier_rejects_uppercase_map_command(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source_app = root / "apps/spl_process_tree_lab"
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            temporary_app = temporary_root / "spl_process_tree_lab"
            shutil.copytree(source_app, temporary_app)
            view = temporary_app / "default/data/ui/views/process_tree.xml"
            view.write_text(
                view.read_text(encoding="utf-8").replace(
                    "| head 80", '| MAP search="| makeresults"\n| head 80', 1
                ),
                encoding="utf-8",
            )
            script = f"""
from pathlib import Path
from tools.process_tree import verify_and_package as verifier
verifier.ROOT = Path({str(temporary_root)!r})
verifier.APP = Path({str(temporary_app)!r})
verifier.PACKAGE = Path({str(temporary_root / 'package.tgz')!r})
verifier.REPORT = Path({str(temporary_root / 'report.json')!r})
verifier.build_and_verify()
"""
            result = subprocess.run(
                [sys.executable, "-O", "-c", script],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("forbidden", result.stderr.lower())

    def test_verifier_rejects_unapproved_additional_dashboard_search(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source_app = root / "apps/spl_process_tree_lab"
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            temporary_app = temporary_root / "spl_process_tree_lab"
            shutil.copytree(source_app, temporary_app)
            view = temporary_app / "default/data/ui/views/process_tree.xml"
            view.write_text(
                view.read_text(encoding="utf-8").replace(
                    "</form>",
                    "<search><query>index=* | head 1</query>"
                    "<earliest>0</earliest><latest>now</latest></search></form>",
                    1,
                ),
                encoding="utf-8",
            )
            script = f"""
from pathlib import Path
from tools.process_tree import verify_and_package as verifier
verifier.ROOT = Path({str(temporary_root)!r})
verifier.APP = Path({str(temporary_app)!r})
verifier.PACKAGE = Path({str(temporary_root / 'package.tgz')!r})
verifier.REPORT = Path({str(temporary_root / 'report.json')!r})
verifier.build_and_verify()
"""
            result = subprocess.run(
                [sys.executable, "-O", "-c", script],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("search inventory", result.stderr.lower())

    def test_verifier_rejects_side_effecting_process_edges_substitution(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source_app = root / "apps/spl_process_tree_lab"
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            temporary_app = temporary_root / "spl_process_tree_lab"
            shutil.copytree(source_app, temporary_app)
            view = temporary_app / "default/data/ui/views/process_tree.xml"
            view.write_text(
                view.read_text(encoding="utf-8").replace(
                    "| head 80</query>",
                    "| collect index=main\n| head 80</query>",
                    1,
                ),
                encoding="utf-8",
            )
            script = f"""
from pathlib import Path
from tools.process_tree import verify_and_package as verifier
verifier.ROOT = Path({str(temporary_root)!r})
verifier.APP = Path({str(temporary_app)!r})
verifier.PACKAGE = Path({str(temporary_root / 'package.tgz')!r})
verifier.REPORT = Path({str(temporary_root / 'report.json')!r})
verifier.build_and_verify()
"""
            result = subprocess.run(
                [sys.executable, "-O", "-c", script],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("forbidden", result.stderr.lower())

    def test_verifier_rejects_an_extra_app_file(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source_app = root / "apps/spl_process_tree_lab"
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            temporary_app = temporary_root / "spl_process_tree_lab"
            shutil.copytree(source_app, temporary_app)
            (temporary_app / "unexpected.conf").write_text("[unexpected]\n", encoding="utf-8")
            script = f"""
from pathlib import Path
from tools.process_tree import verify_and_package as verifier
verifier.ROOT = Path({str(temporary_root)!r})
verifier.APP = Path({str(temporary_app)!r})
verifier.PACKAGE = Path({str(temporary_root / 'package.tgz')!r})
verifier.REPORT = Path({str(temporary_root / 'report.json')!r})
verifier.build_and_verify()
"""
            result = subprocess.run(
                [sys.executable, "-c", script],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("unexpected app files", result.stderr)

    def test_two_builds_are_byte_identical(self) -> None:
        root = Path(__file__).resolve().parents[2]
        first_report = build_and_verify()
        package = root / first_report["package"]
        first_bytes = package.read_bytes()

        second_report = build_and_verify()
        second_bytes = package.read_bytes()

        self.assertEqual(first_bytes, second_bytes)
        self.assertEqual(first_report["sha256"], second_report["sha256"])
        self.assertEqual(
            second_report["checks"]["package"]["reproducible"], "passed"
        )

    def test_builds_deterministic_validated_app_package(self) -> None:
        report = build_and_verify()
        root = Path(__file__).resolve().parents[2]
        package = root / report["package"]

        self.assertEqual(report["app_id"], "spl_process_tree_lab")
        self.assertEqual(report["version"], "1.0.4")
        self.assertEqual(report["status"], "local-package-validated-not-installed")
        self.assertEqual(report["checks"]["credential_scan"], "passed")
        self.assertEqual(report["checks"]["raw_event_scan"], "passed")
        self.assertNotIn("secret_scan", report["checks"])
        self.assertEqual(report["checks"]["spl_contracts"], "passed")
        self.assertRegex(report["sha256"], r"^[0-9a-f]{64}$")
        self.assertTrue(package.is_file())

        with tarfile.open(package, "r:gz") as archive:
            members = archive.getmembers()

        self.assertTrue(members)
        self.assertTrue(
            all(member.name.startswith("spl_process_tree_lab/") for member in members)
        )
        self.assertTrue(all(member.mtime == PACKAGE_MTIME for member in members))
        self.assertFalse(any("._" in member.name for member in members))
        self.assertFalse(any("test" in member.name.lower() for member in members))


if __name__ == "__main__":
    unittest.main()
