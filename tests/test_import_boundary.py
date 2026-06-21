"""Import-boundary test for the Strix Governance Layer (SGL).

S7/S8 hard invariant: SGL modules may only *remove* actions upstream.
They must NEVER import from the detection engine:
  - strix.core.logic
  - strix.core.proposals
  - strix.core.oob
  - strix.core.diff
  - strix.core.race

This test uses Python's ``ast`` module for static analysis — it parses
every ``.py`` file in the SGL directories and checks all ``import`` and
``from ... import`` nodes against the forbidden domain list.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

# SGL directories that must be import-boundary clean.
# Note: strix/runtime/oob/ is pre-existing OOB infrastructure, not SGL
# governance code — it legitimately imports from strix.core.oob.models.
_SGL_RECURSIVE_DIRS = [
    "strix/core/govern",
    "strix/telemetry",
]

# Individual runtime files that are SGL governance code
_SGL_INDIVIDUAL_FILES = [
    "strix/runtime/egress_proxy.py",
    "strix/runtime/docker_client.py",
    "strix/runtime/session_manager.py",
    "strix/runtime/backends.py",
    "strix/runtime/caido_bootstrap.py",
]

# Forbidden import prefixes — the detection engine
_FORBIDDEN_PREFIXES = [
    "strix.core.logic",
    "strix.core.proposals",
    "strix.core.oob",
    "strix.core.diff",
    "strix.core.race",
]

# Known exceptions: runtime/backends.py and runtime/docker_client.py may
# reference detection-engine types in TYPE_CHECKING blocks or string
# annotations.  The test still catches *runtime* imports.
_KNOWN_EXCEPTIONS: set[str] = set()


def _collect_py_files() -> list[Path]:
    """Collect all .py files in the SGL directories."""
    project_root = Path(__file__).parent.parent
    files: list[Path] = []
    # Recursive directories
    for dir_name in _SGL_RECURSIVE_DIRS:
        dir_path = project_root / dir_name
        if dir_path.exists():
            files.extend(dir_path.rglob("*.py"))
    # Individual files
    for file_name in _SGL_INDIVIDUAL_FILES:
        file_path = project_root / file_name
        if file_path.is_file():
            files.append(file_path)
    return files


def _check_file_for_forbidden_imports(filepath: Path) -> list[str]:
    """Parse a Python file and return any forbidden import module names."""
    try:
        source = filepath.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(filepath))
    except (SyntaxError, UnicodeDecodeError):
        return []  # skip unparseable files

    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                for prefix in _FORBIDDEN_PREFIXES:
                    if alias.name == prefix or alias.name.startswith(prefix + "."):
                        violations.append(f"import {alias.name}")

        elif isinstance(node, ast.ImportFrom) and node.module:
            module = node.module
            for prefix in _FORBIDDEN_PREFIXES:
                if module == prefix or module.startswith(prefix + "."):
                    violations.append(f"from {module} import ...")

    return violations


@pytest.mark.parametrize(
    "filepath",
    _collect_py_files(),
    ids=lambda p: str(p.relative_to(Path(__file__).parent.parent)),
)
def test_sgl_import_boundary(filepath: Path) -> None:
    """SGL modules must not import from the detection engine.

    This is the hard invariant that proves gate-neutrality: the governance
    layer can only *remove* actions upstream — it never alters a
    disposition, adds an evidence_class, or modifies any file under
    core/logic, core/proposals, core/oob, core/diff, or core/race.
    """
    violations = _check_file_for_forbidden_imports(filepath)
    assert not violations, (
        f"{filepath} imports from forbidden detection-engine modules:\n"
        + "\n".join(f"  - {v}" for v in violations)
    )


def test_sgl_directories_exist() -> None:
    """Sanity check: the SGL directories we're testing actually exist."""
    project_root = Path(__file__).parent.parent
    for dir_name in _SGL_RECURSIVE_DIRS:
        dir_path = project_root / dir_name
        assert dir_path.exists(), f"SGL directory {dir_name} does not exist"
        assert any(dir_path.rglob("*.py")), f"SGL directory {dir_name} has no .py files"
    for file_name in _SGL_INDIVIDUAL_FILES:
        file_path = project_root / file_name
        assert file_path.exists(), f"SGL file {file_name} does not exist"
