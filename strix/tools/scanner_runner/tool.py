"""``scanner_runner`` — run a Group 1 scanner and return structured output."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
import subprocess  # nosec B404
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)


class ScannerRunnerError(Exception):
    """Raised when a scanner cannot be executed or fails structurally."""


class ScannerNotFoundError(ScannerRunnerError):
    """Raised when the requested scanner binary is not on PATH."""


class ScannerTimeoutError(ScannerRunnerError):
    """Raised when the scanner subprocess exceeds its timeout."""


_SUPPORTED_TOOLS: set[str] = {"gitleaks", "trufflehog", "trivy"}
_SHELL_METACHARS = re.compile(r"[;&|`$<>\n\r]")


def _which(tool: str) -> str:
    path = shutil.which(tool)
    if path is None:
        raise ScannerNotFoundError(f"Scanner not found on PATH: {tool}")
    return path


def _get_version(tool: str) -> str:
    """Best-effort version extraction from ``--version``."""
    try:
        result = subprocess.run(  # noqa: S603  # nosec B603
            [tool, "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    output = (result.stdout + result.stderr).strip()
    if not output:
        return "unknown"
    return output.splitlines()[0].strip()


def _validate_extra_args(extra_args: list[str] | None) -> list[str]:
    """Validate extra CLI arguments to prevent shell-injection via the tool."""
    if extra_args is None:
        return []
    for arg in extra_args:
        if not arg:
            raise ScannerRunnerError("extra_args must be non-empty strings")
        if _SHELL_METACHARS.search(arg):
            raise ScannerRunnerError(f"Unsafe character in extra_args: {arg!r}")
    return extra_args


def _run_scanner(tool: str, target: str, extra_args: list[str] | None) -> tuple[str, int]:
    """Execute the scanner and return merged stdout/stderr plus return code."""
    cmd = [tool, *_validate_extra_args(extra_args), target]
    try:
        result = subprocess.run(  # noqa: S603  # nosec B603
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
    except subprocess.TimeoutExpired as exc:
        raise ScannerTimeoutError(f"Scanner {tool} timed out after {exc.timeout}s") from exc
    except OSError as exc:
        raise ScannerRunnerError(f"Failed to execute scanner {tool}: {exc}") from exc
    return result.stdout + result.stderr, result.returncode


def _parse_gitleaks(raw_output: str) -> list[dict[str, Any]]:
    """Parse newline-delimited JSON output from gitleaks."""
    findings: list[dict[str, Any]] = []
    for raw_line in raw_output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        findings.append(
            {
                "rule_id": obj.get("RuleID", "unknown"),
                "description": obj.get("Description", ""),
                "file": obj.get("File", ""),
                "start_line": obj.get("StartLine", 0),
                "end_line": obj.get("EndLine", 0),
                "fingerprint": obj.get("Fingerprint", ""),
            }
        )
    return sorted(findings, key=lambda f: (f["file"], f["start_line"], f["rule_id"]))


def _parse_trufflehog(raw_output: str) -> list[dict[str, Any]]:
    """Parse newline-delimited JSON output from trufflehog."""
    findings: list[dict[str, Any]] = []
    for raw_line in raw_output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        source = obj.get("SourceMetadata", {}) or {}
        file_info: dict[str, Any] = {}
        if isinstance(source, dict):
            data = source.get("Data", {}) or {}
            if isinstance(data, dict):
                fs = data.get("Filesystem", {}) or {}
                if isinstance(fs, dict):
                    file_info = fs
        findings.append(
            {
                "detector_name": obj.get("DetectorName", "unknown"),
                "verified": bool(obj.get("Verified", False)),
                "raw": obj.get("Raw", ""),
                "file": file_info.get("file", ""),
                "line": file_info.get("line", 0),
            }
        )
    return sorted(findings, key=lambda f: (f["file"], f["line"], f["detector_name"]))


def _parse_trivy(raw_output: str) -> list[dict[str, Any]]:
    """Parse JSON output from trivy filesystem/image scans."""
    findings: list[dict[str, Any]] = []
    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError:
        return findings
    if not isinstance(data, dict):
        return findings
    for result in data.get("Results", []):
        if not isinstance(result, dict):
            continue
        for vuln in result.get("Vulnerabilities", []):
            if not isinstance(vuln, dict):
                continue
            findings.append(
                {
                    "target": result.get("Target", ""),
                    "vulnerability_id": vuln.get("VulnerabilityID", "unknown"),
                    "title": vuln.get("Title", ""),
                    "severity": vuln.get("Severity", "unknown"),
                    "pkg_name": vuln.get("PkgName", ""),
                    "installed_version": vuln.get("InstalledVersion", ""),
                    "fixed_version": vuln.get("FixedVersion", ""),
                }
            )
    return sorted(
        findings,
        key=lambda f: (f["target"], f["vulnerability_id"], f["severity"]),
    )


def _parse_findings(tool: str, raw_output: str) -> list[dict[str, Any]]:
    """Dispatch to the correct parser for the tool."""
    if tool == "gitleaks":
        return _parse_gitleaks(raw_output)
    if tool == "trufflehog":
        return _parse_trufflehog(raw_output)
    if tool == "trivy":
        return _parse_trivy(raw_output)
    return []


def _sanitize_filename(value: str) -> str:
    """Sanitize a target string for safe use in a filename."""
    return "".join(c if c.isalnum() or c in ("-", "_", ".") else "_" for c in value)[:128]


def run_scanner(
    tool: str,
    target: str,
    extra_args: list[str] | None = None,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    """Run a Group 1 scanner and return a structured, deterministic result.

    Args:
        tool: Scanner name. Must be one of ``gitleaks``, ``trufflehog``, ``trivy``.
        target: Path, URL, or image reference to scan.
        extra_args: Additional CLI arguments passed to the scanner.
        output_dir: Optional directory where raw output is persisted. If omitted,
            ``raw_output_ref`` is ``"memory"``.

    Returns:
        Dict with keys ``tool``, ``version``, ``target``, ``returncode``,
        ``findings`` (stably sorted), and ``raw_output_ref``.

    Raises:
        ScannerNotFoundError: If the scanner binary is not on PATH.
        ScannerTimeoutError: If the scanner subprocess times out.
        ScannerRunnerError: For other execution failures.
    """
    if tool not in _SUPPORTED_TOOLS:
        raise ScannerNotFoundError(
            f"Unsupported scanner: {tool}. Supported: {sorted(_SUPPORTED_TOOLS)}"
        )
    _validate_extra_args(extra_args)
    _which(tool)
    version = _get_version(tool)
    raw_output, returncode = _run_scanner(tool, target, extra_args)
    findings = _parse_findings(tool, raw_output)

    raw_output_ref = "memory"
    if output_dir is not None:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        ref_path = out / f"{tool}_{_sanitize_filename(target)}.txt"
        ref_path.write_text(raw_output, encoding="utf-8")
        raw_output_ref = str(ref_path)

    return {
        "tool": tool,
        "version": version,
        "target": target,
        "returncode": returncode,
        "findings": findings,
        "raw_output_ref": raw_output_ref,
    }


@function_tool(timeout=300)
async def scanner_runner(
    ctx: RunContextWrapper,
    tool: str,
    target: str,
    extra_args: list[str] | None = None,
) -> str:
    """Run a Group 1 scanner (gitleaks, trufflehog, or trivy) and return structured findings.

    The result is deterministic: findings are sorted by file/line/ID, and the
    raw output is captured by reference. If the scanner is not installed, a
    structured error object is returned instead of raising into the agent loop.

    Args:
        tool: One of ``gitleaks``, ``trufflehog``, ``trivy``.
        target: Path, URL, or image reference to scan.
        extra_args: Optional list of extra CLI arguments.
    """
    try:
        result = await asyncio.to_thread(run_scanner, tool, target, extra_args)
    except ScannerRunnerError as exc:
        logger.warning("scanner_runner failed: %s", exc)
        result = {
            "tool": tool,
            "version": "unknown",
            "target": target,
            "returncode": -1,
            "findings": [],
            "raw_output_ref": "memory",
            "error": str(exc),
        }
    return json.dumps(result, ensure_ascii=False, default=str, sort_keys=True)
