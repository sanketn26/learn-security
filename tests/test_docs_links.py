"""Static checks that docs do not point at files or commands that do not exist.

Internal links are resolved relative to the page, the way MkDocs does it.
Fenced shell blocks are not executed (that needs a running lab); instead the
make targets, repo paths, and attack-sim scenarios they mention must exist.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
WORK = DOCS / "capstone" / "work"
PAGES = sorted(
    p for p in DOCS.rglob("*.md") if WORK not in p.parents or p == WORK / "README.md"
)

FENCE_RE = re.compile(r"^```[^\n]*\n(.*?)^```", re.MULTILINE | re.DOTALL)
LINK_RE = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
EXTERNAL = ("http://", "https://", "mailto:", "tel:")


def _strip_fences(text: str) -> str:
    return FENCE_RE.sub("", text)


def _rel(page: Path) -> str:
    return str(page.relative_to(DOCS))


@pytest.mark.parametrize("page", PAGES, ids=_rel)
def test_internal_links_resolve(page: Path) -> None:
    text = _strip_fences(page.read_text(encoding="utf-8"))
    text = re.sub(r"`[^`\n]*`", "", text)
    broken = []
    for target in LINK_RE.findall(text):
        if target.startswith(EXTERNAL) or target.startswith("#"):
            continue
        path = target.split("#", 1)[0].split("?", 1)[0]
        if not path:
            continue
        resolved = (page.parent / path).resolve()
        if not (resolved.exists() or (resolved / "index.md").exists()):
            broken.append(target)
    assert not broken, f"broken links: {broken}"


def _make_targets() -> set[str]:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    targets: set[str] = set()
    for line in makefile.splitlines():
        if line.startswith(".PHONY:"):
            targets.update(line.split(":", 1)[1].split())
    targets.update(re.findall(r"^([A-Za-z][\w-]*):", makefile, re.MULTILINE))
    return targets


def _scenarios() -> set[str]:
    source = (ROOT / "labs" / "attack-sim" / "simulate.py").read_text(encoding="utf-8")
    block = re.search(r"SCENARIOS\s*=\s*\{(.*?)\n\}", source, re.DOTALL)
    assert block is not None
    return set(re.findall(r'"(\w+)":', block.group(1))) | {"all"}


def _shell_lines(page: Path) -> list[str]:
    text = page.read_text(encoding="utf-8")
    lines: list[str] = []
    for block in FENCE_RE.findall(text):
        for line in block.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                lines.append(line)
    return lines


# Created at runtime by the lab and gitignored, so absent from a clean checkout.
RUNTIME_DIRS = {"labs/data", "labs/logs", "labs/cases", "labs/evidence"}
COMMENT_RE = re.compile(r"\s+#.*$")

MAKE_RE = re.compile(r"(?:^|[\s;&|])make\s+([A-Za-z][\w-]*)")
PATH_RE = re.compile(r"(?<![\w/.-])(labs/[\w./-]+)")
SCENARIO_RE = re.compile(r"simulate\.py\s+--scenario\s+(\w+)")


@pytest.mark.parametrize("page", PAGES, ids=_rel)
def test_documented_commands_exist(page: Path) -> None:
    targets, scenarios = _make_targets(), _scenarios()
    problems = []
    for line in _shell_lines(page):
        line = COMMENT_RE.sub("", line)
        for target in MAKE_RE.findall(line):
            if target not in targets:
                problems.append(f"unknown make target {target!r} in: {line}")
        for name in SCENARIO_RE.findall(line):
            if name not in scenarios:
                problems.append(f"unknown scenario {name!r} in: {line}")
        for path in PATH_RE.findall(line):
            path = path.rstrip(".,;:)\\/")
            if path in RUNTIME_DIRS:
                continue
            if any(ch in path for ch in "*{<$"):
                continue
            if not (ROOT / path).exists():
                problems.append(f"missing path {path!r} in: {line}")
    assert not problems, "\n".join(problems)


def test_threat_model_cites_only_tests_that_exist():
    """A coverage claim that names a test must name a real one (prefix match for `_*`)."""
    import re as _re

    text = (DOCS / "agent-threat-model.md").read_text(encoding="utf-8")
    cited = set(_re.findall(r"`(test_[a-z_]+\*?)`", text)) | set(_re.findall(r"`(test_agent_[a-z_]+\.py)`", text))
    defined = ""
    for path in (ROOT / "tests").glob("test_*.py"):
        defined += path.read_text(encoding="utf-8")
    missing = []
    for name in cited:
        if name.endswith(".py"):
            if not (ROOT / "tests" / name).exists():
                missing.append(name)
        elif not _re.search(rf"def {_re.escape(name.rstrip('*'))}", defined):
            missing.append(name)
    assert cited and not missing, missing
