"""Docs front matter must be something MkDocs actually strips.

MkDocs removes a leading YAML block only when its delimiter pattern matches
and the block loads as a mapping. Anything else, such as an unquoted
description containing ": " or an empty block, is silently rendered as
visible page text and the meta description is dropped, so
`mkdocs build --strict` does not catch it. These checks mirror
mkdocs.utils.meta.get_data without requiring MkDocs in the lab-tests job.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

DOCS = Path(__file__).resolve().parent.parent / "docs"
PAGES = sorted(DOCS.rglob("*.md"))

# Same pattern as mkdocs.utils.meta.YAML_RE (MkDocs 1.6).
YAML_RE = re.compile(r"^-{3}[ \t]*\n(.*?\n)(?:\.{3}|-{3})[ \t]*\n", re.UNICODE | re.DOTALL)


def front_matter_problem(text: str) -> str | None:
    """Return why MkDocs would render this front matter as page text, or None."""
    if not text.startswith("---"):
        if re.search(r"^description:", text[:500], re.MULTILINE):
            return "front matter must start on line 1"
        return None
    match = YAML_RE.match(text)
    if match is None:
        return "front matter delimiters not recognised by MkDocs"
    try:
        meta = yaml.safe_load(match.group(1))
    except yaml.YAMLError as exc:
        return f"invalid YAML: {str(exc).splitlines()[0]}"
    if not isinstance(meta, dict):
        return "front matter must be a non-empty YAML mapping"
    if "description" in meta and not (
        isinstance(meta["description"], str) and meta["description"].strip()
    ):
        return "description must be a non-empty string"
    return None


@pytest.mark.parametrize(
    ("text", "leaks"),
    [
        ("---\ndescription: Plain text.\n---\n# Page\n", False),
        ('---\ndescription: "Quoted: fine."\n---\n# Page\n', False),
        ("---\ndescription: ok\n...\n# Page\n", False),
        ("--- \ndescription: ok\n---  \n# Page\n", False),
        ("# Page without front matter\n", False),
        ("---\ndescription: Unquoted: breaks YAML.\n---\n# Page\n", True),
        ("---\n---\n# Page\n", True),
        ("---\n\n---\n# Page\n", True),
        ("---\ndescription: ok\n----\n# Page\n", True),
        ("---\ndescription: ok\n# Never closed\n", True),
        ("\n---\ndescription: ok\n---\n", True),
    ],
)
def test_checker_matches_mkdocs(text: str, leaks: bool) -> None:
    assert (front_matter_problem(text) is not None) is leaks


@pytest.mark.parametrize("page", PAGES, ids=lambda p: str(p.relative_to(DOCS)))
def test_front_matter_parses(page: Path) -> None:
    problem = front_matter_problem(page.read_text(encoding="utf-8"))
    assert problem is None, problem
