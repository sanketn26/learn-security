"""Docs front matter must parse as YAML.

MkDocs silently renders unparseable front matter (for example an unquoted
description containing ": ") as visible page text and drops the meta
description, so `mkdocs build --strict` does not catch it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

DOCS = Path(__file__).resolve().parent.parent / "docs"
PAGES = sorted(DOCS.rglob("*.md"))


@pytest.mark.parametrize("page", PAGES, ids=lambda p: str(p.relative_to(DOCS)))
def test_front_matter_parses(page: Path) -> None:
    text = page.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        assert "\ndescription:" not in text[:500], "front matter must start on line 1"
        return
    end = text.find("\n---", 3)
    assert end != -1, "unterminated front matter"
    meta = yaml.safe_load(text[4:end])
    assert isinstance(meta, dict), "front matter must be a YAML mapping"
    if "description" in meta:
        assert isinstance(meta["description"], str) and meta["description"].strip()
