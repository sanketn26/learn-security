"""The Module 4b workshop must stay teachable.

Against the reference fix every exercise test passes. Against the vulnerable
app exactly the test_exploit_* tests fail, so each exploit test provably
detects its vulnerability and each test_legit_* test provably survives a fix.
"""

from __future__ import annotations

import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _run_workshop(lab_mode: str, tmp_path: Path) -> dict[str, bool]:
    """Run labs/workshop in a subprocess; return {test name: passed}."""
    report = tmp_path / f"workshop-{lab_mode}.xml"
    env = {**os.environ, "WORKSHOP_LAB_MODE": lab_mode}
    subprocess.run(
        [sys.executable, "-m", "pytest", "labs/workshop", "-q", "-p", "no:cacheprovider",
         f"--junitxml={report}"],
        cwd=ROOT, env=env, capture_output=True, text=True, check=False,
    )
    results: dict[str, bool] = {}
    for case in ET.parse(report).getroot().iter("testcase"):
        failed = case.find("failure") is not None or case.find("error") is not None
        results[case.get("name", "")] = not failed
    return results


@pytest.fixture(scope="module")
def secure_results(tmp_path_factory):
    return _run_workshop("false", tmp_path_factory.mktemp("secure"))


@pytest.fixture(scope="module")
def lab_results(tmp_path_factory):
    return _run_workshop("true", tmp_path_factory.mktemp("lab"))


def test_reference_fix_passes_every_exercise(secure_results):
    assert secure_results, "no workshop tests collected"
    assert all(secure_results.values()), [n for n, ok in secure_results.items() if not ok]


def test_exploit_tests_fail_on_the_vulnerable_app(lab_results):
    exploits = {n: ok for n, ok in lab_results.items() if n.startswith("test_exploit_")}
    assert exploits
    assert not any(exploits.values()), [n for n, ok in exploits.items() if ok]


def test_legit_tests_pass_on_the_vulnerable_app(lab_results):
    legit = {n: ok for n, ok in lab_results.items() if n.startswith("test_legit_")}
    assert legit
    assert all(legit.values()), [n for n, ok in legit.items() if not ok]


def test_every_test_is_exploit_or_legit(lab_results):
    assert all(n.startswith(("test_exploit_", "test_legit_")) for n in lab_results)
