"""Build the Remote ACP Bridge release artefacts.

Everything this script produces lands outside the checkout, in the project's build
directory; the source tree stays source-only (working spec rule 7/9).

Steps: syntax check -> unit tests -> portable dist directory -> zip.
"""

from __future__ import annotations

import argparse
import ast
import os
import re
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime
from pathlib import Path

# Never leave __pycache__ in the source tree (working spec rule 7): this process
# imports the package, and it also spawns the server, which would write .pyc there.
sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent
# The unit tests are not part of this repository: they live in a sibling directory of the
# checkout (the project's development workspace). A checkout without them still builds.
TESTS = PROJECT / "Tests"
DEV = PROJECT / "Dev"
BUILD = DEV / "build"

SOURCES = [
    "src",
    # The tests are not part of this repository (they live beside the checkout), so the
    # release does not carry them; the syntax step reads them from there when present.
    # The deployment half (T69): the two units, the installer, and the helper's config
    # template. Without them the package cannot be deployed the way README §4 documents.
    "systemd",
    "install.sh",
    "build.py",
    "devrun.py",
    "config.example.toml",
    "client.example.toml",
    "helper.example.toml",
    "keys.example.txt",
    "README.md",
    "build.bat",
    "run.bat",
    # Line endings are part of the contract, so the release carries the rules that
    # enforce them (T14-S2). .gitignore stays out: it is repo hygiene, not deployment.
    ".gitattributes",
]


def python() -> str:
    return sys.executable


VERSION_RE = re.compile(r'^__version__\s*=\s*["\']([^"\']+)["\']', re.MULTILINE)


def version() -> str:
    """Read the release version out of the package source.

    Parsing, not ``exec``: the package's ``__init__`` touches ``__file__`` and the
    filesystem on purpose, so executing it outside an import would be wrong.
    """
    source = (HERE / "src" / "remote_acp_bridge" / "__init__.py").read_text(encoding="utf-8")
    match = VERSION_RE.search(source)
    if not match:
        raise SystemExit("build: cannot find __version__ in src/remote_acp_bridge/__init__.py")
    return match.group(1)


def python_files() -> list[Path]:
    """Every .py the syntax step parses: the package, plus the tests when a checkout has them."""
    roots = [HERE / "src"]
    if TESTS.is_dir():
        roots.append(TESTS)
    return sorted(p for root in roots for p in root.rglob("*.py"))


def step_syntax() -> bool:
    print(f"[1/5] syntax check ({len(python_files())} files)")
    ok = True
    for path in python_files():
        try:
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError as exc:
            ok = False
            print(f"  FAIL {path.relative_to(PROJECT)}: {exc}")
    return ok


ISOLATED_RERUNS = 2


def _run_suite(log_path: Path, env: dict[str, str]) -> int:
    with log_path.open("w", encoding="utf-8") as handle:
        proc = subprocess.run(
            # The tests live in a sibling directory of this checkout (see TESTS).
            [python(), "-m", "unittest", "discover", "-s", "Tests", "-t", ".", "-v"],
            cwd=PROJECT,
            env=env,
            stdout=handle,
            stderr=subprocess.STDOUT,
        )
    return proc.returncode


def _failing_cases(log_path: Path) -> list[str]:
    """The test ids unittest reported as failed/errored, so a retry can be named, not hidden."""
    text = log_path.read_text(encoding="utf-8", errors="replace")
    return sorted(set(re.findall(r"^(?:FAIL|ERROR): (\S+)", text, re.MULTILINE)))


def _rerun_isolated(case: str, env: dict[str, str]) -> bool:
    """Run one failing case on its own. Returns True if it passes there."""
    for _ in range(ISOLATED_RERUNS):
        proc = subprocess.run(
            [python(), "-m", "unittest", case],
            cwd=PROJECT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if proc.returncode == 0:
            return True
    return False


def step_tests(log_path: Path) -> bool:
    print("[2/5] unit tests")
    # No PYTHONDONTWRITEBYTECODE on purpose (R4 was masked while it was set): the
    # package and the test package keep the source tree clean by themselves.
    env = {k: v for k, v in os.environ.items() if k.upper() != "PYTHONDONTWRITEBYTECODE"}
    rc = _run_suite(log_path, env)
    tail = log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-3:]
    for line in tail:
        print(f"  {line}")
    if rc == 0:
        return True
    # T60-N4: the whole suite runs exactly once. The previous policy re-ran **all 322 cases**
    # up to three times here, and the verifier did the same again, so one build could run the
    # suite six times in series — which measurably *increased* the load-sensitive failures it
    # was meant to look through, and the review's A/B showed the case in question is red in a
    # full suite on both a passing commit and this one while it passes 6-7 of 8 times on its
    # own. Re-running only the failing ids answers the question that actually matters (does
    # this case fail by itself?) at a fraction of the load.
    cases = _failing_cases(log_path)
    if not cases:
        print("  FAILED: suite returned non-zero but no FAIL/ERROR line could be parsed")
        return False
    print(f"  suite failed on: {', '.join(cases)} — re-running those cases in isolation")
    stubborn = [case for case in cases if not _rerun_isolated(case, env)]
    if stubborn:
        # What we can say is only this: the failure is not an artefact of suite ordering,
        # because it reproduces on its own. **That is not the same as "this tree caused it"** —
        # the review's A/B ran the same case in isolation on a commit that passed the previous
        # round and it failed there too (T60-N4), so a case that is merely load- or
        # timing-sensitive lands here as well. The build stays red (the strict direction), and
        # the call about flake-vs-regression is left where it belongs: with a human.
        print(f"  FAILED — needs human triage (load/timing flake vs real regression):")
        for case in stubborn:
            print(f"    {case}: still failing when run alone "
                  f"({ISOLATED_RERUNS} attempt(s)); reproducing alone rules out suite ordering, "
                  f"not the change under test")
        print("        compare against the previous commit the same way before blaming this tree;"
              " the known timing-sensitive cases have a separate flake round.")
        return False
    # Not an allowlist and not a pass-by-name: every failing id is printed, and a case that
    # fails in isolation still fails the build. What is *not* concluded here is the thing the
    # old wording got wrong — passing alone does not prove the tree is clean, it only rules out
    # a self-contained defect. Someone has to decide whether the interaction is a test
    # isolation bug or a real ordering problem.
    print("  NOTE — needs human triage: every failing case passes in isolation but fails in the")
    print(f"        full suite ({', '.join(cases)}). That means a load/ordering interaction, not")
    print("        a self-contained defect in this tree; it is NOT evidence the tree is clean.")
    print("        Known timing-sensitive cases are scheduled for a separate flake round.")
    return True


# LIVES OUTSIDE THIS REPOSITORY (T60-C2). The gate's checker is a sibling of this checkout, so a commit
# here cannot carry a change to it: `git show <sha> --stat` never lists it, and a reviewer
# reading only the checkout would miss behaviour that decides whether the build is green — step 2 and
# entry 8 are deliberately the same policy, so changing one without the other makes the verdict
# depend on which ran first. Any change to the retry/triage rule therefore has to be made in
# BOTH files and called out in the commit message; README §6 documents the pairing.
VERIFIER = PROJECT / "Dev" / "run" / "verify-no-bytecode.py"


def step_cleanliness(log_path: Path, skip_unittest_entry: bool = False,
                     required: bool = False) -> bool:
    """Gate working-spec rule 7: no documented entry point may write .pyc into the source tree.


    Runs each entry cold, in an environment stripped of PYTHONDONTWRITEBYTECODE,
    so this step cannot be fooled the way R4 fooled the self-test.

    ``required`` (``--require-cleanliness-gate``) turns a missing verifier into a
    build failure instead of a pass: in CI, where a source-only checkout has no
    development workspace beside it, the step would otherwise spin and report nothing.
    """
    print("[3/5] bytecode cleanliness gate")
    if not VERIFIER.is_file():
        if required:
            print(f"  FAILED: --require-cleanliness-gate given, but the verifier is absent: {VERIFIER}")
            return False
        print(f"  SKIP: verifier not present ({VERIFIER}) - it lives outside the source tree")
        return True
    cmd = [python(), str(VERIFIER)]
    if skip_unittest_entry:
        cmd += ["--fast"]
        print("  note: --skip-tests given, so the verifier skips its own unittest entry too")
    with log_path.open("w", encoding="utf-8") as handle:
        proc = subprocess.run(cmd, cwd=HERE, stdout=handle, stderr=subprocess.STDOUT)
    body = log_path.read_text(encoding="utf-8", errors="replace")
    explaining = False
    failed_labels: list[str] = []
    for line in body.splitlines():
        if line.startswith(("[PASS]", "[FAIL]", "[SKIP]", "summary:")):
            explaining = line.startswith("[FAIL]")
            if explaining:
                failed_labels.append(line.strip().removeprefix("[FAIL]").strip())
            print(f"  {line}")
        elif explaining and line.strip():
            # The verifier prints the reason indented under the verdict; without it a
            # build failure would say "1 FAILED" and nothing else.
            print(f"  {line}")
    if proc.returncode != 0:
        # Name what actually failed (T60-C1). "source tree is polluted" was asserted for every
        # non-zero exit, but the verifier returns non-zero for any failed entry — including the
        # unittest entry failing on a test — which sent people hunting for .pyc files that were
        # never the problem. Pre-existing dirt is reported by the verifier itself under its own
        # heading, and that case is covered by the first label below.
        print(f"  FAILED: cleanliness gate — failed entr{'y' if len(failed_labels) == 1 else 'ies'}:"
              f" {'; '.join(failed_labels) or 'none labelled (see report)'}")
        print(f"  full report in {log_path}")
    return proc.returncode == 0


def step_dist(dist: Path) -> None:
    print(f"[4/5] assemble {dist.relative_to(PROJECT)}")
    if dist.exists():
        shutil.rmtree(dist)
    dist.mkdir(parents=True)
    for name in SOURCES:
        source = HERE / name
        if source.is_dir():
            shutil.copytree(source, dist / name, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        elif source.exists():
            shutil.copy2(source, dist / name)
        else:
            print(f"  WARN missing {name}")


def step_zip(dist: Path, zip_path: Path) -> None:
    print(f"[5/5] zip {zip_path.relative_to(PROJECT)}")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(dist.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(dist.parent))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="build", description="Build the bridge release.")
    parser.add_argument("--skip-tests", action="store_true", help="skip the unit test step")
    parser.add_argument("--require-cleanliness-gate", action="store_true",
                        help="fail the build when the external cleanliness verifier is "
                             "absent, instead of skipping the gate (use this in CI)")
    args = parser.parse_args(argv)

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    BUILD.mkdir(parents=True, exist_ok=True)
    test_log = BUILD / f"unittest-{stamp}.log"
    clean_log = BUILD / f"cleanliness-{stamp}.log"
    release = version()
    dist = BUILD / f"remote-acp-bridge-{release}"
    zip_path = BUILD / f"remote-acp-bridge-{release}.zip"

    ok = step_syntax()
    if not ok:
        print("BUILD FAILED: syntax errors")
        return 1
    if args.skip_tests or not TESTS.is_dir():
        # The tests are not in this repository (they live in the development workspace beside
        # the checkout), so a plain checkout builds without them: skipped, never failed.
        print("[2/5] unit tests skipped (no test directory beside this checkout)")
    elif not step_tests(test_log):
        print(f"BUILD FAILED: unit tests (log: {test_log})")
        return 1

    if not step_cleanliness(clean_log, skip_unittest_entry=args.skip_tests,
                            required=args.require_cleanliness_gate):
        print(f"BUILD FAILED: cleanliness gate (report: {clean_log})")
        return 1

    step_dist(dist)
    step_zip(dist, zip_path)
    print(f"\nOK remote-acp-bridge {release}")
    print(f"  dist: {dist}")
    print(f"  zip : {zip_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
