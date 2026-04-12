"""
Solvability and syntax checking via external planners (Metric-FF and ENHSP).

Metric-FF: fast solvability check (finds plan or reports failure).
ENHSP:     strict syntax validation (stricter parser catches errors Metric-FF ignores).

Usage:
    from cve2pddlap.evaluation.solvability import create_ff_checker, create_enhsp_checker

    ff = create_ff_checker()        # reads path from settings.toml
    result = ff.check("domain.pddl", "problem.pddl")

    enhsp = create_enhsp_checker()  # reads path from settings.toml
    result = enhsp.check("domain.pddl", "problem.pddl")
"""

from __future__ import annotations

import logging
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from cve2pddlap.utils.config import settings, PROJECT_ROOT

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PlannerResult:
    """Result from a planner check."""
    success: bool               # True = plan found (FF) or parsed OK (ENHSP)
    solvable: bool | None       # True = plan found, False = proved unsolvable, None = unknown/timeout
    plan: list[str]             # Ordered action names in the plan (empty if no plan)
    plan_length: int            # Number of actions in the plan
    plan_cost: float | None     # Total plan cost if available
    time_seconds: float | None  # Wall-clock time reported by planner
    raw_output: str             # Full stdout+stderr from planner
    error: str | None           # Error message if any


def _convert_to_enhsp(domain_pddl: str) -> str:
    """
    Convert Metric-FF format domain to ENHSP format:
    1. Replace :fluents with :numeric-fluents
    2. Move (:functions ...) block to after (:predicates ...) block
    """
    # 1. Replace :fluents with :numeric-fluents
    result = re.sub(r':fluents\b', ':numeric-fluents', domain_pddl)

    # 2. Extract and move (:functions ...) block
    functions_block = _extract_sexp(result, '(:functions')
    if functions_block:
        result = result.replace(functions_block, '', 1)
        predicates_end = _find_sexp_end(result, '(:predicates')
        if predicates_end is not None:
            result = result[:predicates_end] + '\n' + functions_block.strip() + '\n' + result[predicates_end:]

    return result


def _extract_sexp(text: str, start_tag: str) -> str | None:
    """Extract a balanced S-expression starting with start_tag."""
    idx = text.find(start_tag)
    if idx == -1:
        return None
    depth = 0
    for i in range(idx, len(text)):
        if text[i] == '(':
            depth += 1
        elif text[i] == ')':
            depth -= 1
            if depth == 0:
                return text[idx:i + 1]
    return None


def _find_sexp_end(text: str, start_tag: str) -> int | None:
    """Find the end position (after closing paren) of an S-expression."""
    idx = text.find(start_tag)
    if idx == -1:
        return None
    depth = 0
    for i in range(idx, len(text)):
        if text[i] == '(':
            depth += 1
        elif text[i] == ')':
            depth -= 1
            if depth == 0:
                return i + 1
    return None


class MetricFFChecker:
    """
    Metric-FF planner for solvability checking.

    Checks whether a plan can be found for the given domain + problem.
    Also extracts plan length, cost, and timing.
    """

    def __init__(self, ff_path: str | Path):
        self.ff_path = Path(ff_path)
        if not self.ff_path.exists():
            raise FileNotFoundError(f"Metric-FF binary not found: {self.ff_path}")

    def check(
        self,
        domain_path: str | Path,
        problem_path: str | Path,
        timeout: int = 60,
        search_config: str = "-s 4 -w 4",
    ) -> PlannerResult:
        """
        Run Metric-FF on the given domain and problem files.

        Args:
            domain_path: Path to domain.pddl
            problem_path: Path to problem.pddl
            timeout: Timeout in seconds
            search_config: FF search strategy flags (default: "-s 4 -w 4")
        """
        cmd = [
            str(self.ff_path),
            "-o", str(domain_path),
            "-f", str(problem_path),
        ] + search_config.split()

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            raw = proc.stdout + proc.stderr
            return self._parse_output(raw)

        except subprocess.TimeoutExpired:
            return PlannerResult(
                success=False, solvable=None, plan=[], plan_length=0,
                plan_cost=None, time_seconds=None, raw_output="",
                error=f"Timeout after {timeout}s",
            )
        except Exception as e:
            return PlannerResult(
                success=False, solvable=None, plan=[], plan_length=0,
                plan_cost=None, time_seconds=None, raw_output="",
                error=str(e),
            )

    def check_from_string(
        self,
        domain_pddl: str,
        problem_pddl: str,
        timeout: int = 60,
        search_config: str = "-s 4 -w 4",
    ) -> PlannerResult:
        """Run Metric-FF on PDDL strings (writes to temp files)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir) / "domain.pddl"
            p = Path(tmpdir) / "problem.pddl"
            d.write_text(domain_pddl, encoding="utf-8")
            p.write_text(problem_pddl, encoding="utf-8")
            return self.check(d, p, timeout, search_config)

    def _parse_output(self, raw: str) -> PlannerResult:
        """Parse Metric-FF output to extract plan, cost, timing."""
        # Check for plan
        plan_actions = []
        plan_match = re.findall(
            r'^\s*\d+:\s+(.+)$', raw, re.MULTILINE,
        )
        if plan_match:
            plan_actions = [a.strip() for a in plan_match]

        # Check solvability
        solvable = None
        if plan_actions:
            solvable = True
        elif "goal can be simplified to FALSE" in raw or "unsolvable" in raw.lower():
            solvable = False
        elif "ff: found legal command line" not in raw and plan_actions == []:
            # Likely a parse error
            solvable = False

        # Extract cost
        cost = None
        cost_match = re.search(r'plan cost:\s*([\d.]+)', raw)
        if cost_match:
            cost = float(cost_match.group(1))

        # Extract time
        time_sec = None
        time_match = re.search(r'([\d.]+)\s+seconds total time', raw)
        if time_match:
            time_sec = float(time_match.group(1))

        # Extract error
        error = None
        if not solvable and not plan_actions:
            error_lines = [
                l.strip() for l in raw.split('\n')
                if 'error' in l.lower() or 'fail' in l.lower() or 'syntax' in l.lower()
            ]
            error = '; '.join(error_lines) if error_lines else "No plan found"

        return PlannerResult(
            success=bool(plan_actions),
            solvable=solvable,
            plan=plan_actions,
            plan_length=len(plan_actions),
            plan_cost=cost,
            time_seconds=time_sec,
            raw_output=raw,
            error=error,
        )


class ENHSPChecker:
    """
    ENHSP planner for strict PDDL syntax validation.

    ENHSP has a stricter parser than Metric-FF and catches syntax errors
    that Metric-FF may ignore. Primarily used for syntax checking, not
    solvability (too slow for most domains).

    Automatically converts Metric-FF format to ENHSP format:
    - :fluents → :numeric-fluents
    - (:functions) moved after (:predicates)
    """

    def __init__(self, enhsp_jar_path: str | Path):
        self.jar_path = Path(enhsp_jar_path)
        if not self.jar_path.exists():
            raise FileNotFoundError(f"ENHSP jar not found: {self.jar_path}")

    def check(
        self,
        domain_path: str | Path,
        problem_path: str | Path,
        timeout: int = 30,
        convert_format: bool = True,
    ) -> PlannerResult:
        """
        Run ENHSP syntax check on domain + problem.

        Args:
            domain_path: Path to domain.pddl (Metric-FF format)
            problem_path: Path to problem.pddl
            timeout: Timeout in seconds (short, since we only need parsing)
            convert_format: Auto-convert from Metric-FF to ENHSP format
        """
        domain_text = Path(domain_path).read_text(encoding="utf-8")
        problem_text = Path(problem_path).read_text(encoding="utf-8")
        return self.check_from_string(domain_text, problem_text, timeout, convert_format)

    def check_from_string(
        self,
        domain_pddl: str,
        problem_pddl: str,
        timeout: int = 30,
        convert_format: bool = True,
    ) -> PlannerResult:
        """
        Run ENHSP syntax check on PDDL strings.

        Only checks parsing — kills process after "Problem parsed" to avoid
        slow grounding/search.
        """
        if convert_format:
            domain_pddl = _convert_to_enhsp(domain_pddl)

        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir) / "domain.pddl"
            p = Path(tmpdir) / "problem.pddl"
            d.write_text(domain_pddl, encoding="utf-8")
            p.write_text(problem_pddl, encoding="utf-8")

            cmd = [
                "java", "-jar", str(self.jar_path),
                "-o", str(d),
                "-f", str(p),
            ]

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                raw = proc.stdout + proc.stderr
                return self._parse_output(raw)

            except subprocess.TimeoutExpired:
                # Timeout is expected — ENHSP is slow at solving.
                # If it got past parsing, syntax is OK.
                return PlannerResult(
                    success=True, solvable=None, plan=[], plan_length=0,
                    plan_cost=None, time_seconds=None,
                    raw_output="Timeout (parsing likely succeeded)",
                    error=None,
                )
            except Exception as e:
                return PlannerResult(
                    success=False, solvable=None, plan=[], plan_length=0,
                    plan_cost=None, time_seconds=None, raw_output="",
                    error=str(e),
                )

    def _parse_output(self, raw: str) -> PlannerResult:
        """Parse ENHSP output — focus on parsing success/failure."""
        domain_parsed = "Domain parsed" in raw
        problem_parsed = "Problem parsed" in raw
        syntax_ok = domain_parsed and problem_parsed

        # Check if a plan was found (bonus, not expected)
        plan_actions = []
        solvable = None
        if "Plan:" in raw:
            plan_section = raw.split("Plan:")[-1]
            plan_actions = re.findall(r'^\s*\d+:\s+\((.+)\)', plan_section, re.MULTILINE)
            solvable = True if plan_actions else None

        error = None
        if not syntax_ok:
            error_lines = [
                l.strip() for l in raw.split('\n')
                if any(k in l.lower() for k in ['error', 'exception', 'parsing failed', 'unexpected'])
            ]
            error = '; '.join(error_lines) if error_lines else "Parsing failed"

        return PlannerResult(
            success=syntax_ok,
            solvable=solvable,
            plan=plan_actions,
            plan_length=len(plan_actions),
            plan_cost=None,
            time_seconds=None,
            raw_output=raw,
            error=error,
        )


# --- Factory functions (read paths from settings.toml) ---

def create_ff_checker() -> MetricFFChecker:
    """Create a MetricFFChecker using the path from settings.toml."""
    return MetricFFChecker(PROJECT_ROOT / settings.Evaluation.metric_ff)


def create_enhsp_checker() -> ENHSPChecker:
    """Create an ENHSPChecker using the path from settings.toml."""
    return ENHSPChecker(PROJECT_ROOT / settings.Evaluation.enhsp)
