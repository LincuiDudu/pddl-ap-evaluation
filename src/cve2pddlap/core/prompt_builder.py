"""
Jinja2-based prompt construction for CVE → PDDL attack path generation.
Supports zero-shot and few-shot modes.
"""

from __future__ import annotations

from pathlib import Path
from jinja2 import Environment, FileSystemLoader

from cve2pddlap.core.data_loader import FewShotExample

# Instruction tiers:
#   BMI1-BMI6: always on (Big Model Instructions — high value for all models)
#   SMI1-SMI5: always on in zero-shot, optional in few-shot (Small Model Instructions)
#   OI1-OI3:   always optional (low value / situational)
BMI_NAMES = ["BMI1", "BMI2", "BMI3", "BMI4", "BMI5", "BMI6"]
SMI_NAMES = ["SMI1", "SMI2", "SMI3", "SMI4", "SMI5"]
OI_NAMES = ["OI1", "OI2", "OI3"]
ALL_SELECTABLE_NAMES = SMI_NAMES + OI_NAMES  # BMIs are always on, not selectable

_project_root = Path(__file__).resolve().parents[3]
_template_dir = _project_root / "resources" / "prompt" / "generation"

_env = Environment(
    loader=FileSystemLoader(str(_template_dir)),
    keep_trailing_newline=True,
    trim_blocks=True,
    lstrip_blocks=True,
)


def render_context(
    selected_oi: list[str] | None = None,
    shot_mode: str = "zero",
) -> str:
    """
    Render the system prompt from the context template.

    Args:
        selected_oi: Instruction keys to include beyond always-on BMIs.
                     e.g. ["SMI1", "OI1"].
                     In zero-shot: controls OI1-OI3 only (SMI1-SMI5 are always on).
                     In few-shot: controls SMI1-SMI5 and OI1-OI3 (BMI1-BMI6 always on).
        shot_mode: "zero" or "few". Controls instruction visibility logic.
    """
    if selected_oi is None:
        selected_oi = []
    template = _env.get_template("context.jinja")
    return template.render(selected_oi=selected_oi, shot_mode=shot_mode)


def render_query(cve_id: str, cve_description: str) -> str:
    """Render the user query from CVE data."""
    template = _env.get_template("query.jinja")
    return template.render(cve_id=cve_id, cve_description=cve_description)


def build_messages(
    cve_id: str,
    cve_description: str,
    selected_oi: list[str] | None = None,
    few_shot_examples: list[FewShotExample] | None = None,
) -> list[dict[str, str]]:
    """
    Build the full message list for LLM input.

    Zero-shot (no examples):
        [system, user]

    Few-shot (with examples):
        [system, ex1_user, ex1_assistant, ..., exN_user, exN_assistant, user]

    Returns:
        List of {"role": "system"|"user"|"assistant", "content": "..."} dicts.
    """
    shot_mode = "few" if few_shot_examples else "zero"
    messages = [{"role": "system", "content": render_context(selected_oi, shot_mode)}]

    # Few-shot examples as user/assistant message pairs
    if few_shot_examples:
        for ex in few_shot_examples:
            messages.append({
                "role": "user",
                "content": render_query(ex.cve_id, ex.description),
            })
            messages.append({
                "role": "assistant",
                "content": ex.domain_pddl,
            })

    # The actual query
    messages.append({"role": "user", "content": render_query(cve_id, cve_description)})

    return messages


# --- Problem PDDL generation ---

def render_problem_context() -> str:
    """Render the system prompt for problem.pddl generation."""
    template = _env.get_template("problem_context.jinja")
    return template.render()


def render_problem_query(cve_id: str, cve_description: str, domain_pddl: str) -> str:
    """Render the user query for problem.pddl generation."""
    template = _env.get_template("problem_query.jinja")
    return template.render(cve_id=cve_id, cve_description=cve_description, domain_pddl=domain_pddl)


def build_problem_messages(
    cve_id: str,
    cve_description: str,
    domain_pddl: str,
    few_shot_examples: list[FewShotExample] | None = None,
) -> list[dict[str, str]]:
    """
    Build the message list for problem.pddl generation.

    Zero-shot:
        [system, user]

    Few-shot:
        [system, ex1_user, ex1_assistant, ..., user]

    Args:
        cve_id: Target CVE ID.
        cve_description: Target CVE description.
        domain_pddl: The generated domain.pddl to create a problem for.
        few_shot_examples: Optional examples (must have problem_pddl attribute).
    """
    messages = [{"role": "system", "content": render_problem_context()}]

    if few_shot_examples:
        for ex in few_shot_examples:
            if not hasattr(ex, 'problem_pddl') or not ex.problem_pddl:
                continue
            messages.append({
                "role": "user",
                "content": render_problem_query(ex.cve_id, ex.description, ex.domain_pddl),
            })
            messages.append({
                "role": "assistant",
                "content": ex.problem_pddl,
            })

    messages.append({
        "role": "user",
        "content": render_problem_query(cve_id, cve_description, domain_pddl),
    })

    return messages
