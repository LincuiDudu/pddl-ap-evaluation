#!/usr/bin/env python3
"""
PDDL Domain Mutator — generate synthetic hard negatives from correct reference domains.

Mutation operators (Target × Op → Expected violation → Expected violation):
  1.  delete_critical_action         — Step 0/final action × delete: remove Exposure or Impact action                → C2 
  2.  delete_random_precondition     — causal precondition × delete: remove causal-chain precondition                → C1
  3.  swap_action_effects            — consecutive actions × swap: swap effects of two consecutive actions            → A2
  4.  remove_stride_goal             — final action effect × delete: remove STRIDE predicate from final action          → V3
  5.  corrupt_exposure_action        — Step 0 effect × delete: remove exposes-attack-surface/exploit-by effects       → V1
  6.  merge_consecutive_actions      — consecutive actions × merge: merge two mid-chain actions into one              → A1
  7.  inject_capability_violation    — mid-chain precondition × inject: add forbidden capability predicate            → F1
  8.  replace_with_abstract_action   — mid-chain action × replace: replace with abstract symbolic transition          → F2
  9.  replace_exploitation_mechanism — mid-chain actions × rename: rename to wrong attack technique                   → V2
  10. scramble_action_names          — all action names × scramble: replace with opaque identifiers                   → N1
  11. scramble_predicate_names       — all predicate names × scramble: replace with opaque identifiers                → N2

Usage:
    python tools/mutator.py <domain.pddl> [--mutation TYPE] [--output mutated.pddl] [--seed 42]
    python tools/mutator.py <domain.pddl> --all --outdir mutations/
"""

from __future__ import annotations

import argparse
import random
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Lightweight PDDL action parser
# ---------------------------------------------------------------------------

def _find_balanced(text: str, start: int) -> int:
    """Return index *after* the closing paren matching the '(' at `start`."""
    assert text[start] == "(", f"Expected '(' at position {start}, got '{text[start]}'"
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i + 1
    raise ValueError("Unbalanced parentheses")


def _extract_sexp(text: str, tag: str) -> Optional[str]:
    """Extract the first balanced s-expression starting with `tag`."""
    idx = text.find(tag)
    if idx == -1:
        return None
    # Walk back to the opening paren
    paren_idx = text.rfind("(", 0, idx + 1)
    if paren_idx == -1:
        return None
    end = _find_balanced(text, paren_idx)
    return text[paren_idx:end]


@dataclass
class PDDLAction:
    """Parsed representation of a single PDDL action."""
    name: str
    full_text: str          # verbatim text including outer parens
    parameters: str         # raw parameter string
    precondition: str       # raw precondition s-exp (including outer parens)
    effect: str             # raw effect s-exp (including outer parens)
    start_idx: int          # char offset in domain string
    end_idx: int            # char offset end


def parse_actions(domain_text: str) -> list[PDDLAction]:
    """Parse all (:action ...) blocks from domain text."""
    actions = []
    pattern = re.compile(r"\(:action\s+")
    for m in pattern.finditer(domain_text):
        start = m.start()
        end = _find_balanced(domain_text, start)
        full = domain_text[start:end]

        # Name
        name_match = re.match(r"\(:action\s+([\w\-]+)", full)
        name = name_match.group(1) if name_match else "unknown"

        # Parameters
        params_match = re.search(r":parameters\s*(\([^)]*\))", full)
        params = params_match.group(1) if params_match else "()"

        # Precondition (balanced sexp)
        precond = ""
        pre_idx = full.find(":precondition")
        if pre_idx != -1:
            # find the next '('
            p_start = full.index("(", pre_idx + len(":precondition"))
            p_end = _find_balanced(full, p_start)
            precond = full[p_start:p_end]

        # Effect (balanced sexp)
        eff = ""
        eff_idx = full.find(":effect")
        if eff_idx != -1:
            e_start = full.index("(", eff_idx + len(":effect"))
            e_end = _find_balanced(full, e_start)
            eff = full[e_start:e_end]

        actions.append(PDDLAction(
            name=name, full_text=full, parameters=params,
            precondition=precond, effect=eff,
            start_idx=start, end_idx=end,
        ))
    return actions


def _replace_action(domain: str, old_action: PDDLAction, new_text: str) -> str:
    """Replace an action in the domain string."""
    return domain[:old_action.start_idx] + new_text + domain[old_action.end_idx:]


def _remove_action(domain: str, action: PDDLAction) -> str:
    """Remove an action from the domain string (including surrounding whitespace)."""
    # Trim trailing whitespace/newlines
    end = action.end_idx
    while end < len(domain) and domain[end] in (" ", "\t", "\n", "\r"):
        end += 1
    return domain[:action.start_idx] + domain[end:]


# ---------------------------------------------------------------------------
# STRIDE predicates
# ---------------------------------------------------------------------------

STRIDE_PREDICATES = [
    "spoofing", "tampering", "repudiation",
    "information-disclosure", "denial-of-service", "elevation-of-privilege",
]


def _find_stride_in_effect(effect_text: str) -> Optional[str]:
    """Find which STRIDE predicate appears in an effect string."""
    for s in STRIDE_PREDICATES:
        if s in effect_text:
            return s
    return None


# ---------------------------------------------------------------------------
# Mutation operators
# ---------------------------------------------------------------------------

@dataclass
class MutationResult:
    """Result of applying a mutation."""
    mutated_domain: str
    mutation_type: str
    description: str
    expected_label: str       # "POSITIVE" or "NEGATIVE"
    changed_action: str       # name of the action that was changed/removed
    details: dict = field(default_factory=dict)


def delete_critical_action(domain: str, actions: list[PDDLAction],
                           rng: random.Random) -> MutationResult:
    """Remove Step 0 (Exposure) or the final action (Impact), violating C2."""
    if len(actions) < 2:
        raise ValueError("Need at least 2 actions to delete Step 0 or final action")
    # Randomly choose Step 0 or final action
    choice = rng.choice(["step0", "final"])
    if choice == "step0":
        target = actions[0]
        stage = "Exposure"
    else:
        target = actions[-1]
        stage = "Impact"
    idx = actions.index(target)
    mutated = _remove_action(domain, target)
    return MutationResult(
        mutated_domain=mutated,
        mutation_type="delete_critical_action",
        description=f"Removed {stage} action '{target.name}' (index {idx}/{len(actions)-1})",
        expected_label="NEGATIVE",
        changed_action=target.name,
        details={"removed_index": idx, "removed_stage": stage, "total_actions": len(actions)},
    )


def delete_random_precondition(domain: str, actions: list[PDDLAction],
                               rng: random.Random) -> MutationResult:
    """Remove a causal-chain precondition from a non-Step-0 action.

    Preferentially targets preconditions related to C1 prohibited implicit jumps:
    credentials, access, artifacts, privileges, user interaction.
    """
    # Keywords matching C1 prohibited implicit jump categories
    CAUSAL_KEYWORDS = [
        # credential use without prior acquisition
        "credential", "password", "token", "api-key", "auth", "session",
        # network boundary traversal without established access
        "access", "connection", "connected", "network", "reach",
        # privilege escalation without a prior foothold
        "privilege", "root", "admin", "foothold", "elevated",
        # artifact use without prior creation
        "craft", "payload", "artifact", "exploit", "malicious",
        # user interaction without prior luring
        "user-click", "user-open", "lure", "phishing",
        # general causal-chain predicates (effects of prior actions)
        "has-", "is-", "can-",
    ]

    candidates = [a for a in actions[1:] if a.precondition]
    if not candidates:
        raise ValueError("No suitable actions with preconditions found")

    def _parse_clauses(precond_text):
        inner = precond_text.strip()
        if inner.startswith("(and"):
            inner = inner[4:].strip()
            if inner.endswith(")"):
                inner = inner[:-1]
        clauses = []
        i = 0
        while i < len(inner):
            if inner[i] == "(":
                end = _find_balanced(inner, i)
                clauses.append(inner[i:end])
                i = end
            else:
                i += 1
        return clauses

    def _is_causal(clause):
        cl = clause.lower()
        return any(kw in cl for kw in CAUSAL_KEYWORDS)

    # Try to find an action with causal-chain preconditions
    rng.shuffle(candidates)
    target = None
    causal_removable = []
    for cand in candidates:
        clauses = _parse_clauses(cand.precondition)
        if len(clauses) <= 1:
            continue
        removable = [c for c in clauses if "total-cost" not in c]
        causal = [c for c in removable if _is_causal(c)]
        if causal:
            target = cand
            causal_removable = causal
            break

    # Fallback: any action with removable preconditions
    if target is None:
        for cand in candidates:
            clauses = _parse_clauses(cand.precondition)
            if len(clauses) <= 1:
                continue
            removable = [c for c in clauses if "total-cost" not in c]
            if removable:
                target = cand
                causal_removable = removable
                break

    if target is None:
        raise ValueError("No action with multiple removable preconditions found")

    precond = target.precondition.strip()
    clauses = _parse_clauses(precond)
    removed = rng.choice(causal_removable)
    clauses.remove(removed)

    # Rebuild precondition
    if len(clauses) == 1:
        new_precond = clauses[0]
    else:
        new_precond = "(and " + "\n                       ".join(clauses) + ")"

    new_action_text = target.full_text.replace(target.precondition, new_precond)
    mutated = _replace_action(domain, target, new_action_text)
    return MutationResult(
        mutated_domain=mutated,
        mutation_type="delete_random_precondition",
        description=f"Removed precondition '{removed.strip()[:60]}...' from '{target.name}'",
        expected_label="NEGATIVE",
        changed_action=target.name,
        details={"removed_clause": removed.strip(), "action": target.name},
    )


def swap_action_effects(domain: str, actions: list[PDDLAction],
                        rng: random.Random) -> MutationResult:
    """Swap effects of two consecutive mid-chain actions."""
    if len(actions) < 3:
        raise ValueError("Need at least 3 actions to swap consecutive effects")
    # Pick consecutive pair from mid-chain
    max_start = len(actions) - 2
    start_idx = rng.randint(1, max_start) if max_start > 1 else 1
    a1, a2 = actions[start_idx], actions[start_idx + 1]

    # Swap their effects in the domain text
    # We must do the replacement carefully — replace the later one first to preserve offsets
    if a1.start_idx < a2.start_idx:
        first, second = a1, a2
    else:
        first, second = a2, a1

    new_second = second.full_text.replace(second.effect, first.effect)
    mutated = domain[:second.start_idx] + new_second + domain[second.end_idx:]

    # Now replace first (offsets haven't changed before second)
    new_first = first.full_text.replace(first.effect, second.effect)
    mutated = mutated[:first.start_idx] + new_first + mutated[first.start_idx + len(first.full_text):]

    return MutationResult(
        mutated_domain=mutated,
        mutation_type="swap_action_effects",
        description=f"Swapped effects of '{a1.name}' and '{a2.name}'",
        expected_label="NEGATIVE",
        changed_action=f"{a1.name}, {a2.name}",
        details={"action1": a1.name, "action2": a2.name},
    )


def remove_stride_goal(domain: str, actions: list[PDDLAction],
                        rng: random.Random) -> MutationResult:
    """Remove the STRIDE predicate from the final action's effect (V3 violation)."""
    final = actions[-1]
    current_stride = _find_stride_in_effect(final.effect)
    if current_stride is None:
        raise ValueError(f"Final action '{final.name}' has no STRIDE predicate in its effect")

    # Remove the STRIDE clause from effect
    inner = final.effect.strip()
    if inner.startswith("(and"):
        inner_content = inner[4:].strip()
        if inner_content.endswith(")"):
            inner_content = inner_content[:-1]
        # Parse clauses
        clauses = []
        i = 0
        while i < len(inner_content):
            if inner_content[i] == "(":
                end = _find_balanced(inner_content, i)
                clauses.append(inner_content[i:end])
                i = end
            else:
                i += 1
        # Remove STRIDE clause
        kept = [c for c in clauses if current_stride not in c]
        if not kept:
            raise ValueError("Removing STRIDE would leave effect empty")
        elif len(kept) == 1:
            new_effect = kept[0]
        else:
            new_effect = "(and " + "\n                 ".join(kept) + ")"
    else:
        raise ValueError("Final action effect is not an (and ...) block")

    new_action = final.full_text.replace(final.effect, new_effect)
    mutated = _replace_action(domain, final, new_action)

    return MutationResult(
        mutated_domain=mutated,
        mutation_type="replace_stride_goal",
        description=f"Removed STRIDE '{current_stride}' from final action (V3 violation)",
        expected_label="NEGATIVE",
        changed_action=final.name,
        details={"removed_stride": current_stride},
    )


def corrupt_exposure_action(domain: str, actions: list[PDDLAction],
                            rng: random.Random) -> MutationResult:
    """Remove exposes-attack-surface or exploit-by effects from Step 0 (V1 violation)."""
    step0 = actions[0]
    effect = step0.effect

    # Parse effect clauses
    inner = effect.strip()
    if inner.startswith("(and"):
        inner = inner[4:].strip()
        if inner.endswith(")"):
            inner = inner[:-1]

    clauses = []
    i = 0
    while i < len(inner):
        if inner[i] == "(":
            end = _find_balanced(inner, i)
            clauses.append(inner[i:end])
            i = end
        else:
            i += 1

    # Target V1 required effects: exposes-attack-surface, exploit-by
    V1_KEYWORDS = ["exposes-attack-surface", "exploit-by"]
    removable = [c for c in clauses if any(kw in c.lower() for kw in V1_KEYWORDS)]
    kept = [c for c in clauses if c not in removable]

    if not removable:
        raise ValueError("Step 0 has no exposes-attack-surface or exploit-by effects to remove")

    if len(kept) == 0:
        raise ValueError("Removing all effects would leave Step 0 empty")
    elif len(kept) == 1:
        new_effect = kept[0]
    else:
        new_effect = "(and " + "\n                       ".join(kept) + ")"

    new_action = step0.full_text.replace(step0.effect, new_effect)
    mutated = _replace_action(domain, step0, new_action)

    return MutationResult(
        mutated_domain=mutated,
        mutation_type="corrupt_exposure_action",
        description=f"Removed {len(removable)} V1-required effects (exposes-attack-surface/exploit-by) from Step 0",
        expected_label="NEGATIVE",
        changed_action=step0.name,
        details={"removed_count": len(removable), "removed_clauses": [r.strip()[:60] for r in removable]},
    )


def merge_consecutive_actions(domain: str, actions: list[PDDLAction],
                              rng: random.Random) -> MutationResult:
    """Merge two consecutive mid-chain actions into one, violating atomicity (A1).

    The merged action takes:
      - name: concatenation of both names with "-AND-"
      - parameters: union of both parameter lists
      - precondition: first action's preconditions
      - effect: union of both actions' effects (second action's preconditions are dropped)

    This creates an action that performs two independent operations in one step.
    """
    if len(actions) < 4:
        raise ValueError("Need at least 4 actions to merge two mid-chain actions")

    # Pick two consecutive mid-chain actions (not Step 0 or final)
    max_start = len(actions) - 2  # second action can't be the final one
    candidates = list(range(1, max_start))
    if not candidates:
        raise ValueError("No valid consecutive mid-chain pair to merge")
    idx = rng.choice(candidates)
    a1, a2 = actions[idx], actions[idx + 1]

    # Merge name
    merged_name = f"{a1.name}-AND-{a2.name}"

    # Merge parameters: concatenate, deduplicate by variable name
    p1 = a1.parameters.strip().strip("()")
    p2 = a2.parameters.strip().strip("()")
    p1_vars = set(re.findall(r'\?\w+', p1))
    p2_only = p2
    for var in p1_vars:
        p2_only = re.sub(rf'{re.escape(var)}\s+-\s+[\w-]+', '', p2_only)
    p2_only = re.sub(r'\s+', ' ', p2_only).strip()
    merged_param_str = f"({p1} {p2_only})" if p2_only else f"({p1})"

    # Use a1's precondition (drop a2's — this is the key atomicity violation)
    merged_precond = a1.precondition

    # Merge effects: combine both effects
    def _extract_effect_clauses(eff: str) -> list[str]:
        inner = eff.strip()
        if inner.startswith("(and"):
            inner = inner[4:].strip()
            if inner.endswith(")"):
                inner = inner[:-1]
        clauses = []
        i = 0
        while i < len(inner):
            if inner[i] == "(":
                end = _find_balanced(inner, i)
                clauses.append(inner[i:end])
                i = end
            else:
                i += 1
        return clauses

    eff1_clauses = _extract_effect_clauses(a1.effect)
    eff2_clauses = _extract_effect_clauses(a2.effect)
    all_effects = eff1_clauses + eff2_clauses
    # Deduplicate
    seen = set()
    unique_effects = []
    for e in all_effects:
        if e.strip() not in seen:
            seen.add(e.strip())
            unique_effects.append(e)
    merged_effect = "(and " + "\n                 ".join(unique_effects) + ")"

    # Build merged action text
    merged_action = (
        f"(:action {merged_name}\n"
        f"    :parameters {merged_param_str}\n"
        f"    :precondition {merged_precond}\n"
        f"    :effect {merged_effect}\n"
        f"  )"
    )

    # Remove both original actions, insert merged one
    # a1 is always before a2 (parsed in order), so remove a2 first to preserve a1's offsets
    assert a1.start_idx < a2.start_idx, "Actions should be in parse order"
    mutated = _remove_action(domain, a2)
    mutated = _replace_action(mutated, a1, merged_action)

    return MutationResult(
        mutated_domain=mutated,
        mutation_type="merge_consecutive_actions",
        description=f"Merged '{a1.name}' and '{a2.name}' into single action (A1 violation)",
        expected_label="NEGATIVE",
        changed_action=merged_name,
        details={
            "action1": a1.name,
            "action2": a2.name,
            "merged_name": merged_name,
            "original_action_count": len(actions),
            "new_action_count": len(actions) - 1,
        },
    )


def inject_capability_violation(domain: str, actions: list[PDDLAction],
                                rng: random.Random) -> MutationResult:
    """Add excluded-capability predicates to a mid-chain action's preconditions (F1 violation).

    Injects preconditions that assume pre-existing root/admin access or internal network
    position — capabilities explicitly excluded by the adversarial model. The action
    keeps its original structure but now depends on impossible capabilities.
    """
    if len(actions) <= 2:
        raise ValueError("Need at least 3 actions")

    # Capability violations to inject (randomly pick one)
    VIOLATIONS = [
        ("has-root-access", "assumes pre-existing root/admin access"),
        ("has-valid-admin-credentials", "assumes pre-existing admin credentials"),
    ]
    violation_pred, violation_desc = rng.choice(VIOLATIONS)

    mid_indices = list(range(1, len(actions) - 1))
    idx = rng.choice(mid_indices)
    target = actions[idx]

    # Add the violating predicate to predicates block
    pred_block = _extract_sexp(domain, "(:predicates")
    if pred_block:
        last_paren = pred_block.rfind(")")
        new_pred = f"    ({violation_pred} ?Target - target-system)"
        new_pred_block = pred_block[:last_paren] + "\n" + new_pred + "\n  )"
        mutated = domain.replace(pred_block, new_pred_block, 1)
    else:
        mutated = domain

    # Re-parse to get updated offsets after predicate insertion
    updated_actions = parse_actions(mutated)
    target_updated = updated_actions[idx]

    # Inject the violation predicate into the action's precondition
    precond = target_updated.precondition.strip()
    inject_clause = f"({violation_pred} ?Target)"
    if precond.startswith("(and"):
        # Insert before the closing paren of (and ...)
        last_paren = precond.rfind(")")
        new_precond = precond[:last_paren] + f"\n                       {inject_clause})"
    else:
        new_precond = f"(and {precond}\n                       {inject_clause})"

    new_action_text = target_updated.full_text.replace(target_updated.precondition, new_precond)
    mutated = _replace_action(mutated, target_updated, new_action_text)

    return MutationResult(
        mutated_domain=mutated,
        mutation_type="inject_capability_violation",
        description=f"Injected '{violation_pred}' precondition into '{target.name}' — {violation_desc} (F1 violation)",
        expected_label="NEGATIVE",
        changed_action=target.name,
        details={"injected_predicate": violation_pred, "violation": violation_desc, "action": target.name},
    )


def replace_with_abstract_action(domain: str, actions: list[PDDLAction],
                                 rng: random.Random) -> MutationResult:
    """Replace a mid-chain action with an abstract, non-executable symbolic transition (F2 violation).

    The replacement action has no real-world operational counterpart — both the name
    and the effects are replaced with abstract symbolic identifiers.
    """
    if len(actions) <= 2:
        raise ValueError("Need at least 3 actions")
    mid_indices = list(range(1, len(actions) - 1))
    idx = rng.choice(mid_indices)
    target = actions[idx]

    # Extract individual effect clauses using balanced-paren parsing
    def _extract_clauses(sexp: str) -> list[str]:
        inner = sexp.strip()
        if inner.startswith("(and"):
            # Skip "(and" and find clauses inside
            depth = 0
            clauses = []
            ci = 4  # skip "(and"
            while ci < len(inner) - 1:  # -1 to skip outer closing paren
                if inner[ci] == "(":
                    end = _find_balanced(inner, ci)
                    clauses.append(inner[ci:end])
                    ci = end
                else:
                    ci += 1
            return clauses
        else:
            return [inner]

    original_effects = _extract_clauses(target.effect)

    # Keep original effects for solvability, add abstract ones alongside
    abstract_effects = []
    abstract_count = 0
    for j, eff in enumerate(original_effects):
        abstract_effects.append(eff)
        if "total-cost" not in eff and "increase" not in eff:
            abstract_effects.append(f"(abstract-state-{idx}-{abstract_count} ?Target)")
            abstract_count += 1

    abstract_effect = "(and " + "\n                 ".join(abstract_effects) + ")"

    # Add abstract predicates to predicates block
    pred_block = _extract_sexp(domain, "(:predicates")
    if pred_block:
        last_paren = pred_block.rfind(")")
        new_preds = "\n".join(
            f"    (abstract-state-{idx}-{j} ?Target - target-system)"
            for j in range(abstract_count)
        )
        new_pred_block = pred_block[:last_paren] + "\n" + new_preds + "\n  )"
        mutated = domain.replace(pred_block, new_pred_block, 1)
    else:
        mutated = domain

    # Re-parse to get updated offsets
    updated_actions = parse_actions(mutated)
    target_updated = updated_actions[idx]

    abstract_action = (
        f"(:action generic-state-transition-step-{idx}\n"
        f"    :parameters {target_updated.parameters}\n"
        f"    :precondition {target_updated.precondition}\n"
        f"    :effect {abstract_effect}\n"
        f"  )"
    )
    mutated = _replace_action(mutated, target_updated, abstract_action)

    return MutationResult(
        mutated_domain=mutated,
        mutation_type="replace_with_abstract_action",
        description=f"Replaced '{target.name}' with abstract action and symbolic effects (F2 violation)",
        expected_label="NEGATIVE",
        changed_action=f"generic-state-transition-step-{idx}",
        details={"replaced_action": target.name, "abstract_effects_added": abstract_count},
    )


def replace_exploitation_mechanism(domain: str, actions: list[PDDLAction],
                                   rng: random.Random) -> MutationResult:
    """Replace exploitation-specific action names AND predicates with a wrong mechanism (V2 violation).

    Renames mid-chain actions and replaces their non-structural predicates with predicates
    from a completely different attack technique. The wrong mechanism is selected by
    excluding any mechanism whose keywords appear in the domain (action names, predicates,
    or exploit-by constants).
    """
    ALL_MECHANISMS = [
        {"prefix": "sql-injection", "keywords": ["sql", "database", "query"],
         "predicates": ["sql-query-crafted", "sql-payload-injected", "database-accessed",
                        "sql-response-received", "sql-data-exfiltrated"]},
        {"prefix": "xss", "keywords": ["xss", "script", "cross-site"],
         "predicates": ["xss-payload-crafted", "script-injected-into-page", "victim-browser-executes-script",
                        "session-cookie-stolen", "xss-exfiltration-complete"]},
        {"prefix": "buffer-overflow", "keywords": ["buffer-overflow", "shellcode", "return-address"],
         "predicates": ["overflow-payload-crafted", "stack-buffer-overwritten", "return-address-overwritten",
                        "shellcode-injected", "arbitrary-code-executed"]},
        {"prefix": "ldap-injection", "keywords": ["ldap", "directory-service"],
         "predicates": ["ldap-query-crafted", "ldap-filter-injected", "directory-entry-accessed",
                        "ldap-response-received", "ldap-data-exfiltrated"]},
        {"prefix": "ssrf", "keywords": ["ssrf", "server-side-request"],
         "predicates": ["ssrf-url-crafted", "internal-request-triggered", "internal-service-accessed",
                        "ssrf-response-received", "internal-data-leaked"]},
        {"prefix": "command-injection", "keywords": ["command-injection", "os-command", "shell"],
         "predicates": ["command-payload-crafted", "shell-command-injected", "os-command-executed",
                        "command-output-captured", "system-compromised"]},
    ]

    if len(actions) <= 2:
        raise ValueError("Need at least 3 actions")

    # Detect actual mechanism from domain content (action names, predicates, constants)
    domain_lower = domain.lower()
    eligible = [m for m in ALL_MECHANISMS
                if not any(kw in domain_lower for kw in m["keywords"])]
    if not eligible:
        raise ValueError("All wrong mechanisms match keywords in the domain — cannot select a wrong one")
    mechanism = rng.choice(eligible)

    # Collect non-structural predicate names from mid-chain actions' effects
    protected = set(STRIDE_PREDICATES) | {
        "exposes-attack-surface", "exploit-by", "total-cost", "version", "port",
        "increase", "decrease", "and", "not", "or",
    }
    mid_actions = actions[1:-1]

    # Build rename map: original predicate → wrong-mechanism predicate
    original_preds = []
    for action in mid_actions:
        eff_preds = re.findall(r'\((?:not\s+\()?([\w][\w-]*)', action.effect)
        for p in eff_preds:
            if p not in protected and p not in original_preds:
                original_preds.append(p)

    pred_rename_map = {}
    for i, orig in enumerate(original_preds):
        wrong_pred = mechanism["predicates"][i % len(mechanism["predicates"])]
        pred_rename_map[orig] = f"{wrong_pred}-{i}"

    mutated = domain

    # Rename mid-chain action names
    action_renames = []
    for i, action in enumerate(mid_actions):
        new_name = f"attacker-{mechanism['prefix']}-step-{i+1}"
        new_text = action.full_text.replace(action.name, new_name, 1)
        mutated = mutated.replace(action.full_text, new_text, 1)
        action_renames.append(f"{action.name} → {new_name}")

    # Rename predicates globally — includes predicates block, Step 0 effects, and final
    # action preconditions. This is intentional: ensures PDDL consistency after renaming.
    # Use lookaround that treats '-' as part of identifiers (PDDL names use hyphens)
    for old_pred, new_pred in pred_rename_map.items():
        pattern = re.compile(rf'(?<![\w-]){re.escape(old_pred)}(?![\w-])')
        mutated = pattern.sub(new_pred, mutated)

    return MutationResult(
        mutated_domain=mutated,
        mutation_type="replace_exploitation_mechanism",
        description=f"Replaced {len(action_renames)} action names and {len(pred_rename_map)} predicates with '{mechanism['prefix']}' mechanism (V2 violation)",
        expected_label="NEGATIVE",
        changed_action=", ".join(action_renames[:3]) + ("..." if len(action_renames) > 3 else ""),
        details={
            "wrong_mechanism": mechanism["prefix"],
            "actions_renamed": len(action_renames),
            "predicates_renamed": len(pred_rename_map),
            "predicate_sample": dict(list(pred_rename_map.items())[:5]),
        },
    )


def scramble_action_names(domain: str, actions: list[PDDLAction],
                          rng: random.Random) -> MutationResult:
    """Replace action names with opaque identifiers, removing actor-verb pattern (N1 violation)."""
    mutated = domain
    renamed = []

    for i, action in enumerate(actions):
        new_name = f"op-{i:02d}-proc"
        mutated = mutated.replace(f"(:action {action.name}", f"(:action {new_name}", 1)
        renamed.append(f"{action.name} → {new_name}")

    return MutationResult(
        mutated_domain=mutated,
        mutation_type="scramble_action_names",
        description=f"Renamed {len(actions)} actions to opaque identifiers (N1 violation)",
        expected_label="NEGATIVE",
        changed_action="all actions",
        details={"renamed_count": len(actions), "sample": renamed[:3]},
    )


def scramble_predicate_names(domain: str, actions: list[PDDLAction],
                             rng: random.Random) -> MutationResult:
    """Replace predicate names with opaque identifiers, removing descriptive semantics (N2 violation).

    Only renames non-STRIDE, non-structural predicates to preserve PDDL validity.
    """
    # Find all predicate names in the predicates block
    pred_block = _extract_sexp(domain, "(:predicates")
    if not pred_block:
        raise ValueError("No predicates block found")

    # Extract predicate names (first token after opening paren in each declaration)
    pred_names = re.findall(r'\((\w[\w-]*)\s+\?', pred_block)

    # Don't rename STRIDE predicates, exposes-attack-surface, exploit-by, or total-cost
    protected = set(STRIDE_PREDICATES) | {
        "exposes-attack-surface", "exploit-by", "total-cost", "version", "port",
    }
    renamable = [p for p in set(pred_names) if p not in protected]

    if not renamable:
        raise ValueError("No renamable predicates found")

    # Create mapping
    rename_map = {}
    for i, pred in enumerate(sorted(renamable)):
        rename_map[pred] = f"pred-{i:03d}"

    mutated = domain
    renamed_count = 0
    for old_name, new_name in rename_map.items():
        # Use lookaround that treats '-' as part of PDDL identifiers
        pattern = re.compile(rf'(?<![\w-]){re.escape(old_name)}(?![\w-])')
        new_text = pattern.sub(new_name, mutated)
        if new_text != mutated:
            renamed_count += 1
            mutated = new_text

    return MutationResult(
        mutated_domain=mutated,
        mutation_type="scramble_predicate_names",
        description=f"Renamed {renamed_count} predicates to opaque identifiers (N2 violation)",
        expected_label="NEGATIVE",
        changed_action="all predicates",
        details={"renamed_count": renamed_count, "sample": dict(list(rename_map.items())[:5])},
    )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

MUTATIONS = {
    "delete_critical_action": delete_critical_action,
    "delete_random_precondition": delete_random_precondition,
    "swap_action_effects": swap_action_effects,
    "remove_stride_goal": remove_stride_goal,
    "corrupt_exposure_action": corrupt_exposure_action,
    "merge_consecutive_actions": merge_consecutive_actions,
    "inject_capability_violation": inject_capability_violation,
    "replace_with_abstract_action": replace_with_abstract_action,
    "replace_exploitation_mechanism": replace_exploitation_mechanism,
    "scramble_action_names": scramble_action_names,
    "scramble_predicate_names": scramble_predicate_names,
}


def apply_mutation(domain_text: str, mutation_type: str | None = None,
                   seed: int | None = None) -> MutationResult:
    """
    Apply a mutation to a PDDL domain string.

    Args:
        domain_text: raw PDDL domain string
        mutation_type: one of MUTATIONS keys, or None for random
        seed: random seed for reproducibility
    """
    rng = random.Random(seed)
    actions = parse_actions(domain_text)

    if mutation_type is None:
        mutation_type = rng.choice(list(MUTATIONS.keys()))

    if mutation_type not in MUTATIONS:
        raise ValueError(f"Unknown mutation: {mutation_type}. Choose from {list(MUTATIONS.keys())}")

    return MUTATIONS[mutation_type](domain_text, actions, rng)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="PDDL Domain Mutator")
    parser.add_argument("domain", type=Path, help="Path to domain.pddl")
    parser.add_argument("--mutation", type=str, default=None,
                        choices=list(MUTATIONS.keys()),
                        help="Mutation type (random if omitted)")
    parser.add_argument("--output", "-o", type=Path, default=None,
                        help="Output file for mutated domain")
    parser.add_argument("--all", action="store_true",
                        help="Apply all mutation types and save each")
    parser.add_argument("--outdir", type=Path, default=None,
                        help="Output directory for --all mode")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed (default: 42)")
    parser.add_argument("--verify", action="store_true",
                        help="Verify solvability with Metric-FF (needs problem.pddl in same dir)")
    args = parser.parse_args()

    domain_text = args.domain.read_text(encoding="utf-8")

    if args.all:
        outdir = args.outdir or args.domain.parent / "mutations"
        outdir.mkdir(parents=True, exist_ok=True)
        results = []
        for mt in MUTATIONS:
            try:
                result = apply_mutation(domain_text, mt, seed=args.seed)
                out_path = outdir / f"domain_{mt}.pddl"
                out_path.write_text(result.mutated_domain, encoding="utf-8")
                results.append(result)
                print(f"[OK]   {mt:30s}  label={result.expected_label:8s}  {result.description}")
            except Exception as e:
                print(f"[FAIL] {mt:30s}  {e}")

        if args.verify:
            _verify_results(results, outdir, args.domain.parent)

    else:
        result = apply_mutation(domain_text, args.mutation, seed=args.seed)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(result.mutated_domain, encoding="utf-8")
            print(f"Written to {args.output}")
        else:
            print(result.mutated_domain)
        print(f"\n--- Mutation metadata ---", file=sys.stderr)
        print(f"Type:     {result.mutation_type}", file=sys.stderr)
        print(f"Label:    {result.expected_label}", file=sys.stderr)
        print(f"Action:   {result.changed_action}", file=sys.stderr)
        print(f"Desc:     {result.description}", file=sys.stderr)


def _verify_results(results: list[MutationResult], outdir: Path, domain_dir: Path):
    """Verify mutations with Metric-FF."""
    problem_path = domain_dir / "problem.pddl"
    if not problem_path.exists():
        print(f"\n[SKIP] No problem.pddl found at {problem_path} — cannot verify")
        return

    # Find FF binary relative to this script
    tools_dir = Path(__file__).resolve().parent
    ff_path = tools_dir / "Metric-FF" / "ff"
    if not ff_path.exists():
        print(f"\n[SKIP] FF binary not found at {ff_path}")
        return

    import subprocess
    print(f"\n{'='*70}")
    print("Solvability verification with Metric-FF")
    print(f"{'='*70}")

    for result in results:
        domain_path = outdir / f"domain_{result.mutation_type}.pddl"
        try:
            proc = subprocess.run(
                [str(ff_path), "-o", str(domain_path), "-f", str(problem_path), "-s", "4", "-w", "4"],
                capture_output=True, text=True, timeout=30,
            )
            raw = proc.stdout + proc.stderr
            solvable = bool(re.findall(r"^\s*\d+:\s+.+$", raw, re.MULTILINE))
            unsolvable = "goal can be simplified to FALSE" in raw or "unsolvable" in raw.lower()

            if solvable:
                status = "SOLVABLE"
            elif unsolvable:
                status = "UNSOLVABLE"
            else:
                status = "UNKNOWN"

            expected = "SOLVABLE" if result.expected_label == "POSITIVE" else "UNSOLVABLE/CHANGED"
            match = "OK" if (solvable and result.expected_label == "POSITIVE") or \
                           (not solvable and result.expected_label == "NEGATIVE") else "MISMATCH"

            print(f"  {result.mutation_type:30s}  FF={status:10s}  expected={expected:20s}  [{match}]")
        except Exception as e:
            print(f"  {result.mutation_type:30s}  ERROR: {e}")


if __name__ == "__main__":
    main()
