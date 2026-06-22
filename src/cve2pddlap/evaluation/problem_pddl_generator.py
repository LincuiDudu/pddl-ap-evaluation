"""
Generate problem.pddl deterministically from domain.pddl.
No LLM needed — purely code-based.

Algorithm:
1. Parse domain → types, constants, actions (params, preconditions, effects)
2. Collect all positive preconditions and all positive effects across actions
3. Init = positive preconditions NOT produced by any effect
4. Version constraints → extract and pick a valid value (first range lower bound)
5. Objects = one instance per parameter type (excluding constant types)
6. Goal = STRIDE predicate from last action's effect
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


STRIDE_PREDICATES = frozenset({
    "spoofing", "tampering", "repudiation",
    "information-disclosure", "denial-of-service", "elevation-of-privilege",
})


# ---------------------------------------------------------------------------
# S-expression utilities
# ---------------------------------------------------------------------------

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


def _tokenize_sexp(sexp: str) -> list:
    """Convert an S-expression string into a nested list structure."""
    tokens = sexp.replace('(', ' ( ').replace(')', ' ) ').split()
    stack: list[list] = [[]]
    for tok in tokens:
        if tok == '(':
            new = []
            stack[-1].append(new)
            stack.append(new)
        elif tok == ')':
            stack.pop()
        else:
            stack[-1].append(tok)
    return stack[0][0] if stack[0] else []


# ---------------------------------------------------------------------------
# Domain parsing
# ---------------------------------------------------------------------------

@dataclass
class Action:
    name: str
    parameters: list[tuple[str, str]]  # [(var_name, type_name), ...]
    precondition_raw: str
    effect_raw: str


def _parse_types(domain: str) -> dict[str, str]:
    """Parse (:types ...) → {child: parent} (parent="" if no parent)."""
    block = _extract_sexp(domain, '(:types')
    if not block:
        return {}
    # Remove outer parens and tag
    inner = block[len('(:types'):].rstrip(')')
    types_map: dict[str, str] = {}
    for line in inner.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        if ' - ' in line:
            parts = line.split(' - ')
            children = parts[0].split()
            parent = parts[1].strip()
            for c in children:
                types_map[c.strip()] = parent
        else:
            for t in line.split():
                types_map[t.strip()] = ''
    return types_map


def _parse_constants(domain: str) -> dict[str, str]:
    """Parse (:constants ...) → {name: type}."""
    block = _extract_sexp(domain, '(:constants')
    if not block:
        return {}
    inner = block[len('(:constants'):].rstrip(')')
    constants: dict[str, str] = {}
    for line in inner.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        if ' - ' in line:
            parts = line.split(' - ')
            names = parts[0].split()
            ctype = parts[1].strip()
            for n in names:
                constants[n.strip()] = ctype
    return constants


def _parse_predicate_types(domain: str) -> set[str]:
    """Extract all types referenced in (:predicates ...) declarations."""
    block = _extract_sexp(domain, '(:predicates')
    if not block:
        return set()
    types_used: set[str] = set()
    # Match patterns like "?Var - type-name" in predicate declarations
    for m in re.finditer(r'\?\w+\s+-\s+([\w-]+)', block):
        types_used.add(m.group(1).lower())
    return types_used


def _parse_function_types(domain: str) -> set[str]:
    """Extract types referenced in (:functions ...) — like (port ?Port)."""
    block = _extract_sexp(domain, '(:functions')
    if not block:
        return set()
    types_used: set[str] = set()
    for m in re.finditer(r'\?\w+\s+-\s+([\w-]+)', block):
        types_used.add(m.group(1).lower())
    return types_used


def _parse_actions(domain: str) -> list[Action]:
    """Extract all actions with parameters, precondition, effect."""
    actions = []
    pattern = re.compile(r'\(:action\s+([\w-]+)')
    for m in pattern.finditer(domain):
        action_name = m.group(1)
        action_block = _extract_sexp(domain[m.start():], '(:action')
        if not action_block:
            continue

        # Parameters - use robust regex to find ?Var - Type pairs
        params = []
        params_match = re.search(r':parameters\s*\(', action_block)
        if params_match:
            # Find the balanced paren content after :parameters
            pstart = params_match.end() - 1  # position of '('
            depth = 0
            pend = pstart
            for i in range(pstart, len(action_block)):
                if action_block[i] == '(':
                    depth += 1
                elif action_block[i] == ')':
                    depth -= 1
                    if depth == 0:
                        pend = i
                        break
            param_str = action_block[pstart + 1:pend]
            # Remove comments (;; ...)
            param_str = re.sub(r';;[^\n]*', '', param_str)
            # Find all ?Var - Type pairs, handling edge cases like:
            # "?Var -type" (no space after dash)
            # "?Var - type)" (trailing paren from malformed input)
            for vm in re.finditer(r'(\?\S+)\s+-\s*(\S+)', param_str):
                var = vm.group(1)
                typ = vm.group(2).rstrip(')').lower()  # normalize type to lowercase, strip trailing parens
                params.append((var, typ))

        # Precondition — extract the (and ...) after :precondition
        prec_raw = ''
        prec_pos = action_block.find(':precondition')
        if prec_pos != -1:
            prec_and = _extract_sexp(action_block[prec_pos:], '(')
            prec_raw = prec_and if prec_and else ''

        # Effect — extract the (and ...) after :effect
        eff_raw = ''
        eff_pos = action_block.find(':effect')
        if eff_pos != -1:
            eff_and = _extract_sexp(action_block[eff_pos:], '(')
            eff_raw = eff_and if eff_and else ''

        actions.append(Action(
            name=action_name,
            parameters=params,
            precondition_raw=prec_raw,
            effect_raw=eff_raw,
        ))
    return actions


# ---------------------------------------------------------------------------
# Extract predicates from preconditions/effects
# ---------------------------------------------------------------------------

def _extract_positive_predicates(sexp_str: str) -> list[str]:
    """
    Extract all positive ground-level predicates from a precondition/effect block.
    Skips (not ...), (increase ...), (= (version ...) ...), (= (total-cost) ...).
    For (or ...) branches, include predicates from the FIRST branch.
    Returns predicate strings like "(pred ?a ?b)".
    """
    if not sexp_str:
        return []
    results = []
    tree = _tokenize_sexp(sexp_str)

    def _walk(node):
        if not isinstance(node, list) or not node:
            return
        head = node[0] if isinstance(node[0], str) else None

        if head in ('and', ':precondition', ':effect'):
            for child in node[1:]:
                _walk(child)
        elif head == 'or':
            # For init computation, include predicates from the FIRST branch
            # of each OR. This ensures at least one branch is satisfiable.
            if len(node) > 1:
                first_branch = node[1]
                _walk(first_branch)
        elif head == 'not':
            pass  # skip negated predicates
        elif head == 'increase':
            pass
        elif head in ('=', '>=', '<=', '>', '<'):
            pass  # skip numeric comparisons (handled by version extraction)
        elif head and not head.startswith('?'):
            # This is a predicate application
            results.append('(' + ' '.join(_flatten(node)) + ')')
        else:
            for child in node[1:]:
                _walk(child)

    _walk(tree)
    return results


def _extract_effect_predicates(sexp_str: str) -> list[str]:
    """Extract predicate names from effects (for tracking what gets established)."""
    if not sexp_str:
        return []
    results = []
    tree = _tokenize_sexp(sexp_str)

    def _walk(node):
        if not isinstance(node, list) or not node:
            return
        head = node[0] if isinstance(node[0], str) else None
        if head in ('and', ':effect'):
            for child in node[1:]:
                _walk(child)
        elif head == 'not':
            pass
        elif head == 'increase':
            pass
        elif head and not head.startswith('?') and head not in ('=', '>=', '<=', '>', '<'):
            results.append('(' + ' '.join(_flatten(node)) + ')')
        else:
            for child in node[1:]:
                _walk(child)

    _walk(tree)
    return results


def _flatten(node) -> list[str]:
    """Flatten a nested list to a flat list of strings."""
    if isinstance(node, str):
        return [node]
    result = []
    for item in node:
        result.extend(_flatten(item))
    return result


# ---------------------------------------------------------------------------
# Version constraint extraction
# ---------------------------------------------------------------------------

def _extract_version_constraints(sexp_str: str) -> list[tuple[str, list[tuple[str, int]]]]:
    """
    Extract version constraints from preconditions, including inside OR branches.
    Returns: [(variable_name, [(op, value), ...]), ...]
    e.g. [("?SpringFramework", [(">=", 5003000000), ("<=", 5003039000)])]

    For OR with multiple version ranges, collects constraints from the FIRST branch.
    """
    if not sexp_str:
        return []

    # First try to extract from the first OR branch containing version constraints
    tree = _tokenize_sexp(sexp_str)
    or_version_constraints: dict[str, list[tuple[str, int]]] = {}

    def _find_or_version_branches(node):
        """Find OR nodes containing version constraints and extract from first branch."""
        if not isinstance(node, list) or not node:
            return
        head = node[0] if isinstance(node[0], str) else None

        if head == 'or':
            # Check if any branch contains version constraints
            has_version = False
            for branch in node[1:]:
                branch_str = _sexp_to_string(branch)
                if 'version' in branch_str:
                    has_version = True
                    break

            if has_version and len(node) > 1:
                # Extract version constraints from the FIRST branch only
                first_branch = node[1]
                first_str = _sexp_to_string(first_branch)
                pattern = re.compile(
                    r'\((=|>=|<=|>|<)\s+\(version\s+(\?[\w-]+)\)\s+(\d+)\)'
                )
                for m_vc in pattern.finditer(first_str):
                    op, var, val = m_vc.group(1), m_vc.group(2), int(m_vc.group(3))
                    or_version_constraints.setdefault(var, []).append((op, val))
                return  # Don't recurse into OR branches

        if head in ('and', ':precondition'):
            for child in node[1:]:
                _find_or_version_branches(child)

    _find_or_version_branches(tree)

    # Also extract top-level version constraints (outside OR)
    results: dict[str, list[tuple[str, int]]] = dict(or_version_constraints)

    # Match patterns at the top level (not inside or)
    # We need to exclude those inside or branches
    # Simple approach: extract all, then if we already have constraints for a var from OR, skip
    pattern = re.compile(
        r'\((=|>=|<=|>|<)\s+\(version\s+(\?[\w-]+)\)\s+(\d+)\)'
    )
    for m_vc in pattern.finditer(sexp_str):
        op, var, val = m_vc.group(1), m_vc.group(2), int(m_vc.group(3))
        if var not in results:
            results.setdefault(var, []).append((op, val))
        # If already from OR, don't add duplicates from full scan

    return [(var, constraints) for var, constraints in results.items()]


def _extract_port_constraints(sexp_str: str) -> list[tuple[str, int]]:
    """
    Extract port constraints from preconditions.
    Handles patterns like (= (port ?HTTPInterface) 80) or inside OR branches.
    Returns: [(variable_name, value), ...]
    Takes the first matching value.
    """
    if not sexp_str:
        return []

    results: list[tuple[str, int]] = []
    seen_vars: set[str] = set()

    # Match patterns like (= (port ?Var) 80)
    pattern = re.compile(
        r'\(=\s+\(port\s+(\?[\w-]+)\)\s+(\d+)\)'
    )
    for m_pc in pattern.finditer(sexp_str):
        var, val = m_pc.group(1), int(m_pc.group(2))
        if var.lower() not in seen_vars:
            results.append((var, val))
            seen_vars.add(var.lower())

    return results


def _sexp_to_string(node) -> str:
    """Convert a parsed S-expression node back to a string."""
    if isinstance(node, str):
        return node
    return '(' + ' '.join(_sexp_to_string(x) for x in node) + ')'


def _pick_version_value(constraints: list[tuple[str, int]]) -> int:
    """Pick a concrete version value satisfying the constraints.

    Uses the lower bound when available. When only an upper bound exists,
    picks a value with margin to avoid Metric-FF float precision issues
    with large numbers close to comparison boundaries.
    """
    # Check for exact equality first
    for op, val in constraints:
        if op == '=':
            return val

    # Find lower bound and upper bound
    lower = None
    upper = None
    for op, val in constraints:
        if op == '>=' and (lower is None or val > lower):
            lower = val
        elif op == '>' and (lower is None or val + 1 > lower):
            lower = val + 1
        elif op == '<=' and (upper is None or val < upper):
            upper = val
        elif op == '<' and (upper is None or val - 1 < upper):
            upper = val - 1

    if lower is not None:
        return lower
    if upper is not None:
        # Use margin to avoid float precision issues in Metric-FF
        # Version encoding is typically: major*10^9 + minor*10^6 + patch*10^3
        # Subtracting 1000 gives one patch version below
        safe_val = upper - 1000
        return max(safe_val, 1)
    return 1000000  # fallback


# ---------------------------------------------------------------------------
# Object generation
# ---------------------------------------------------------------------------

def _compute_objects(
    actions: list[Action],
    types_map: dict[str, str],
    constants: dict[str, str],
    predicate_types: set[str] | None = None,
) -> tuple[list[tuple[str, str]], dict[str, str], dict[str, list[str]]]:
    """
    Generate one object instance per unique type across all action parameters.
    Also ensures types referenced in predicates have at least one object
    (required by Metric-FF to avoid "unknown or empty type" errors).
    Handles type inheritance: if child and parent both appear, only create child object.
    Returns ([(object_name, type_name), ...], type_to_obj mapping, type_to_all_objs mapping).
    """
    constant_types = set(constants.values())

    # Collect unique types from parameters (skip constant types)
    param_types: set[str] = set()
    for action in actions:
        for var, typ in action.parameters:
            if typ not in constant_types:
                param_types.add(typ)

    # Build full ancestor chain for each type
    def get_ancestors(typ: str) -> list[str]:
        """Get all ancestor types."""
        ancestors = []
        current = typ
        while current in types_map and types_map[current]:
            parent = types_map[current]
            ancestors.append(parent)
            current = parent
        return ancestors

    # Build children map for the full type hierarchy
    def get_all_descendants(typ: str) -> set[str]:
        """Get all descendant types."""
        descendants = set()
        children = [t for t, p in types_map.items() if p == typ]
        for child in children:
            descendants.add(child)
            descendants.update(get_all_descendants(child))
        return descendants

    # Remove parent types if a child type also exists
    children_of: dict[str, set[str]] = {}  # parent → {child types in param_types}
    for typ in param_types:
        for ancestor in get_ancestors(typ):
            if ancestor in param_types:
                children_of.setdefault(ancestor, set()).add(typ)

    leaf_types = param_types - set(children_of.keys())

    # Build type_to_obj: map each type (including parents) to an object name
    type_to_obj: dict[str, str] = {}
    # Also track ALL objects that can satisfy a given type (for parent types with multiple children)
    type_to_all_objs: dict[str, list[str]] = {}
    objects = []

    def _make_obj_name(typ: str) -> str:
        if typ == 'target-system':
            return 'SEFA'
        elif typ == 'attacker':
            return 'attacker1'
        elif typ == 'user':
            return 'user1'
        else:
            clean = typ.replace(' ', '-')
            return f'{clean}_SEFA'

    for typ in sorted(leaf_types):
        obj_name = _make_obj_name(typ)
        objects.append((obj_name, typ))
        type_to_obj[typ] = obj_name
        type_to_all_objs.setdefault(typ, []).append(obj_name)

        # Also map parent types to this object
        for ancestor in get_ancestors(typ):
            if ancestor in param_types:
                if ancestor not in type_to_obj:
                    type_to_obj[ancestor] = obj_name
                type_to_all_objs.setdefault(ancestor, []).append(obj_name)

    # Ensure types used in predicates have at least one object
    # This prevents Metric-FF "unknown or empty type" errors
    if predicate_types:
        # First, collect existing object types (exact type names from objects list)
        existing_obj_types = {typ for _, typ in objects}

        for pred_type in sorted(predicate_types):
            if pred_type in constant_types:
                continue

            # Check if this exact type or any descendant has an object
            has_exact_object = pred_type in existing_obj_types
            if not has_exact_object:
                for desc in get_all_descendants(pred_type):
                    if desc in existing_obj_types:
                        has_exact_object = True
                        # Map this type to the descendant's object
                        if pred_type not in type_to_obj:
                            type_to_obj[pred_type] = type_to_obj[desc]
                            type_to_all_objs.setdefault(pred_type, []).append(type_to_obj[desc])
                        break

            if not has_exact_object:
                # Need to create an object for this type
                # Metric-FF requires at least one object per type used in predicates
                # If this type has children in types_map, use a child type instead
                # (avoids ENHSP issues with parent-only types like 'file')
                actual_type = pred_type
                children = [t for t, p in types_map.items() if p == pred_type]
                if children:
                    actual_type = children[0]
                obj_name = _make_obj_name(actual_type)
                # Avoid duplicate object names
                existing_names = {name for name, _ in objects}
                if obj_name not in existing_names:
                    objects.append((obj_name, actual_type))
                    type_to_obj[pred_type] = obj_name
                    type_to_all_objs.setdefault(pred_type, []).append(obj_name)

    return objects, type_to_obj, type_to_all_objs


# ---------------------------------------------------------------------------
# Init state computation
# ---------------------------------------------------------------------------

def _compute_init(
    actions: list[Action],
    type_to_obj: dict[str, str],
    type_to_all_objs: dict[str, list[str]],
    constants: dict[str, str],
    version_constraints: list[tuple[str, list[tuple[str, int]]]],
    port_constraints: list[tuple[str, int]] | None = None,
) -> list[str]:
    """
    Compute the :init predicates.
    Process actions sequentially: for each action, its preconditions that are NOT
    established by any PREVIOUS action's effects must be in init.
    """
    constant_types = set(constants.values())

    # Build variable → object name mapping (case-insensitive for variable names)
    # Also build var → type mapping so we can handle parent types
    var_to_obj: dict[str, str] = {}
    var_to_type: dict[str, str] = {}

    for action in actions:
        for var, typ in action.parameters:
            var_lower = var.lower()
            if typ in type_to_obj:
                var_to_obj[var_lower] = type_to_obj[typ]
                var_to_type[var_lower] = typ
            elif typ in constant_types:
                for cname, ctype in constants.items():
                    if ctype == typ:
                        var_to_obj[var_lower] = cname
                        var_to_type[var_lower] = typ
                        break

    # Also add constants directly
    for cname, ctype in constants.items():
        var_to_obj[cname.lower()] = cname

    # Process actions sequentially: track cumulative effects
    init_preds: list[str] = []
    seen: set[str] = set()
    cumulative_effects: set[str] = set()

    for action in actions:
        # Check preconditions against cumulative effects so far
        for pred in _extract_positive_predicates(action.precondition_raw):
            grounded_list = _ground_predicate_all(pred, var_to_obj, var_to_type, type_to_all_objs)
            for grounded in grounded_list:
                # Skip predicates with unresolved variables
                if '?' in grounded:
                    continue
                if grounded not in cumulative_effects and grounded not in seen:
                    init_preds.append(grounded)
                    seen.add(grounded)

        # Add this action's effects to cumulative
        for pred in _extract_effect_predicates(action.effect_raw):
            grounded_list = _ground_predicate_all(pred, var_to_obj, var_to_type, type_to_all_objs)
            for g in grounded_list:
                cumulative_effects.add(g)

    # Add version assignments
    for var, constraints in version_constraints:
        var_lower = var.lower()
        obj = var_to_obj.get(var_lower, var.lstrip('?'))
        val = _pick_version_value(constraints)
        version_str = f'(= (version {obj}) {val})'
        if version_str not in seen:
            init_preds.append(version_str)
            seen.add(version_str)

    # Add port assignments
    if port_constraints:
        for var, val in port_constraints:
            var_lower = var.lower()
            obj = var_to_obj.get(var_lower, var.lstrip('?'))
            port_str = f'(= (port {obj}) {val})'
            if port_str not in seen:
                init_preds.append(port_str)
                seen.add(port_str)

    return init_preds


def _ground_predicate(pred_str: str, var_to_obj: dict[str, str]) -> str:
    """Replace ?Variables with object names in a predicate string (case-insensitive var matching)."""
    result = pred_str
    # Find all ?Variables in the predicate and replace them
    variables = re.findall(r'\?[\w-]+', result)
    for var in sorted(variables, key=lambda x: -len(x)):
        obj = var_to_obj.get(var.lower())
        if obj:
            result = result.replace(var, obj)
    return result


def _ground_predicate_all(
    pred_str: str,
    var_to_obj: dict[str, str],
    var_to_type: dict[str, str],
    type_to_all_objs: dict[str, list[str]],
) -> list[str]:
    """
    Ground a predicate, expanding parent-type variables to all possible child objects.
    Returns a list of grounded predicate strings.
    """
    # Find all variables in the predicate
    variables = re.findall(r'\?[\w-]+', pred_str)
    if not variables:
        return [pred_str]

    # For each variable, determine its possible groundings
    var_options: list[tuple[str, list[str]]] = []
    for var in sorted(set(variables), key=lambda x: -len(x)):
        var_lower = var.lower()
        typ = var_to_type.get(var_lower, '')
        all_objs = type_to_all_objs.get(typ, [])

        if len(all_objs) > 1:
            # Parent type with multiple children - expand to all
            var_options.append((var, all_objs))
        elif var_lower in var_to_obj:
            var_options.append((var, [var_to_obj[var_lower]]))
        else:
            # Unresolved variable - keep as is
            var_options.append((var, [var]))

    # Generate all combinations (for parent types with multiple children)
    results = [pred_str]
    for var, objs in var_options:
        new_results = []
        for r in results:
            for obj in objs:
                new_results.append(r.replace(var, obj))
        results = new_results

    return list(set(results))


# ---------------------------------------------------------------------------
# STRIDE goal extraction
# ---------------------------------------------------------------------------

def _extract_stride_goal(actions: list[Action]) -> str | None:
    """Find the STRIDE predicate from the last action's effects."""
    for action in reversed(actions):
        for pred in _extract_effect_predicates(action.effect_raw):
            tokens = pred.strip('()').split()
            if tokens and tokens[0] in STRIDE_PREDICATES:
                return tokens[0]
    return None


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def generate_problem(domain_pddl: str, save_path: str | None = None) -> str:
    """
    Generate a problem.pddl string from a domain.pddl string.

    Args:
        domain_pddl: Complete domain.pddl content.
        save_path: If provided, save the generated problem to this file path.

    Returns:
        Complete problem.pddl content.
    """
    types_map = _parse_types(domain_pddl)
    constants = _parse_constants(domain_pddl)
    actions = _parse_actions(domain_pddl)
    predicate_types = _parse_predicate_types(domain_pddl)

    if not actions:
        raise ValueError("No actions found in domain.pddl")

    # Objects — pass predicate types to ensure all referenced types have objects
    objects, type_to_obj, type_to_all_objs = _compute_objects(
        actions, types_map, constants, predicate_types
    )

    # Version constraints (from all preconditions)
    all_version_constraints = []
    # Port constraints (from all preconditions)
    all_port_constraints = []
    for action in actions:
        all_version_constraints.extend(
            _extract_version_constraints(action.precondition_raw)
        )
        all_port_constraints.extend(
            _extract_port_constraints(action.precondition_raw)
        )

    # Deduplicate: keep first constraints per variable
    seen_vars: set[str] = set()
    unique_vc = []
    for var, constraints in all_version_constraints:
        var_lower = var.lower()
        if var_lower not in seen_vars:
            unique_vc.append((var, constraints))
            seen_vars.add(var_lower)

    # Init
    init_preds = _compute_init(actions, type_to_obj, type_to_all_objs, constants,
                               unique_vc, all_port_constraints)

    # Goal
    stride_goal = _extract_stride_goal(actions)
    if not stride_goal:
        raise ValueError("No STRIDE goal predicate found in domain effects")

    # Extract domain name from domain.pddl
    m = re.search(r'\(define\s+\(domain\s+([\w-]+)\)', domain_pddl)
    domain_name = m.group(1) if m else 'AED'

    # Find the actual target-system object name (could be a subtype like tomcat-server_SEFA)
    target_obj = 'SEFA'
    # Check if 'target-system' has an object directly
    if 'target-system' in type_to_obj:
        target_obj = type_to_obj['target-system']
    else:
        # Find any subtype of target-system that has an object
        for typ, parent in types_map.items():
            if parent == 'target-system' and typ in type_to_obj:
                target_obj = type_to_obj[typ]
                break

    # Render
    problem_str = _render_problem(stride_goal, objects, init_preds, domain_name, target_obj)

    if save_path is not None:
        from pathlib import Path
        Path(save_path).write_text(problem_str, encoding='utf-8')

    return problem_str


def _render_problem(
    stride_goal: str,
    objects: list[tuple[str, str]],
    init_preds: list[str],
    domain_name: str = 'AED',
    target_obj: str = 'SEFA',
) -> str:
    """Render the problem.pddl string."""
    lines = []
    lines.append(f'(define (problem AEDI-{stride_goal})')
    lines.append(f'  (:domain {domain_name})')

    # Objects
    lines.append('  (:objects')
    for obj_name, typ in objects:
        lines.append(f'    {obj_name} - {typ}')
    lines.append('  )')

    # Init
    lines.append('  (:init')
    lines.append('    (= (total-cost) 0)')
    for pred in init_preds:
        lines.append(f'    {pred}')
    lines.append('  )')

    # Goal
    lines.append(f'  (:goal (and ({stride_goal} {target_obj})))')
    lines.append('  (:metric minimize (total-cost)))')
    lines.append('')

    return '\n'.join(lines)
