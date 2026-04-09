# Instruction Ablation Analysis

> **Test setup:** CVE-2024-47072 (XStream BinaryStreamDriver DoS)
> **Date:** 2026-04-07

## Instruction Tier System

| Tier | Count | Visibility | Description |
|---|---|---|---|
| **BMI** (Big Model Instructions) | 6 | Always on (zero-shot & few-shot) | High value for all models — reasoning strategy, quality constraints, structural constraints |
| **SMI** (Small Model Instructions) | 5 | Always on in zero-shot, optional in few-shot | High value for weaker models — format, naming, basic structure rules that large models follow naturally |
| **OI** (Optional Instructions) | 3 | Always optional | Low value / situational |

## Instruction Reference

### BMI (6)

| ID | Short Name | Content |
|---|---|---|
| **BMI1** | Effect backward reasoning | Action effects must encode exactly the state changes that downstream actions depend on. Reason backwards from downstream preconditions. |
| **BMI2** | Action atomicity | Each action must represent a single minimal, real-world-executable attack step that cannot be decomposed further. |
| **BMI3** | Exposure structure | Exposure action preconditions must follow (i)(ii)(iii)(iv+) structure. Effects must include exposes-attack-surface, exploit-by, vulnerable-element. |
| **BMI4** | Action feasibility | No action may assume attacker capabilities excluded by the adversarial model or not established through prior actions. |
| **BMI5** | Semantic executability | Path must be genuinely executable, no implicit jumps. Prohibited jumps: network traversal without access, privilege escalation without foothold, credential use without acquisition, artifact use without creation, user-interaction trigger without luring step. |
| **BMI6** | Attack stage template | Pattern: exposure-confirmation -> [payload-creation ->] [payload-delivery ->] ... -> vulnerability-trigger -> security-impact. |

### SMI (5)

| ID | Short Name | Content |
|---|---|---|
| **SMI1** | Precondition satisfiability | Every action's preconditions must be satisfiable from initial state or prior effects. |
| **SMI2** | Actor naming | Actor is one of: attacker, target-system, user, infrastructure. Names must be verbalizable as attack narrative. |
| **SMI3** | Step 0 / Step End structure | Exactly one Step 0 (exposure) and one Step End (impact). STRIDE goal only in Step End. |
| **SMI4** | Predicate naming | Boolean predicates use is-xxx naming. STRIDE vocabulary for goals. Verb-based naming for relationships. |
| **SMI5** | Precondition minimalism | Preconditions must contain only the minimal set of conditions strictly necessary. |

### OI (3)

| ID | Short Name | Content |
|---|---|---|
| **OI1** | Path filtering | Output the single highest-threat path with fewest preconditions. |
| **OI2** | Predicate taxonomy | Six-category taxonomy: Environment, Vulnerability exposure, Adversary capability, Artifact/Delivery, Target state-change, Security outcome. |
| **OI3** | Parameter generalization | Parameters should support generalization across multiple CVEs. |

---

## Zero-shot Analysis (Claude Opus 4.6)

### Method

Baseline: ROLE + TASK + ADVERSARIAL MODEL + OUTPUT TEMPLATE, **no instructions**. Then add single instructions per test.

### Baseline Output

- **3 actions**, 5 exposure preconditions, 0 `not` conditions
- Broken causal chain, coarse type system

### Ground Truth

- **9 actions**, 22 exposure preconditions (10 positive + 12 `not`), 35 predicates, 16 types

### Single Instruction Impact (Claude Opus)

| Instruction | Action Count | Exposure Improvement | Causal Chain | Independent Contribution | Necessary? |
|---|---|---|---|---|---|
| **Baseline** | 3 | — | broken | — | — |
| **BMI1** | 5 | No | Yes | Backward reasoning drives decomposition | **Yes** |
| **BMI2** | 7 | No | Yes | Atomicity (finest decomposition) | **Yes** |
| **BMI3** | 3 | Yes (5→11 preconditions, (i)(ii)(iii)) | No | Irreplaceable exposure structure | **Yes** |
| **BMI4** | 3 | Partial (+3 not conditions) | No | Security control conditions | **Yes** |
| **BMI5** | 6 | No | Yes | Prohibits semantic jumps | **Yes** |
| **BMI6** | 8 | No | Yes (strongest) | Attack stage template | **Yes** |
| **SMI1** | 3 | No | No | None (large model naturally complies) | Redundant (large model) |
| **SMI2** | 3 | No | No | Minor naming adjustment | Redundant (large model) |
| **SMI3** | 3 | No | No | None (large model naturally complies) | Redundant (large model) |
| **SMI4** | 3 | No | No | Naming style only | Redundant (large model) |
| **SMI5** | 3 | No | No | None (possibly negative) | Redundant (large model) |
| **OI1** | 3 | No | No | None | Redundant |
| **OI2** | 3 | No | No | Minimal impact | Redundant |
| **OI3** | 3 | No | No | Minimal impact | Redundant |

### Problem Classification

| Problem | Primary fix | Secondary fix |
|---|---|---|
| Steps compressed | BMI2 (atomicity) | BMI1 (backward reasoning), BMI5 (semantic executability), BMI6 (stage template) |
| Causal chain broken | BMI1 (backward reasoning) | BMI5 (semantic executability) |
| Exposure under-specified | BMI3 (exposure structure) | BMI4 (feasibility) |
| Type system too coarse | BMI3 (indirectly) | — |

---

## Cross-Model Validation: Qwen-plus

### Data Source

Actual LLM outputs from Qwen-plus ablation experiments. Qwen always ran with all original mandatory instructions active. Only optional instruction combinations varied.

### Qwen Baseline (all mandatory instructions, no optional)

- **2 actions** (vs Claude baseline 3, vs ground truth 9)
- **4 exposure preconditions**, 0 `not` conditions
- Missing `:fluents` in requirements
- 7 predicates, 7 types

### Common Issues Across All Qwen Outputs

1. **Missing `:fluents`** in every file — Metric-FF would reject
2. **2-3 actions** max vs ground truth's 9 — severe step compression persists despite instructions
3. **0-2 `not` conditions** vs ground truth's 12
4. **Undeclared predicates** in multiple files
5. **One file produces unsolvable plan** (Step 1 deletes predicate Step End requires)

### Key Finding: Instruction Effectiveness by Model Tier

| Dimension | Claude Opus | Qwen-plus | Implication |
|---|---|---|---|
| BMI2 (atomicity) effective? | Yes (3→7 actions) | **No — still 2 actions** | BMI2 alone insufficient for mid-tier models |
| BMI3 (exposure) effective? | Yes (5→11 preconditions) | Partial — comment structure learned, content sparse | BMI3 partially effective for weaker models |
| SMI1 (satisfiability) needed? | No | **Yes — unsolvable plan generated** | SMI1 necessary for weaker models |
| SMI4 (naming) needed? | No | Yes — naming inconsistent | SMI4 matters for weaker models |
| Syntax correctness | Naturally correct | **Pervasive issues** | Weaker models need all SMI instructions |
| SMI5 value | Redundant / negative | **Most effective optional instruction for Qwen** | SMI5 valuable for weaker models |

### Revised Necessity by Model Tier

| Instruction | Large model | Mid-tier model |
|---|---|---|
| BMI1-BMI6 | **All necessary** | **All necessary** (but some insufficient alone) |
| SMI1 | Redundant | **Necessary** |
| SMI2 | Redundant | Likely necessary |
| SMI3 | Redundant | Likely necessary |
| SMI4 | Redundant | Likely necessary |
| SMI5 | Redundant / negative | **High value** |
| OI1-OI3 | Low value | Low value |

---

## Few-shot Analysis (Claude Opus, 2-shot)

### Setup

2 few-shot examples (CVE-2023-2976: 8 actions, CVE-2022-1471: 14 actions), CVE-2024-47072 as query.

### Few-shot + All BMI Baseline

| Metric | Ground Truth | Few-shot + BMI | Zero-shot (no instructions) |
|---|---|---|---|
| Actions | 9 | **8** | 3 |
| Exposure preconditions | 22 | **14** | 5 |
| `not` conditions | 12 | **6** | 0 |
| Predicates | 35 | **33** | ~10 |
| Types | 16 | **13** | 3 |
| `:fluents` | Yes | **Yes** | No |
| Syntax issues | None | **None** | N/A |

### BMI Removal Impact in Few-shot

| Removed BMI | Actions | Exposure | Impact | Still necessary? |
|---|---|---|---|---|
| None (baseline) | 8 | 14 precond, 6 not | — | — |
| -BMI1 (backward reasoning) | 7 | unchanged | Effect slightly bloated | Yes (quality constraint) |
| -BMI2 (atomicity) | 6 | unchanged | 2 step pairs merged | Yes (quality constraint) |
| -BMI3 (exposure structure) | 8 | **7 precond, 2 not** | Exposure degrades significantly | **Yes — irreplaceable** |
| -BMI4 (feasibility) | 8 | unchanged | Precondition completeness drops | **Yes — irreplaceable** |
| -BMI5 (semantic executability) | 8 | unchanged | Near-zero change | Covered by examples |
| -BMI6 (stage template) | 7 | unchanged | Missing 1 step | Covered by examples |

### SMI Value in Few-shot

All SMI instructions (SMI1-SMI5) showed **zero incremental value** for large models in few-shot mode — examples fully cover format and naming constraints.

### Few-shot Instruction Summary

| Category | Instructions | Few-shot necessity |
|---|---|---|
| **Always necessary** | BMI1-BMI4 | Reasoning strategy + quality constraints — examples cannot teach these |
| **Necessary (conservative)** | BMI5 | Quality constraint — other large models may need it |
| **Covered by examples** | BMI6, SMI1-SMI5, OI1-OI3 | Format/structure/naming — examples directly demonstrate these |

---

## Conclusions

1. **BMI instructions are universally necessary** across zero-shot and few-shot for all model tiers. They encode reasoning strategies and quality constraints that examples alone cannot teach.

2. **SMI instructions are model-tier dependent.** Large models naturally comply; mid-tier and small models need them. In zero-shot they should always be on. In few-shot they can be selectively enabled based on model capability.

3. **OI instructions have minimal impact** across all tested conditions and models.

4. **Instruction effectiveness is model-dependent.** Ablation results from one model cannot be transferred to another. Full cross-model experiments are required.

5. **Mid-tier models may ignore instructions they "understand."** Qwen had atomicity instructions active yet still produced 2-action paths. For weaker models, instruction reinforcement (multiple overlapping instructions) may be necessary.

6. **A post-generation syntax validation step is essential** for weaker models, which consistently produce syntax errors (undeclared predicates, missing requirements, free variables).
