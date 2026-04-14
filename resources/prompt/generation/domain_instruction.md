# Domain Generation Instruction System

16 instructions across three tiers. Tier determines when an instruction is included in the prompt.

| Tier | Count | Zero-shot | Few-shot |
|------|-------|-----------|----------|
| BMI (Big Model Mandatory) | 9 | Always on (BMI1–BMI8 always; BMI9 always) | BMI1–BMI8 always; BMI9 SMI-level |
| SMI (Small Model Mandatory) | 4 | Always on | Optional (SMI-level or OI-level) |
| OI (Optional) | 3 | Controlled by `selected_oi` | Controlled by `selected_oi` |

**Few-shot visibility detail:**
- Always on: BMI1–BMI8
- SMI-level (included if selected): BMI9, SMI1, SMI2, SMI5
- OI-level (included if selected): SMI4, OI1, OI2, OI3

---

## BMI — Big Model Mandatory Instructions

**BMI1.** Action effects should preferably encode the state changes that downstream actions depend on. Reason backwards: ask what predicates the downstream actions' preconditions require, and prioritize encoding those. Avoid encoding low-level exploit mechanics unless they directly gate a future action. Effects should primarily represent attacker capability gains, such as privilege escalation, credential acquisition, service access, or lateral movement. Each action should preferably result in a single primary capability change and avoid introducing excessive system state changes.

**BMI2.** Action atomicity. Each action must represent a single minimal, real-world-executable attack step: a minimal attack primitive that exists in the real world. It cannot be decomposed into smaller independent attack steps, and must be expressible as a single sentence in an attack narrative. Each action must have explicitly defined preconditions and effects, and must be executable in practice when its preconditions are satisfied.

**BMI3.** The exposure action is the mandatory entry point. Its preconditions must encode only decidable and observable conditions characterizing vulnerability exposure, following the (i)(ii)(iii)(iv+) structure in the template. Its effects must always include: `exposes-attack-surface`, `exploit-by`, and `vulnerable-element` predicates.

**BMI4.** Action feasibility. No action may assume attacker capabilities that are excluded by the adversarial model or not established through prior actions. Preconditions of actions must fully encode the conditions that make the exploit feasible.

**BMI5.** Semantic executability. The attack path must not only be symbolically solvable but must represent a genuinely executable real-world attack sequence. Every transition between actions must correspond to a concrete attacker operation, no implicit jumps are allowed. The plan must be readable as a causally coherent attack narrative, not merely as a sequence of formally satisfiable operators. Examples of prohibited semantic jumps between consecutive steps: traversal across network boundaries without established access, privilege escalation without a prior foothold, credential use without prior acquisition, artifact use without prior creation, triggering a user-interaction-dependent vulnerability without a prior user-luring step.

**BMI6.** The attack path has exactly one Step 0 (vulnerability exposure action) and exactly one Step End (security impact). Step End's effect must include exactly one of: `(spoofing ?Target)`, `(tampering ?Target)`, `(repudiation ?Target)`, `(information-disclosure ?Target)`, `(denial-of-service ?Target)`, or `(elevation-of-privilege ?Target)`.

**BMI7.** Valid ground terms. Every argument in action preconditions and effects must be either a `?`-prefixed parameter (declared in `:parameters`) or a constant declared in the `:constants` block. Never use type names or any other undeclared identifier as a bare ground term in predicate arguments. Every `?`-prefixed variable used in preconditions or effects must be declared in the `:parameters` of the same action.

**BMI8.** Unique identifiers. Predicate names must not clash with any identifier declared in `:constants`, `:types`, or `:functions`. Each name must be unique across all PDDL namespaces.

**BMI9.** *(Zero-shot: always on. Few-shot: SMI-level.)* Each vulnerability exploitation should generally follow the pattern: exposure-confirmation → [payload-creation →] [payload-delivery →] [payload-received →] [payload-extraction →] [payload-parsing →] vulnerable-component-invocation → vulnerability-trigger → security-impact. Not all stages are required for every CVE; omit stages that are not applicable to the specific vulnerability being modeled.

---

## SMI — Small Model Mandatory Instructions

*(Zero-shot: always on. Few-shot: SMI-level or OI-level as noted.)*

**SMI1.** *(Few-shot: SMI-level.)* Every action's preconditions must be satisfiable from either the initial state or the effects of prior actions.

**SMI2.** *(Few-shot: SMI-level.)* Action actor is one of: attacker, target-system, user, infrastructure. Names must be directly verbalizable as a sentence in an attack narrative. When an action's actor does not clearly fit any of the four categories, define a new actor type based on PDDL modeling principles and common security knowledge.

**SMI4.** *(Few-shot: OI-level.)* Attack goals use the canonical STRIDE vocabulary. When a predicate expresses a relationship between entities, use verb-based naming and keep argument order as subject to object.

**SMI5.** *(Few-shot: SMI-level.)* Avoid introducing unnecessary preconditions. Repeated checking of monotonic predicates (predicates that are never deleted once established) across consecutive actions is acceptable for readability.

---

## OI — Optional Instructions

*(Both modes: included only when key appears in `selected_oi`.)*

**OI1.** Path filtering. When multiple semantically valid attack paths exist for a given CVE, output the single highest-threat path, defined as the path requiring the fewest preconditions.

**OI2.** Preferably semantics of predicates follow the six-category taxonomy:
- Environment/Structural: static relationships among entities
- Vulnerability exposure: produced only by exposure action
- Adversary capability: produced by attacker actions
- Artifact/Delivery: produced and consumed by payload-related actions
- Target state-change: state transitions inside the target
- Security outcome: produced only by Step End

**OI3.** For all actions except the CVE-specific exposure action, parameters should preferably be designed to support generalization across multiple CVEs. Do not compress predicate semantics to reduce parameter count.
