"""
Load CVE data from JSON input files and few-shot examples from dataset.
"""

import json
import random
from pathlib import Path
from dataclasses import dataclass


@dataclass(frozen=True)
class CVEEntry:
    cve_id: str
    description: str


@dataclass(frozen=True)
class FewShotExample:
    """A single few-shot example: CVE description → PDDL domain."""
    cve_id: str
    ap_id: str
    description: str
    domain_pddl: str

    @property
    def key(self) -> str:
        """Unique key for this example, e.g. 'CVE-2022-40149 / AP2'."""
        return f"{self.cve_id} / {self.ap_id}"


def load_cve_list(path: str | Path) -> list[CVEEntry]:
    """
    Load CVE entries from a JSON file.

    Expected format: [{"cve_id": "CVE-...", "description": "..."}, ...]
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return [CVEEntry(cve_id=item["cve_id"], description=item["description"]) for item in data]


def load_few_shot_pool(dataset_dir: str | Path) -> list[FewShotExample]:
    """
    Load all available few-shot examples from the CVE-PDDL dataset.

    Expected structure:
        dataset_dir/
            CVE-XXXX-XXXXX/
                description.txt
                AP1/
                    domain.pddl
                AP2/
                    domain.pddl

    Loads all APx variants for each CVE (one FewShotExample per AP).
    """
    dataset_dir = Path(dataset_dir)
    examples = []

    for cve_dir in sorted(dataset_dir.iterdir()):
        if not cve_dir.is_dir() or not cve_dir.name.startswith("CVE-"):
            continue

        desc_file = cve_dir / "description.txt"
        if not desc_file.exists():
            continue

        description = desc_file.read_text(encoding="utf-8").strip()

        for ap_dir in sorted(cve_dir.iterdir()):
            if not ap_dir.is_dir() or not ap_dir.name.startswith("AP"):
                continue
            domain_file = ap_dir / "domain.pddl"
            if not domain_file.exists():
                continue
            examples.append(FewShotExample(
                cve_id=cve_dir.name,
                ap_id=ap_dir.name,
                description=description,
                domain_pddl=domain_file.read_text(encoding="utf-8").strip(),
            ))

    return examples


def select_few_shot_examples(
    pool: list[FewShotExample],
    num_examples: int,
    exclude_cve: str | None = None,
    mode: str = "random",
    fixed_keys: list[str] | None = None,
    seed: int | None = None,
) -> list[FewShotExample]:
    """
    Select few-shot examples from the pool.

    Args:
        pool: All available examples.
        num_examples: How many to select.
        exclude_cve: CVE ID to exclude all APs of (avoid data leakage).
        mode: "random" or "fixed".
        fixed_keys: Example keys to use in fixed mode, e.g. ["CVE-2022-1471 / AP1"].
        seed: Random seed for reproducibility.

    Returns:
        Selected examples.
    """
    candidates = [ex for ex in pool if ex.cve_id != exclude_cve]

    if mode == "fixed":
        if not fixed_keys:
            raise ValueError("fixed_keys must be provided in fixed mode")
        key_set = set(fixed_keys)
        selected = [ex for ex in candidates if ex.key in key_set]
        return selected[:num_examples]

    elif mode == "random":
        rng = random.Random(seed)
        k = min(num_examples, len(candidates))
        return rng.sample(candidates, k)

    else:
        raise ValueError(f"Unknown few-shot mode: {mode}")
