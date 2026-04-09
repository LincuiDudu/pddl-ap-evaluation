"""
Experiment runner: single, batch, and ablation modes.
Supports zero-shot and few-shot via message-based prompts.
"""

from __future__ import annotations

import itertools
import logging
from pathlib import Path

from cve2pddlap.core.data_loader import (
    load_cve_list, load_few_shot_pool, select_few_shot_examples, FewShotExample,
)
from cve2pddlap.core.prompt_builder import build_messages, ALL_SELECTABLE_NAMES, SMI_NAMES, OI_NAMES
from cve2pddlap.llm_providers.llm_provider import LLMProvider

logger = logging.getLogger(__name__)


def run_single(
    cve_id: str,
    cve_description: str,
    llm: LLMProvider,
    selected_oi: list[str] | None = None,
    few_shot_examples: list[FewShotExample] | None = None,
) -> str:
    """Run a single CVE through the pipeline and return generated PDDL."""
    messages = build_messages(cve_id, cve_description, selected_oi, few_shot_examples)
    return llm.send(messages)


def run_batch(
    input_path: str | Path,
    output_dir: str | Path,
    llm: LLMProvider,
    selected_oi: list[str] | None = None,
    experiment_tag: str = "mandatory_only",
    few_shot_pool: list[FewShotExample] | None = None,
    few_shot_mode: str = "none",
    num_few_shot: int = 0,
    fixed_cves: list[str] | None = None,
    seed: int | None = 42,
) -> None:
    """
    Run all CVEs from a JSON file and save results.
    Output filename: {cve_id}_{provider}_{tag}.pddl
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    cve_list = load_cve_list(input_path)
    provider_name = llm.__class__.__name__.replace("Provider", "").lower()

    for entry in cve_list:
        # Select few-shot examples (excluding current CVE)
        few_shot_examples = None
        if few_shot_pool and few_shot_mode != "none" and num_few_shot > 0:
            few_shot_examples = select_few_shot_examples(
                pool=few_shot_pool,
                num_examples=num_few_shot,
                exclude_cve=entry.cve_id,
                mode=few_shot_mode,
                fixed_cves=fixed_cves,
                seed=seed,
            )

        shot_label = f"{num_few_shot}shot" if few_shot_examples else "0shot"
        logger.info("Processing: %s | %s | %s | %s", entry.cve_id, llm, experiment_tag, shot_label)
        print(f"Processing: {entry.cve_id} | {llm} | {experiment_tag} | {shot_label}")

        result = run_single(entry.cve_id, entry.description, llm, selected_oi, few_shot_examples)

        out_file = output_dir / f"{entry.cve_id}_{provider_name}_{experiment_tag}_{shot_label}.pddl"
        out_file.write_text(result, encoding="utf-8")
        print(f"Saved: {out_file}")

        # Save the rendered messages for reproducibility
        messages = build_messages(entry.cve_id, entry.description, selected_oi, few_shot_examples)
        prompt_file = output_dir / f"{entry.cve_id}_{provider_name}_{experiment_tag}_{shot_label}_prompt.txt"
        lines = []
        for msg in messages:
            lines.append(f"[{msg['role'].upper()}]\n{msg['content']}\n")
        prompt_file.write_text("\n".join(lines), encoding="utf-8")


def run_ablation(
    input_path: str | Path,
    output_dir: str | Path,
    llm: LLMProvider,
    max_optional: int = 3,
    few_shot_pool: list[FewShotExample] | None = None,
    few_shot_mode: str = "none",
    num_few_shot: int = 0,
    fixed_cves: list[str] | None = None,
    seed: int | None = 42,
) -> None:
    """
    Run all combinations of optional instructions (size 0 to max_optional).
    Total for 7 OIs, max_optional=3: C(7,0)+C(7,1)+C(7,2)+C(7,3) = 64 combinations.
    """
    for r in range(0, max_optional + 1):
        for combo in itertools.combinations(ALL_SELECTABLE_NAMES, r):
            if combo:
                selected_oi = list(combo)
                tag = "_".join(combo)
            else:
                selected_oi = []
                tag = "mandatory_only"

            print(f"\n--- Experiment: {tag} ---")
            run_batch(
                input_path=input_path,
                output_dir=output_dir,
                llm=llm,
                selected_oi=selected_oi,
                experiment_tag=tag,
                few_shot_pool=few_shot_pool,
                few_shot_mode=few_shot_mode,
                num_few_shot=num_few_shot,
                fixed_cves=fixed_cves,
                seed=seed,
            )
