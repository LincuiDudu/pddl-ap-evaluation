"""
Experiment runner: single, batch, and ablation modes.
Supports zero-shot and few-shot via message-based prompts.
"""

from __future__ import annotations

import itertools
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from cve2pddlap.core.data_loader import (
    load_cve_list, load_few_shot_pool, select_few_shot_examples, FewShotExample,
)
from cve2pddlap.core.prompt_builder import build_messages, ALL_SELECTABLE_NAMES
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


def _save_run_metadata(
    output_dir: Path,
    llm: LLMProvider,
    experiment_tag: str,
    shot_label: str,
    selected_oi: list[str],
    few_shot_mode: str,
    few_shot_seed: int | None,
) -> None:
    """
    Write a metadata JSON for this batch run — captures all reproducibility-relevant
    parameters so results can be traced back to exact experimental conditions.
    """
    meta: dict = {
        "experiment_tag": experiment_tag,
        "shot_label": shot_label,
        "selected_oi": selected_oi,
        "few_shot_mode": few_shot_mode,
        "few_shot_seed": few_shot_seed,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "model": {
            "provider": llm.__class__.__name__,
            "model": llm.model,
            "temperature": llm.temperature,
            "seed": llm.seed,
            "top_p": llm.top_p,
            "max_tokens": llm.max_tokens,
        },
    }

    # If the provider exposes get_metadata() (e.g. VLLMProvider), merge it in
    if hasattr(llm, "get_metadata"):
        meta["model"].update(llm.get_metadata())

    meta_file = output_dir / f"_metadata_{experiment_tag}_{shot_label}.json"
    meta_file.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info("Metadata saved: %s", meta_file)


def run_batch(
    input_path: str | Path,
    output_dir: str | Path,
    llm: LLMProvider,
    selected_oi: list[str] | None = None,
    experiment_tag: str = "mandatory_only",
    few_shot_pool: list[FewShotExample] | None = None,
    few_shot_mode: str = "none",
    num_few_shot: int = 0,
    fixed_keys: list[str] | None = None,
    seed: int | None = 42,
) -> None:
    """
    Run all CVEs from a JSON file and save results.
    Output files per CVE: {cve_id}_{provider}_{tag}_{shot}.pddl + _prompt.txt
    Metadata file:        _metadata_{tag}_{shot}.json
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    cve_list = load_cve_list(input_path)
    provider_name = llm.__class__.__name__.replace("Provider", "").lower()
    selected_oi = selected_oi or []

    shot_label = f"{num_few_shot}shot" if num_few_shot > 0 else "0shot"

    _save_run_metadata(
        output_dir=output_dir,
        llm=llm,
        experiment_tag=experiment_tag,
        shot_label=shot_label,
        selected_oi=selected_oi,
        few_shot_mode=few_shot_mode,
        few_shot_seed=seed,
    )

    for entry in cve_list:
        few_shot_examples = None
        if few_shot_pool and few_shot_mode != "none" and num_few_shot > 0:
            few_shot_examples = select_few_shot_examples(
                pool=few_shot_pool,
                num_examples=num_few_shot,
                exclude_cve=entry.cve_id,
                mode=few_shot_mode,
                fixed_keys=fixed_keys,
                seed=seed,
            )

        logger.info("Processing: %s | %s | %s | %s", entry.cve_id, llm, experiment_tag, shot_label)
        print(f"Processing: {entry.cve_id} | {llm} | {experiment_tag} | {shot_label}")

        result = run_single(entry.cve_id, entry.description, llm, selected_oi, few_shot_examples)

        stem = f"{entry.cve_id}_{provider_name}_{experiment_tag}_{shot_label}"
        (output_dir / f"{stem}.pddl").write_text(result, encoding="utf-8")

        messages = build_messages(entry.cve_id, entry.description, selected_oi, few_shot_examples)
        lines = [f"[{m['role'].upper()}]\n{m['content']}\n" for m in messages]
        (output_dir / f"{stem}_prompt.txt").write_text("\n".join(lines), encoding="utf-8")

        print(f"  Saved: {stem}.pddl")


def run_ablation(
    input_path: str | Path,
    output_dir: str | Path,
    llm: LLMProvider,
    max_optional: int = 3,
    few_shot_pool: list[FewShotExample] | None = None,
    few_shot_mode: str = "none",
    num_few_shot: int = 0,
    fixed_keys: list[str] | None = None,
    seed: int | None = 42,
) -> None:
    """
    Run all combinations of optional instructions (size 0 to max_optional).
    Total for 8 selectables, max_optional=3: C(8,0)+...+C(8,3) = 93 combinations.
    """
    for r in range(0, max_optional + 1):
        for combo in itertools.combinations(ALL_SELECTABLE_NAMES, r):
            selected_oi = list(combo) if combo else []
            tag = "_".join(combo) if combo else "mandatory_only"

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
                fixed_keys=fixed_keys,
                seed=seed,
            )
