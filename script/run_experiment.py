#!/usr/bin/env python3
"""
Main entry point for running experiments.

Usage:
    python script/run_experiment.py                                    # zero-shot ablation
    python script/run_experiment.py --host deepseek --few-shot 3       # 3-shot
    python script/run_experiment.py --host claude --mode batch --oi OI1 OI3
    python script/run_experiment.py --few-shot 2 --few-shot-mode fixed --fixed-cves CVE-2022-1471 CVE-2023-6378
"""

import argparse
import logging
import sys
from pathlib import Path

# Ensure project root is on sys.path
project_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(project_root / "src"))

from cve2pddlap.core.data_loader import load_few_shot_pool
from cve2pddlap.core.experiment_runner import run_single, run_batch, run_ablation
from cve2pddlap.llm_providers import create_provider
from cve2pddlap.utils.config import settings


def main():
    parser = argparse.ArgumentParser(description="CVE → PDDL Attack Path Generator")
    parser.add_argument("--host", type=str, default=None,
                        help="LLM provider (gemini/deepseek/qwen/zhipu/claude/gpt4)")
    parser.add_argument("--mode", type=str, default="ablation",
                        choices=["single", "batch", "ablation"],
                        help="Experiment mode")
    parser.add_argument("--input", type=str, default=None,
                        help="Input CVE JSON file")
    parser.add_argument("--output", type=str, default=None,
                        help="Output directory")
    parser.add_argument("--oi", nargs="*", default=[],
                        help="Optional instructions to include (e.g., OI1 OI3)")
    parser.add_argument("--max-optional", type=int, default=3,
                        help="Max optional instructions per combo in ablation mode")

    # Few-shot arguments
    parser.add_argument("--few-shot", type=int, default=0,
                        help="Number of few-shot examples (0 = zero-shot)")
    parser.add_argument("--few-shot-mode", type=str, default="random",
                        choices=["random", "fixed"],
                        help="Few-shot selection mode")
    parser.add_argument("--few-shot-dataset", type=str, default=None,
                        help="Path to few-shot dataset (default: CVE-PDDL-NNL-ReAP)")
    parser.add_argument("--fixed-cves", nargs="*", default=None,
                        help="CVE IDs for fixed few-shot mode")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed for few-shot selection")

    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    llm = create_provider(host=args.host)
    input_path = args.input or str(project_root / settings.Experiment.input_file)
    output_dir = args.output or str(project_root / settings.Experiment.output_dir)

    # Load few-shot pool if needed
    few_shot_pool = None
    few_shot_mode = "none"
    if args.few_shot > 0:
        dataset_path = args.few_shot_dataset or str(
            project_root / settings.get("FewShot.dataset_dir", "resources/datasets/CVE-PDDL-NNL-ReAP")
        )
        few_shot_pool = load_few_shot_pool(dataset_path)
        few_shot_mode = args.few_shot_mode
        print(f"Loaded {len(few_shot_pool)} few-shot examples from {dataset_path}")

    common_kwargs = dict(
        few_shot_pool=few_shot_pool,
        few_shot_mode=few_shot_mode,
        num_few_shot=args.few_shot,
        fixed_cves=args.fixed_cves,
        seed=args.seed,
    )

    if args.mode == "ablation":
        run_ablation(input_path, output_dir, llm, max_optional=args.max_optional,
                     **common_kwargs)
    elif args.mode == "batch":
        tag = "_".join(args.oi) if args.oi else "mandatory_only"
        run_batch(input_path, output_dir, llm, selected_oi=args.oi, experiment_tag=tag,
                  **common_kwargs)
    elif args.mode == "single":
        import json
        with open(input_path) as f:
            first = json.load(f)[0]
        examples = None
        if few_shot_pool and args.few_shot > 0:
            from cve2pddlap.core.data_loader import select_few_shot_examples
            examples = select_few_shot_examples(
                few_shot_pool, args.few_shot, exclude_cve=first["cve_id"],
                mode=few_shot_mode, fixed_cves=args.fixed_cves, seed=args.seed,
            )
        result = run_single(first["cve_id"], first["description"], llm,
                            selected_oi=args.oi, few_shot_examples=examples)
        print(result)


if __name__ == "__main__":
    main()
