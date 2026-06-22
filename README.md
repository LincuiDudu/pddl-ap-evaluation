# S3Eval — Replication Package

Replication package for the paper: *S3Eval: A Three-Layer Pipeline for Automated Evaluation of PDDL-Encoded Attack Paths*.

## Overview

S3Eval is a three-layer automated evaluation pipeline that assesses the **S**yntactic correctness (S1), **S**olvability (S2), and **S**emantic quality (S3) of PDDL-encoded attack paths. This repository contains the source code, evaluation notebooks, prompt templates, and full experimental results.

## Repository Structure

```
├── src/cve2pddlap/          # Core Python package
│   ├── core/                 # Data loading utilities
│   ├── evaluation/           # S1 syntax & S2 solvability checks
│   ├── llm_providers/        # LLM API clients (OpenAI, DeepSeek, Ollama, vLLM, etc.)
│   └── utils/                # Configuration utilities
├── notebooks/
│   ├── attack_paths/         # Evaluation notebooks (S1, S2, S3)
│   └── paper/                # Figure generation for the paper
├── resources/
│   ├── data/                 # PDDL-encoded attack paths (reference + mutated negatives)
│   ├── prompt/evaluation/    # LLM scoring prompt templates & calibration data
│   └── configs/              # Configuration files
├── results/                  # Full experimental results (see results/README.md)
├── tools/
│   ├── Metric-FF/            # Metric-FF planner (S2 solvability)
│   ├── enhsp/                # ENHSP parser (S1 syntax)
│   └── mutator.py            # Controlled mutation operator (11 mutation types)
└── Fig/                      # Generated figures
```

## Setup

```bash
pip install -r requirements.txt
pip install -e .
```

Copy `.env.example` to `.env` and add your API keys for commercial LLM evaluation.

## Evaluation Pipeline

| Layer | Tool | Notebook |
|-------|------|----------|
| S1: Syntax | ENHSP | `evaluation-S1.ipynb` |
| S2: Solvability | Metric-FF | `evaluation-S2.ipynb` |
| S3: Embedding (intrinsic) | Sentence Transformers | `evaluation-server-embse.ipynb` |
| S3: Embedding (extrinsic) | Sentence Transformers | `evaluation-S3-server-embse.ipynb` |
| S3: LLM (local) | Ollama / vLLM | `evaluation-S3-server-local-llm.ipynb` |
| S3: LLM (GPT) | OpenAI API | `evaluation-S3-llm-gpt-*.ipynb` |
| S3: LLM (DeepSeek-R1) | DeepSeek API | `evaluation-S3-llm-deepseek-r1.ipynb` |
| Figures | Matplotlib | `eval-reults-figures.ipynb` |

## Results

Pre-computed results for all experiments are in `results/`. See `results/README.md` for the detailed structure and file descriptions.

## Dataset

The evaluation dataset contains 21 CVEs with 55 expert-authored reference attack paths and 55 controlled mutated negatives (11 mutation types). One sample CVE (CVE-2023-6378) is included in `resources/data/`. The full dataset is available upon request.

## License

Apache License 2.0. See [LICENSE](LICENSE).
