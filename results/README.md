# S3Eval — Replication Package

Evaluation results for the S3Eval pipeline. All result files are in JSONL format (one JSON object per line).

## Directory Structure

```
results/
├── syntax/
│   └── results_syntax.jsonl                # S1: syntax correctness check
├── solvability/
│   └── results_solvability.jsonl           # S2: plan solvability check
├── semantic/
│   ├── intrinsic/
│   │   ├── similarity/
│   │   │   ├── cv_intrinsic_similarity.jsonl        # CV calibration (full-matrix)
│   │   │   └── results_intrinsic_similarity.jsonl   # Predictions (full-matrix)
│   │   └── llm-as-experts/
│   │       ├── results_intrinsic_binary_<model>.jsonl   # Simplified rubric
│   │       └── results_intrinsic_scored_<model>.jsonl   # Detailed rubric
│   ├── extrinsic/
│   │   ├── similarity/
│   │   │   ├── cv_extrinsic_similarity.jsonl        # CV calibration (full-matrix)
│   │   │   └── results_extrinsic_similarity.jsonl   # Predictions (full-matrix)
│   │   └── llm-as-experts/
│   │       ├── results_extrinsic_binary_<model>.jsonl   # Simplified rubric
│   │       └── results_extrinsic_scored_<model>.jsonl   # Detailed rubric
│   └── reference_pair_scores.jsonl         # Pairwise similarity scores for calibration
└── agreement/
    └── fleiss_kappa.jsonl                  # Inter-layer Fleiss' kappa
```

## Layers

- **S1 (Syntax)**: ENHSP-based syntax correctness check.
- **S2 (Solvability)**: Metric-FF-based plan solvability check.
- **S3 (Semantic)**: Embedding-based similarity and LLM-as-expert evaluation.

## S3 Settings

- **Intrinsic**: Evaluates using the CVE natural language description.
- **Extrinsic**: Evaluates using an expert-authored reference attack path.

## Embedding Calibration

- **Full-matrix**: Exhaustive pairing of all available examples for CV threshold calibration.

## LLM Models

Commercial: `gpt-4.1`, `gpt-5.4`, `gpt-5.5`, `deepseek-reasoner` (DeepSeek-R1).
Local: `qwen3:4b`, `qwen3:8b`, `qwen3:14b`, `qwen3:32b`.

## Rubric Variants

- **Simplified** (`binary`): Holistic binary judgment (accept/reject).
- **Detailed** (`scored`): Per-criterion 0-5 scoring with minimum-score threshold.

## Dataset

The evaluation dataset contains 21 CVEs with 55 expert-authored reference attack paths (positives) and 55 controlled mutated attack paths (negatives). The dataset is available upon request.
