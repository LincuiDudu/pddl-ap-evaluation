#!/bin/bash
#SBATCH --job-name=eval-qwen8b
#SBATCH --partition=gpu
#SBATCH --nodelist=icsnode05,icsnode06
#SBATCH --gres=gpu:1
#SBATCH --time=24:00:00
#SBATCH --mem=64G
#SBATCH --cpus-per-task=8
#SBATCH --output=logs/eval-%j.out
#SBATCH --error=logs/eval-%j.err

# ─────────────────────────────────────────────────────────────────────────
# Full Qwen3-Embedding-8B evaluation run on A100.
# Queues on icsnode05 / icsnode06. Once it gets the GPU, runs ~20-60 min.
# Submit:  sbatch run_eval_server.sh
# Check:   squeue -u $USER ; tail -f logs/eval-<JOB_ID>.out
# Cancel:  scancel <JOB_ID>
# ─────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ───────── Repo location ─────────
# Adjust REPO_ROOT to where you cloned the repo on the server.
REPO_ROOT="${REPO_ROOT:-$HOME/llm-ap-generation}"
cd "$REPO_ROOT"
mkdir -p logs

# ───────── Module load (adjust to your cluster) ─────────
module purge 2>/dev/null || true
module load python/3.10 2>/dev/null || echo "[warn] python/3.10 module not found, using system python3"
module load cuda/12.1   2>/dev/null || echo "[warn] cuda/12.1 module not found, relying on torch wheel"

# ───────── HF cache redirected to repo dir (avoid filling home quota) ─────────
export HF_HOME="$REPO_ROOT/.hf_cache"
export TRANSFORMERS_CACHE="$HF_HOME/transformers"
export HUGGINGFACE_HUB_CACHE="$HF_HOME/hub"
mkdir -p "$HF_HOME"

# ───────── Python venv (created on first run, reused after) ─────────
VENV="$REPO_ROOT/.venv"
if [ ! -d "$VENV" ]; then
    echo "[setup] creating venv at $VENV"
    python3 -m venv "$VENV"
fi
source "$VENV/bin/activate"
python -m pip install --upgrade --quiet pip wheel setuptools

# ───────── Install dependencies (idempotent) ─────────
echo "[setup] installing Python deps"
pip install --quiet \
    "torch>=2.1" \
    "transformers>=4.51" \
    "sentence-transformers>=3.0" \
    accelerate \
    numpy pandas scikit-learn statsmodels \
    matplotlib \
    ipywidgets jupyter nbconvert ipykernel \
    python-dotenv \
    openai \
    jinja2 \
    huggingface_hub \
    einops

# Install the local cve2pddlap package in editable mode
pip install --quiet -e .

# Register a kernel pointing to this venv (so nbconvert can find it)
python -m ipykernel install --user --name evalvenv --display-name "Python (evalvenv)" >/dev/null 2>&1 || true

# ───────── Environment dump ─────────
echo "=================================================================="
echo "Job: $SLURM_JOB_ID  Node: $(hostname)  Date: $(date)"
echo "=================================================================="
nvidia-smi
echo
python -c "import torch; print(f'PyTorch {torch.__version__}, CUDA {torch.version.cuda}, GPUs: {torch.cuda.device_count()}, name: {torch.cuda.get_device_name(0) if torch.cuda.is_available() else \"N/A\"}')"
python -c "import transformers, sentence_transformers; print(f'transformers {transformers.__version__}, sentence-transformers {sentence_transformers.__version__}')"
echo "=================================================================="

# ───────── Run the notebook ─────────
NOTEBOOK="notebooks/attack_paths/evaluation-win-server.ipynb"
OUTPUT="notebooks/attack_paths/evaluation-win-server_run_${SLURM_JOB_ID}.ipynb"

echo "[exec] running $NOTEBOOK ..."
jupyter nbconvert --to notebook --execute "$NOTEBOOK" \
    --output "$(basename "$OUTPUT")" \
    --output-dir "$(dirname "$OUTPUT")" \
    --ExecutePreprocessor.timeout=-1 \
    --ExecutePreprocessor.kernel_name=evalvenv

echo "=================================================================="
echo "[done] output saved to: $OUTPUT"
echo "[done] results jsonl in: results/tests/reference_set/semantic/{intrinsic,extrinsic}/similarity/"
echo "[done] elapsed: $SECONDS s"
