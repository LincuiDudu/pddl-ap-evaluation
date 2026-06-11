#!/bin/bash
#SBATCH --job-name=eval-test
#SBATCH --partition=gpu
#SBATCH --nodelist=icsnode08
#SBATCH --gres=gpu:1
#SBATCH --time=02:00:00
#SBATCH --mem=32G
#SBATCH --cpus-per-task=4
#SBATCH --output=logs/eval-test-%j.out
#SBATCH --error=logs/eval-test-%j.err

# ─────────────────────────────────────────────────────────────────────────
# Quick smoke test on icsnode08 (no queue).
# Same notebook, same code, but the smaller / faster cells let you verify
# the env works before committing to a long A100 run.
# Submit:  sbatch run_eval_test.sh
# Or run interactively:  srun --partition=gpu --nodelist=icsnode08 --gres=gpu:1 --pty bash
# ─────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ───────── Repo location ─────────
REPO_ROOT="${REPO_ROOT:-$HOME/llm-ap-generation}"
cd "$REPO_ROOT"
mkdir -p logs

# ───────── Module load ─────────
module purge 2>/dev/null || true
module load python/3.10 2>/dev/null || echo "[warn] python/3.10 module not found, using system python3"
module load cuda/12.1   2>/dev/null || echo "[warn] cuda/12.1 module not found, relying on torch wheel"

# ───────── HF cache (shared with main job — first download paid once) ─────────
export HF_HOME="$REPO_ROOT/.hf_cache"
export TRANSFORMERS_CACHE="$HF_HOME/transformers"
export HUGGINGFACE_HUB_CACHE="$HF_HOME/hub"
mkdir -p "$HF_HOME"

# ───────── Python venv (shared with main job) ─────────
VENV="$REPO_ROOT/.venv"
if [ ! -d "$VENV" ]; then
    echo "[setup] creating venv at $VENV"
    python3 -m venv "$VENV"
fi
source "$VENV/bin/activate"
python -m pip install --upgrade --quiet pip wheel setuptools

echo "[setup] installing Python deps (idempotent)"
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

pip install --quiet -e .
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
OUTPUT="notebooks/attack_paths/evaluation-win-server_TEST_${SLURM_JOB_ID}.ipynb"

echo "[exec] running $NOTEBOOK on icsnode08 ..."
jupyter nbconvert --to notebook --execute "$NOTEBOOK" \
    --output "$(basename "$OUTPUT")" \
    --output-dir "$(dirname "$OUTPUT")" \
    --ExecutePreprocessor.timeout=-1 \
    --ExecutePreprocessor.kernel_name=evalvenv

echo "=================================================================="
echo "[done] output saved to: $OUTPUT"
echo "[done] elapsed: $SECONDS s"
