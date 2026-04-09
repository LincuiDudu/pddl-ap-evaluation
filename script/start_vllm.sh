#!/usr/bin/env bash
# Start a local vLLM server for PDDL attack path generation experiments.
#
# Usage:
#   bash script/start_vllm.sh                      # qwen7b (default)
#   MODEL=qwen14b bash script/start_vllm.sh        # 14B
#   MODEL=qwen3b bash script/start_vllm.sh         # 3B
#   MODEL=qwen7b_coder bash script/start_vllm.sh   # Coder 7B
#
# To pin model version (recommended for paper reproducibility):
#   REVISION=<commit_hash> MODEL=qwen7b bash script/start_vllm.sh
#   Find commit hash at: https://huggingface.co/Qwen/Qwen2.5-7B-Instruct/commits/main

set -euo pipefail

MODEL=${MODEL:-qwen7b}
PORT=${PORT:-8000}
REVISION=${REVISION:-}   # empty = use latest; set to HF commit hash to pin version

case "$MODEL" in
  qwen3b)       MODEL_ID="Qwen/Qwen2.5-3B-Instruct" ;;
  qwen7b)       MODEL_ID="Qwen/Qwen2.5-7B-Instruct" ;;
  qwen14b)      MODEL_ID="Qwen/Qwen2.5-14B-Instruct" ;;
  qwen7b_coder) MODEL_ID="Qwen/Qwen2.5-Coder-7B-Instruct" ;;
  *)
    echo "Unknown MODEL=$MODEL. Options: qwen3b | qwen7b | qwen14b | qwen7b_coder"
    exit 1
    ;;
esac

echo "Model:    $MODEL_ID"
echo "Revision: ${REVISION:-latest}"
echo "Endpoint: http://localhost:$PORT/v1"
echo ""

ARGS=(
  --model "$MODEL_ID"
  --dtype bfloat16
  --port "$PORT"
  --trust-remote-code
)

if [[ -n "$REVISION" ]]; then
  ARGS+=(--revision "$REVISION")
fi

python -m vllm.entrypoints.openai.api_server "${ARGS[@]}"
