#!/usr/bin/env bash
# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
#
# fire-line-audit.sh
# Verifies that no forbidden identifiers have been introduced into the codebase.
# Run before every release: bash scripts/fire-line-audit.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_DIRS=("typescript/src" "python/src" "examples")

FORBIDDEN_IDENTIFIERS=(
  "progressLevel"
  "promoteLevel"
  "computeTrustScore"
  "behavioralScore"
  "adaptiveBudget"
  "optimizeBudget"
  "predictSpending"
  "detectAnomaly"
  "generateCounterfactual"
  "PersonalWorldModel"
  "MissionAlignment"
  "SocialTrust"
  "CognitiveLoop"
  "AttentionFilter"
  "GOVERNANCE_PIPELINE"
)

FORBIDDEN_PATTERNS=(
  "import.*openai"
  "import.*anthropic"
  "import.*cohere"
  "from openai"
  "from anthropic"
  "from cohere"
  "require.*openai"
  "require.*anthropic"
  "sklearn"
  "torch\."
  "tensorflow"
  "sentence_transformers"
  "embed("
  "vectorize("
)

ERRORS=0
CHECKED=0

echo "=== FIRE LINE AUDIT ==="
echo "Repository: ${REPO_ROOT}"
echo ""

# Check forbidden identifiers
echo "--- Checking forbidden identifiers ---"
for identifier in "${FORBIDDEN_IDENTIFIERS[@]}"; do
  for dir in "${SOURCE_DIRS[@]}"; do
    target="${REPO_ROOT}/${dir}"
    if [ ! -d "${target}" ]; then
      continue
    fi
    matches=$(grep -rn --include="*.ts" --include="*.py" "${identifier}" "${target}" 2>/dev/null || true)
    if [ -n "${matches}" ]; then
      echo "[FAIL] Forbidden identifier '${identifier}' found:"
      echo "${matches}"
      ERRORS=$((ERRORS + 1))
    fi
    CHECKED=$((CHECKED + 1))
  done
done

# Check forbidden patterns (ML/LLM imports)
echo ""
echo "--- Checking forbidden ML/LLM patterns ---"
for pattern in "${FORBIDDEN_PATTERNS[@]}"; do
  for dir in "${SOURCE_DIRS[@]}"; do
    target="${REPO_ROOT}/${dir}"
    if [ ! -d "${target}" ]; then
      continue
    fi
    matches=$(grep -rn --include="*.ts" --include="*.py" -i "${pattern}" "${target}" 2>/dev/null || true)
    if [ -n "${matches}" ]; then
      echo "[FAIL] Forbidden pattern '${pattern}' found:"
      echo "${matches}"
      ERRORS=$((ERRORS + 1))
    fi
    CHECKED=$((CHECKED + 1))
  done
done

# Check SPDX headers
echo ""
echo "--- Checking SPDX headers in TypeScript source files ---"
while IFS= read -r -d '' file; do
  first_line=$(head -n 1 "${file}")
  if [[ "${first_line}" != "// SPDX-License-Identifier: BSL-1.1" ]]; then
    echo "[FAIL] Missing SPDX header in: ${file}"
    ERRORS=$((ERRORS + 1))
  fi
  CHECKED=$((CHECKED + 1))
done < <(find "${REPO_ROOT}/typescript/src" -name "*.ts" -print0 2>/dev/null)

echo ""
echo "--- Checking SPDX headers in Python source files ---"
while IFS= read -r -d '' file; do
  first_line=$(head -n 1 "${file}")
  if [[ "${first_line}" != "# SPDX-License-Identifier: BSL-1.1" ]]; then
    echo "[FAIL] Missing SPDX header in: ${file}"
    ERRORS=$((ERRORS + 1))
  fi
  CHECKED=$((CHECKED + 1))
done < <(find "${REPO_ROOT}/python/src" "${REPO_ROOT}/examples" -name "*.py" -print0 2>/dev/null)

echo ""
echo "=== AUDIT COMPLETE ==="
echo "Checks run: ${CHECKED}"
if [ "${ERRORS}" -eq 0 ]; then
  echo "Result: PASS — no violations found"
  exit 0
else
  echo "Result: FAIL — ${ERRORS} violation(s) found"
  exit 1
fi
