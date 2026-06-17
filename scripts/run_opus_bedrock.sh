#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# run_opus_bedrock.sh — run the Model C (Opus) benchmark via AWS Bedrock.
#
# Bedrock has no 4-hour subscription wall (it bills per token), so unlike
# scripts/opus_resume_watcher.sh there is NO sleep/bridge logic — each repo runs
# once to completion. It still:
#   • maps your $BEDROCK_API_KEY -> AWS_BEARER_TOKEN_BEDROCK (the claude CLI's
#     Bedrock bearer-token var);
#   • trails the local qwen3.6 (Model B) run via a per-repo lock (no collision);
#   • passes --resume so a re-run picks up checkpoints after any failure;
#   • REFUSES to file a wall/throttle-degraded s4 (integrity gate) so Model C
#     stays comparable to the clean A/B runs.
#
# Bedrock selection itself is via env (.env): CLAUDE_CODE_USE_BEDROCK=1,
# AWS_REGION, ANTHROPIC_SMALL_FAST_MODEL. Stock harness — nothing under
# vvaharness/ is touched. The model id lives in config.opus.yaml.
#
# 💸 Opus on Bedrock is EXPENSIVE. Run `vvaharness estimate` first and prefer to
#    run ONE repo, check run_manifest token spend, then decide on the rest.
#
# USAGE (separate terminal):
#   scripts/run_opus_bedrock.sh nokogiri            # one repo (recommended first)
#   scripts/run_opus_bedrock.sh                     # all 3, B's order
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

HARNESS=/home/higgs/workspace/cyness/visa-vulnerability-agentic-harness
SRC_BASE=/home/higgs/workspace/cyness
BENCH=/home/higgs/workspace/cyness/benchmarks/visa
CFG=./config.opus.yaml
MDIR=claude-opus-4-8
VVA="$HARNESS/.venv/bin/vvaharness"
LOCK_POLL="${LOCK_POLL:-60}"

if [ "$#" -gt 0 ]; then REPOS=("$@"); else REPOS=(nokogiri juice-shop underscore); fi
log(){ printf '%(%Y-%m-%dT%H:%M:%S%z)T  [bedrock] %s\n' -1 "$*"; }

# Bedrock auth: prefer an already-exported AWS_BEARER_TOKEN_BEDROCK, else map it
# from $BEDROCK_API_KEY. Fail loudly if neither is present.
if [ -z "${AWS_BEARER_TOKEN_BEDROCK:-}" ]; then
  if [ -n "${BEDROCK_API_KEY:-}" ]; then
    export AWS_BEARER_TOKEN_BEDROCK="$BEDROCK_API_KEY"
  else
    log "FATAL: neither AWS_BEARER_TOKEN_BEDROCK nor BEDROCK_API_KEY is set in this"
    log "       shell. Export your Bedrock API key first:  export BEDROCK_API_KEY=…"
    exit 1
  fi
fi

# Model B (qwen3.6) collision guard: is it currently scanning repo $1?
b_on_repo(){
  pgrep -af "vvaharness scan" 2>/dev/null \
    | grep -- "config.qwen3.6.yaml" \
    | grep -qE -- "/$1([[:space:]/]|$)|bench-$1([[:space:]]|$)"
}

cd "$HARNESS" || { log "FATAL: cannot cd $HARNESS"; exit 1; }
[ -x "$VVA" ] || { log "FATAL: vvaharness not found at $VVA"; exit 1; }
[ -f "$CFG" ] || { log "FATAL: $CFG missing in $HARNESS"; exit 1; }

log "start. repos: ${REPOS[*]}  (Bedrock: us-east-1, $(grep -m1 'id:' "$CFG" | tr -d ' '))"

for REPO in "${REPOS[@]}"; do
  SRC="$SRC_BASE/$REPO"; DST="$BENCH/$MDIR/$REPO"; LOG="$DST/scan.log"
  mkdir -p "$DST"

  while b_on_repo "$REPO"; do
    log "$REPO held by the qwen3.6 (Model B) run — waiting ${LOCK_POLL}s…"; sleep "$LOCK_POLL"
  done

  log "$REPO: estimate (no spend)…"
  "$VVA" estimate --repo "$SRC" --config "$CFG" | tee "$DST/estimate.txt"

  log "$REPO: scanning on Bedrock…"
  printf '\n===== bedrock run  %(%Y-%m-%dT%H:%M:%S%z)T =====\n' -1 >>"$LOG"
  "$VVA" scan --repo "$SRC" --config "$CFG" --auto-step1 --resume \
      --application-id "bench-$REPO" --repo-name "$REPO" 2>&1 | tee -a "$LOG"
  rc=${PIPESTATUS[0]}
  if [ "$rc" -ne 0 ]; then
    log "$REPO: scan FAILED (rc=$rc). Checkpoints kept in $SRC for --resume."
    log "$REPO: inspect $LOG; re-run this script to resume. Stopping."
    exit 2
  fi

  # Integrity gate: reject a degraded s4 (chunks lost to throttling) — keeps
  # Model C comparable to the clean A/B runs.
  report=$(ls -t "$SRC"/security-scan/*_report.md 2>/dev/null | head -1)
  if [ -n "$report" ] && grep -qiE "Degraded coverage|deep-dive chunk\(s\) failed|\*\*DEGRADED\*\*" "$report"; then
    log "$REPO: ⚠️  s4 DEGRADED (throttle/errors lost chunks) — NOT filing."
    log "$REPO: to retry s4 cleanly: rm -f $SRC/checkpoints/*_s[4-9].pkl && re-run this script."
    log "$REPO: (if it keeps degrading, lower step4.parallel in config.opus.yaml). Stopping."
    exit 4
  fi

  if [ -d "$SRC/security-scan" ] || [ -d "$SRC/checkpoints" ]; then
    mv "$SRC/security-scan" "$SRC/checkpoints" "$DST/" 2>/dev/null \
      && log "$REPO: ✅ complete (s4 clean) — artifacts moved to $DST" \
      || log "$REPO: ✅ complete but mv reported an issue — check $SRC and $DST"
  fi
done
log "done: ${REPOS[*]}"
