#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# opus_resume_watcher.sh — bridge the Claude Code subscription token wall for the
# Model C (Opus, via:cli) benchmark run.
#
# WHAT IT DOES
#   For each target repo (in B's order so it trails the local qwen3.6 run):
#     1. waits until Model B (config.qwen3.6.yaml) is not scanning that repo
#        (per-repo output/run-id collision guard);
#     2. runs `vvaharness scan ... --resume` (picks up intact checkpoints);
#     3. if the run dies on the rate/usage wall, sleeps REFRESH_WAIT (~4h refresh)
#        and re-runs --resume — repeating up to MAX_CYCLES;
#     4. on a clean finish, moves security-scan/ + checkpoints/ into the
#        benchmark dir; on a NON-rate failure it STOPS (so a real bug doesn't loop).
#
# It is EXTERNAL to vvaharness/: it only calls the shipped CLI. Stock harness,
# same via:cli backend, same config.opus.yaml — benchmark stays clean.
#
# USAGE (run in its own terminal — tmux/nohup, it sleeps for hours):
#   scripts/opus_resume_watcher.sh                       # all 3 repos, B's order
#   scripts/opus_resume_watcher.sh nokogiri              # just one
#   REFRESH_WAIT=18000 scripts/opus_resume_watcher.sh    # tune the sleep
#
# TUNABLES (env): REFRESH_WAIT (sec across the wall), MAX_CYCLES (per repo),
#                 LOCK_POLL (sec between B-lock checks).
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

HARNESS=/home/higgs/workspace/cyness/visa-vulnerability-agentic-harness
SRC_BASE=/home/higgs/workspace/cyness
BENCH=/home/higgs/workspace/cyness/benchmarks/visa
CFG=./config.opus.yaml          # relative to $HARNESS (we cd there)
MDIR=claude-opus-4-8
VVA="$HARNESS/.venv/bin/vvaharness"

REFRESH_WAIT="${REFRESH_WAIT:-15300}"   # 4h15m — bridge the ~4h token refresh (+buffer)
MAX_CYCLES="${MAX_CYCLES:-12}"          # max resume cycles/repo (12 × 4h ≈ 48h cap)
LOCK_POLL="${LOCK_POLL:-60}"            # seconds between Model-B lock checks

# Signatures that mean "token/rate wall — worth sleeping + resuming" (vs a real bug).
WALL_RX='transient upstream error|rate.?limit|overloaded|too many requests|usage limit|hit your (usage )?limit|\b429\b|temporarily unavailable'

if [ "$#" -gt 0 ]; then REPOS=("$@"); else REPOS=(nokogiri juice-shop underscore); fi

log(){ printf '%(%Y-%m-%dT%H:%M:%S%z)T  [watcher] %s\n' -1 "$*"; }

# Is the local qwen3.6 (Model B) run currently scanning repo $1? (collision guard)
b_on_repo(){
  pgrep -af "vvaharness scan" 2>/dev/null \
    | grep -- "config.qwen3.6.yaml" \
    | grep -qE -- "/$1([[:space:]/]|$)|bench-$1([[:space:]]|$)"
}

cd "$HARNESS" || { log "FATAL: cannot cd $HARNESS"; exit 1; }
[ -x "$VVA" ] || { log "FATAL: vvaharness not found at $VVA"; exit 1; }
[ -f "$CFG" ] || { log "FATAL: $CFG missing in $HARNESS"; exit 1; }

# Refuse to start a 2nd Opus scan on top of one already running (would self-collide).
if pgrep -af "vvaharness scan" 2>/dev/null | grep -q "config.opus.yaml"; then
  log "An Opus scan (config.opus.yaml) is already running. Stop it first (or let it"
  log "die on the wall), then launch this watcher to resume. Refusing to start."
  exit 1
fi

log "start. repos: ${REPOS[*]} | REFRESH_WAIT=${REFRESH_WAIT}s MAX_CYCLES=${MAX_CYCLES}"

for REPO in "${REPOS[@]}"; do
  SRC="$SRC_BASE/$REPO"; DST="$BENCH/$MDIR/$REPO"; LOG="$DST/scan.log"
  mkdir -p "$DST"

  # 1) Collision guard: wait until Model B has vacated this repo.
  while b_on_repo "$REPO"; do
    log "$REPO held by the qwen3.6 (Model B) run — waiting ${LOCK_POLL}s…"
    sleep "$LOCK_POLL"
  done

  # 2) One-time scope preview (no spend).
  "$VVA" estimate --repo "$SRC" --config "$CFG" >"$DST/estimate.txt" 2>&1 || true

  # 3) Resume cycles across the token wall.
  ok=0
  for ((c=1; c<=MAX_CYCLES; c++)); do
    log "$REPO: scan cycle $c/$MAX_CYCLES (--resume)…"
    printf '\n===== watcher cycle %d  %(%Y-%m-%dT%H:%M:%S%z)T =====\n' "$c" -1 >>"$LOG"
    "$VVA" scan --repo "$SRC" --config "$CFG" --auto-step1 --resume \
        --application-id "bench-$REPO" --repo-name "$REPO" >>"$LOG" 2>&1
    rc=$?
    if [ "$rc" -eq 0 ]; then ok=1; break; fi

    if tail -n 80 "$LOG" | grep -qiE "$WALL_RX"; then
      wake=$(date -d "+${REFRESH_WAIT} seconds" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "in ${REFRESH_WAIT}s")
      log "$REPO: hit the token/rate wall (cycle $c, rc=$rc). Sleeping ${REFRESH_WAIT}s — resume ~${wake}."
      sleep "$REFRESH_WAIT"
      continue
    else
      log "$REPO: FAILED with a NON-rate error (cycle $c, rc=$rc) — not a token wall."
      log "$REPO: stopping for manual review. Tail of $LOG:"; tail -n 15 "$LOG"
      exit 2
    fi
  done

  if [ "$ok" -ne 1 ]; then
    log "$REPO: exhausted $MAX_CYCLES resume cycles — giving up. See $LOG"; exit 3
  fi

  # 4) Integrity gate: rc=0 is NOT enough. s4 has no intra-stage checkpoint, so a
  #    resume that ran s4 during a partial token window can complete s4 DEGRADED
  #    (chunks lost to the wall), checkpoint it, and sail on — silently filing a
  #    nokogiri report missing findings. That would contaminate Model C vs the
  #    clean A/B runs. Refuse to accept a degraded run; make the operator decide.
  report=$(ls -t "$SRC"/security-scan/*_report.md 2>/dev/null | head -1)
  if [ -n "$report" ] && grep -qiE "Degraded coverage|deep-dive chunk\(s\) failed|\*\*DEGRADED\*\*" "$report"; then
    log "$REPO: ⚠️  run finished but s4 is DEGRADED — chunks were lost to the token"
    log "$REPO:     wall, so this report is NOT comparable to the clean A/B runs."
    log "$REPO:     NOT filing it. To force a clean s4 redo (keeps clean s1–s3):"
    log "$REPO:        rm -f $SRC/checkpoints/*_s[4-9].pkl"
    log "$REPO:     then re-run this watcher AFTER a token refresh so s4 gets a full"
    log "$REPO:     window. If s4 simply can't fit one subscription window, this cell"
    log "$REPO:     may be unwinnable on the subscription — decide to accept+document"
    log "$REPO:     the coverage gap or skip Opus for this repo. Leaving artifacts in place."
    exit 4
  fi

  # Clean run → file artifacts.
  if [ -d "$SRC/security-scan" ] || [ -d "$SRC/checkpoints" ]; then
    mv "$SRC/security-scan" "$SRC/checkpoints" "$DST/" 2>/dev/null \
      && log "$REPO: ✅ complete (s4 clean) — artifacts moved to $DST" \
      || log "$REPO: ✅ complete but mv reported an issue — check $SRC and $DST"
  else
    log "$REPO: ✅ complete (no in-repo artifacts to move — already filed?)"
  fi
done

log "all requested repos done."
