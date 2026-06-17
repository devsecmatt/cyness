# Visa vvaharness — Local-LLM Benchmark

Tool-and-model benchmark of **vvaharness** (Visa's 9-stage agentic SAST
pipeline, v1.0.0) across **two local Ollama models** (via the tool's
OpenAI-compatible backend → `http://localhost:11434/v1`) **and one frontier
cloud model** (Anthropic Claude Opus 4.8 via the `claude` CLI backend). The two
local models run with zero cloud calls; the Opus column is the frontier
quality-ceiling reference.

Created: 2026-06-14.

---

## What's being compared

A 3 × 3 matrix: **three models × three source repos**.

### Models

| Label (dir) | Built from | Arch | Params | Backend | num_ctx (runtime) | Thinking | vvaharness config |
|---|---|---|---|---|---|---|---|
| `qwen2.5-coder-14b-32k` | `qwen2.5-coder:14b` | qwen2 (dense) | 14.8B | `via:openai` → Ollama | 32768 | No | `config.yaml` (32k budgets) |
| `qwen3.6-36b-128k` | `qwen3.6` | qwen35moe (MoE) | 36B | `via:openai` → Ollama | 131072 | Yes | `config.qwen3.6.yaml` (128k budgets) |
| `claude-opus-4-8` | Anthropic (cloud) | — | — | `via:cli` → **AWS Bedrock** | ~200k | Yes | `config.opus.yaml` (shipped large budgets) |

> Model C note: the Claude Code **subscription** was not viable for these scans —
> Opus's s4 token demand exceeds one subscription refresh window and s4 can't
> checkpoint mid-stage, so it was unwinnable. Model C runs the same stock harness
> and `via:cli` backend pointed at **Opus 4.8 on AWS Bedrock** (pay-per-token, no
> daily wall). See `VISA_HARNESS_MODEL_COMPARISON.md` for the full write-up.

All three advertise the `tools` capability (required by the agentic stages
s1/s6). **Context design = "each model at its own max"**: the 14B at 32k,
Qwen3.6 at 128k, Opus at its ~200k window, with each profile's budgets sized to
its window. So across the columns, model *and* context window vary together —
context is a deliberate co-variable, not a held constant. Agentic stages (s1/s6)
are held to **Read/Glob/Grep on all three** (no Bash, even though `via:cli`
could grant it) so the tool surface doesn't add a fourth variable.

> Naming note: the 14B model was originally mislabeled `qwen3.6-32k` in Ollama.
> It is **not** Qwen3.6 — it's qwen2.5-coder-14b with a forced 32k window. It was
> renamed for honest manifests. Qwen3.6 (the real 36B MoE) is the `…-36b-128k`
> model.

### Targets

| Repo | Language(s) | Files (git-tracked) |
|---|---|---|
| `nokogiri` | Ruby + C extension | 518 |
| `juice-shop` | JavaScript/TypeScript | 1187 |
| `underscore` | JavaScript | 400 |

All scans use `--auto-step1` (the model AI-surveys each repo to derive its own
file-exclusion rules), so scope is model-dependent — see Caveats.

---

## Directory layout

```
benchmarks/visa/
├── README.md                       # this file
├── _meta/                          # reproducibility snapshot (see below)
│   ├── config.yaml                 # Model-A profile, as run
│   ├── config.qwen3.6.yaml         # Model-B profile, as run
│   ├── config.opus.yaml            # Model-C profile, as run
│   ├── Modelfile                   # Model-A build recipe
│   ├── Modelfile.qwen3.6           # Model-B build recipe
│   ├── model_A_qwen2.5-coder-14b-32k.txt   # `ollama show` output
│   ├── model_B_qwen3.6-36b-128k.txt
│   └── doctor.txt                  # `vvaharness doctor` readiness output
│
├── qwen2.5-coder-14b-32k/          # Model A results (local)
│   ├── nokogiri/
│   ├── juice-shop/
│   └── underscore/
├── qwen3.6-36b-128k/               # Model B results (local)
│   ├── nokogiri/
│   ├── juice-shop/
│   └── underscore/
└── claude-opus-4-8/                # Model C results (cloud, frontier reference)
    ├── nokogiri/
    ├── juice-shop/
    └── underscore/
```

### Per-`<model>/<repo>/` artifacts

| Path | What it is |
|---|---|
| `security-scan/*_report.md` | Human-readable findings report (summary, threat model, findings, exploit chains, dropped findings, scope appendix) |
| `security-scan/*_report.sarif` | SARIF 2.1.0 — machine-readable findings for CI / code-scanning tools |
| `security-scan/*_errors.jsonl` | Per-stage recoverable errors (one JSON object per line) |
| `security-scan/run_manifest.json` | Provenance: model id, config, per-stage timing, token totals |
| `checkpoints/` | Intermediate stage outputs s1→s9 (resume points). Inspect to see what each stage produced |
| `checkpoints/step1.yaml` | The **auto-step1-derived exclusions** that model chose for this repo |
| `scan.log` | Full console transcript (stage progress, `[openai] prompt -> <model>` lines, per-call token usage) |
| `estimate.txt` | Pre-scan scope preview (no model spend) |

---

## How to read the results

1. **Start with `run_manifest.json`** — confirms which model/config/window
   actually ran and gives timing + token totals for cost/throughput comparison.
2. **`*_report.md`** — the findings. Note these are **triage candidates, not
   confirmed vulnerabilities** (the tool says so itself). Compare counts,
   classes, and quality across models for the same repo.
3. **`*_report.sarif`** — for tooling / diffing findings programmatically.
4. **`scan.log` + `*_errors.jsonl`** — how the run *behaved*: JSON-parse
   failures, dropped findings, stage timeouts, force-finalized agentic loops.
   For the thinking model (B) this is where reasoning-token pollution shows up.
5. **`checkpoints/step1.yaml`** — what scope each model selected (differs per
   model because of `--auto-step1`).

Cross-model comparison lives in the parallel trees: e.g.
`qwen2.5-coder-14b-32k/nokogiri/` vs `qwen3.6-36b-128k/nokogiri/` vs
`claude-opus-4-8/nokogiri/`. Opus 4.8 is the frontier ceiling — read the locals
*against* it (what did the 14B/36B miss or hallucinate relative to Opus on the
same repo), not just against each other.

---

## Caveats (read before drawing conclusions)

- **Findings are triage candidates**, not verified vulnerabilities. Adversarial
  verification (s6) reduces false positives but does not eliminate them.
- **Local-model quality.** A 9-stage *adversarial* SAST pipeline is demanding;
  small/quantized local models produce weaker, noisier results than the frontier
  models vvaharness ships against. Treat absolute numbers cautiously; the value
  is the *relative* tool×model comparison.
- **Thinking-model JSON risk (Model B).** Qwen3.6 emits reasoning tokens that can
  leak into the JSON stages (s2/s3/s4/s7). `vvaharness/models.py` coercion
  absorbs most off-schema output; the rest surfaces in `scan.log`/`errors.jsonl`
  — itself a benchmark data point.
- **Context is a co-variable.** "Each model at its own max" means a model
  difference and a window difference are confounded. Don't attribute a delta to
  the model alone.
- **`--auto-step1` makes scope model-dependent.** Each run's `checkpoints/step1.yaml`
  records the exact files in/out of scope for that model+repo. Coverage numbers
  in two reports are only comparable in light of those scope choices.
- **Quantization & runtime.** Both *local* models are Q4_K_M. Qwen3.6 at 128k
  allocates a large KV cache; if it was lowered to fit hardware (e.g. `-64k`),
  the dir/label and `Modelfile.qwen3.6` reflect the value actually used. Opus 4.8
  is full-precision cloud inference — not directly comparable on a quantization
  axis.
- **Cost asymmetry (Model C).** The two local models are free (your GPU); Opus 4.8
  spends real Anthropic tokens — full 180k budgets × 9 stages × 3 repos. `runs:1`
  keeps it from 4×-ing. Per-run token/cost provenance is in each
  `run_manifest.json`; `estimate.txt` is the pre-spend scope preview.
- **Backend asymmetry.** Locals run `via:openai` (Ollama); Opus runs `via:cli`
  pointed at **AWS Bedrock** (the Claude subscription was token-bound). The
  agentic tool surface is held identical (Read/Glob/Grep) so this is an
  auth/transport difference, not a capability one.

### Run isolation (how the matrix was produced safely)

vvaharness writes every run to `<repo>/security-scan` + `<repo>/checkpoints` with
a **run-id derived from the repo path**, so **two scans of the same repo at once
collide** — regardless of model. Rules used:

- **One scan per repo at a time.** The two *local* models (A, B) also share a
  single GPU / one Ollama server, so they run strictly sequentially to each other
  anyway.
- **Opus (cloud) may run in parallel with a local scan — but on a *different*
  repo.** It uses Anthropic cloud, not the GPU, so there's no resource
  contention; the only constraint is the per-repo lock above.
- Each run's artifacts are **moved out** of the source repo into this tree only
  after a clean finish (`mv` guarded on exit status), so a failed run never
  pollutes the matrix and the source repos return to a clean git state.

---

## Observed model behaviors (from pilot runs)

Empirical notes from validation runs, recorded so they're not mistaken for tool
bugs. Both are graceful degradations, not crashes.

- **14B emits malformed `--auto-step1` YAML.** On `qwen2.5-coder-14b-32k`, the
  auto-step1 survey returned an unquoted glob (`- **/node_modules/**`), which is
  invalid YAML. vvaharness caught it, logged
  `[auto-step1] WARN: model YAML unparseable … writing empty overlay`, and fell
  back to the **static `config.yaml` exclusions**. Net effect: `--auto-step1` is
  *partially ineffective* on the 14B — `checkpoints/step1.yaml` for its runs will
  often be an empty overlay. Treat any 14B-vs-Qwen3.6 scope difference in that
  light; the cause may be auto-step1 parse failure, not a real scope judgment.
- **Sparse Step 1 extraction on low-surface repos.** A pilot s1 on `underscore`
  yielded `0 modules, 0 entry points, 0 sinks` (with the agentic loop finishing
  in 1 turn / 0 tool calls). For `underscore` this is *partly legitimate* — it's a
  pure utility library with no network/IPC attack surface — but it also indicates
  the 14B drives the agentic Read/Glob/Grep exploration weakly. **Do not judge
  model capability from `underscore`;** `juice-shop` (a deliberately vulnerable
  web app) is the discriminating target. If a model returns near-empty s1 on
  `juice-shop`, downstream stages will have little to work with and the report
  will be hollow — that is a model result, not a tool failure.

---

## Reproducing a run

The exact configs, Modelfiles, and model snapshots used are in `_meta/`. To
re-run a single cell of the matrix from the harness repo
(`/home/higgs/workspace/cyness/visa-vulnerability-agentic-harness`):

```bash
# Local models (A / B):
export OLLAMA_MODEL=qwen3.6-36b-128k          # or qwen2.5-coder-14b-32k
.venv/bin/vvaharness scan \
  --repo /home/higgs/workspace/cyness/<repo> \
  --config ./config.qwen3.6.yaml \            # or ./config.yaml for the 14B
  --auto-step1 --application-id "bench-<repo>" --repo-name "<repo>"

# Frontier model (C) — Opus 4.8 on AWS Bedrock (no OLLAMA_MODEL):
export AWS_BEARER_TOKEN_BEDROCK="$BEDROCK_API_KEY"     # .env sets CLAUDE_CODE_USE_BEDROCK=1, AWS_REGION
.venv/bin/vvaharness scan \
  --repo /home/higgs/workspace/cyness/<repo> \
  --config ./config.opus.yaml \
  --auto-step1 --application-id "bench-<repo>" --repo-name "<repo>"
# convenience wrapper (B-guarded, integrity gate): scripts/run_opus_bedrock.sh <repo>

# then move <repo>/security-scan and <repo>/checkpoints into the matching
# benchmarks/visa/<model>/<repo>/ directory.
```

Backends: the local models run `via: openai` → Ollama `/v1` (`OPENAI_API_KEY` is
a placeholder `ollama`; Ollama ignores it but preflight requires it non-empty;
the `OLLAMA_MODEL` shell export wins over `.env`). Opus 4.8 runs `via: cli` → the
`claude` CLI in **Bedrock mode** (`CLAUDE_CODE_USE_BEDROCK=1` + `AWS_REGION` in
`.env`, `AWS_BEARER_TOKEN_BEDROCK` from your shell). The earlier Claude Code
subscription path was abandoned as token-bound (see the model-comparison doc).
