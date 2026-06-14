# Anthropic defending-code Harness — Benchmark Results

Results from the **Anthropic defending-code reference harness**
(https://github.com/anthropics/defending-code-reference-harness) run against the
three shared target repos. Unlike the Visa `vvaharness` 9-stage pipeline (see
`../visa/`), this harness is driven by three **skill workflows** invoked in
sequence:

| Skill / workflow | Produces |
|---|---|
| `/threat-model` | `THREAT_MODEL.md` — assets, trust boundaries, ranked threats |
| `/vuln-scan` | `VULN-FINDINGS.md` + `VULN-FINDINGS.json` — raw findings (human + machine) |
| `/triage` | `TRIAGE.md` + `TRIAGE.json` — verified / prioritized findings after review |

> **Stub** — fill in methodology, per-model scoring, and a results summary as the
> matrix completes.

## Matrix

A 2 × 3 matrix: **two models × three targets**.

### Models

| Label (dir) | Model | Driver |
|---|---|---|
| `opus/` | Claude Opus (Anthropic, cloud) | defending-code harness skills |
| `qwen3.6/` | Qwen3.6 36B MoE (local) | defending-code harness skills via local model |

`opus` is the frontier reference; `qwen3.6` is the local open-weight comparison
(the same 36B MoE family used as Model B in the `../visa/` benchmark — read the
two harnesses against each other for the same model where possible).

### Targets

| Target | Repo |
|---|---|
| nokogiri | https://github.com/sparklemotion/nokogiri |
| OWASP Juice Shop | https://github.com/juice-shop/juice-shop |
| underscore | https://github.com/jashkenas/underscore |

## Layout

```
benchmarks/anthropics/
├── README.md                 # this file
├── opus/                     # Claude Opus results
│   ├── nokogiri/             # THREAT_MODEL.md, VULN-FINDINGS.{md,json}, TRIAGE.{md,json}
│   ├── juice-shop/
│   └── underscore/
└── qwen3.6/                  # Qwen3.6 results (+ run screenshots)
    ├── nokogiri/
    ├── juice-shop/
    ├── underscore/
    ├── finished.png                     # run evidence / console captures
    ├── qwen_antrhopics_false_start.png
    ├── qwen_antro_start2.png
    └── resources.png
```

### How to read

1. `THREAT_MODEL.md` — the model's threat model for the target (context for the
   scan).
2. `VULN-FINDINGS.md` / `.json` — raw findings from `/vuln-scan` (the `.json` is
   the machine-readable form for diffing/scoring across models and harnesses).
3. `TRIAGE.md` / `.json` — post-review verdicts; this is the "confirmed" set to
   compare against the Visa harness's verified findings for the same repo.

Cross-harness comparison: pair each repo here with its counterpart under
`../visa/<model>/<repo>/` — e.g. `qwen3.6/nokogiri/TRIAGE.json` (skills harness)
vs `../visa/qwen3.6-36b-128k/nokogiri/security-scan/*.sarif` (pipeline harness).

## Known gaps (as of this writing)

- **`qwen3.6/juice-shop/` is missing `TRIAGE.md`** (has `TRIAGE.json`,
  `THREAT_MODEL.md`, `VULN-FINDINGS.{md,json}`) — the triage write-up did not
  complete for that cell; re-run `/triage` to fill it.
- The `qwen3.6/` PNGs (`*false_start*`, `*start2*`) suggest one or more aborted
  runs before a clean pass — context for any anomalies in that model's results.
