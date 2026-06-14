# Agentic SAST Harness Benchmark

A comparative benchmark of **agentic security-scanning harnesses** run against a
common set of open-source target repositories. The goal is to compare how
different harnesses (and the models driving them) perform at the same
vulnerability-discovery task on the same code.

> **Stub** — fill in methodology, scoring, and results summaries as runs complete.

## Harnesses under test

| Harness | Output dir | Repo |
|---|---|---|
| Visa vvaharness (9-stage agentic SAST pipeline) | `benchmarks/visa/` | https://github.com/visa/visa-vulnerability-agentic-harness |
| Anthropic defending-code reference harness (threat-model / vuln-scan / triage skills) | `benchmarks/anthropics/` | https://github.com/anthropics/defending-code-reference-harness |

## Target repositories

| Target | Language(s) | Repo |
|---|---|---|
| nokogiri | Ruby + C extension | https://github.com/sparklemotion/nokogiri |
| OWASP Juice Shop | JavaScript/TypeScript | https://github.com/juice-shop/juice-shop |
| underscore | JavaScript | https://github.com/jashkenas/underscore |

## Layout

```
cyness/
├── README.md                 # this file
├── benchmarks/
│   ├── visa/                 # vvaharness results (see benchmarks/visa/README.md)
│   └── anthropics/           # defending-code-reference-harness results
├── nokogiri/   juice-shop/   underscore/        # target repos (cloned, git-ignored)
├── visa-vulnerability-agentic-harness/          # harness (cloned, git-ignored)
└── defending-code-reference-harness/            # harness (cloned, git-ignored)
```

The target repos and harnesses are **cloned separately** and excluded via
`.gitignore` — only the `benchmarks/` artifacts and this repo's own files are
tracked here. See **`benchmarks/visa/README.md`** for the detailed vvaharness
model matrix, run configs, and how to read the per-scan artifacts.

## Reproducing

Clone the targets and harnesses into this directory, then run each harness per
its own instructions, writing artifacts under the matching `benchmarks/<harness>/`
tree:

```bash
git clone https://github.com/sparklemotion/nokogiri.git
git clone https://github.com/juice-shop/juice-shop.git
git clone https://github.com/jashkenas/underscore.git
git clone https://github.com/visa/visa-vulnerability-agentic-harness.git
git clone https://github.com/anthropics/defending-code-reference-harness.git
```
