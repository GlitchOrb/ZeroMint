# ZeroMint

[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://ssh.cloud.google.com/cloudshell/editor?cloudshell_git_repo=https://github.com/GlitchOrb/ZeroMint)

> **WARNING: AUTHORIZED TARGETS ONLY**
>
> This tool is designed **exclusively** for security research on code you own,
> authorized bug-bounty programs, and controlled test environments.
> **Do NOT use it against any system without explicit written permission.**
> Unauthorized scanning, exploitation, or data exfiltration is illegal and
> strictly prohibited. The authors accept no liability for misuse.

---

**LLM Agent-based Vulnerability Detection & Automated PoC/Triage Platform (Research/Defense)**

## Overview

ZeroMint automates the vulnerability research workflow:

1. **Code Indexing** - Parse & build call/data-flow graphs (tree-sitter)
2. **Static Analysis** - Narrow candidates via Semgrep / CodeQL
3. **Hypothesis Generation** - LLM reasons about potential vulnerabilities
4. **Harness Generation** - LLM creates non-destructive PoC test harnesses
5. **Sandbox Execution** - Run in Docker (network=none, resource limits, ASan/UBSan)
6. **Self-Correction** - Feed errors back to LLM for iterative repair
7. **Triage** - Validate evidence, deduplicate, assign severity
8. **Reporting** - Generate CVE-draft-ready REPORT.md + evidence bundle

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Create config from template
zeromint init

# Check tool availability
zeromint doctor

# Index a repo and find hotspots
zeromint recon -c config.yaml

# Run full analysis pipeline
zeromint run -c config.yaml
```

## Commands

### `zeromint recon`

Index a local repository, catalogue files by language, and score
security-relevant hotspot candidates.

```bash
zeromint recon -c config.yaml
zeromint recon -c config.yaml --run-id recon-001 --verbose
```

**Outputs** (`runs/<run_id>/artifacts/`):
- `repo_index.json` - file catalogue with language guess, size, counts
- `hotspots.json` - top-50 candidates scored by keyword signals

**Hotspot scoring** considers:
- Filename signals: `auth`, `jwt`, `token`, `session`, `crypto`,
  `deserialize`, `eval`, `exec`, `shell`, `sql`, `upload`, ...
- Code content keywords: `eval()`, `exec()`, `subprocess`, `pickle`,
  `os.system`, `strcpy`, `innerHTML`, SQL keywords, ...

### `zeromint graph`

Parse source files with tree-sitter, extract function/class code units,
and build a call graph.

```bash
zeromint graph -c config.yaml
zeromint graph -c config.yaml --run-id graph-001 --verbose
```

**Outputs** (`runs/<run_id>/artifacts/`):
- `code_units.json` - extracted functions/classes with signatures, text, location
- `call_graph.json` - nodes + directed edges (caller -> callee symbol)

**Supported languages**: Python, JavaScript/TypeScript.

### `zeromint static`

Run static analysis using Semgrep and/or CodeQL.

```bash
zeromint static -c config.yaml
zeromint static -c config.yaml --run-id static-001 --verbose
```

**Outputs** (`runs/<run_id>/artifacts/`):
- `semgrep_raw.json` / `semgrep_candidates.json` - raw + normalized Semgrep findings
- `codeql_raw.json` / `codeql_candidates.json` - raw SARIF + normalized CodeQL findings

**Normalisation rules:**
- `Finding.status = "candidate"` (never auto-confirmed)
- `Finding.id` = stable SHA-256 hash of `file + rule + line`
- Severity mapping: ERROR -> HIGH, WARNING -> MEDIUM, INFO -> LOW
- Confidence is conservative (0.2-0.7 depending on tool severity)

### `zeromint hypothesize`

Generate vulnerability hypotheses from hotspots + static analysis results.

```bash
zeromint hypothesize -c config.yaml
zeromint hypothesize -c config.yaml --verbose
```

| Mode | Config | Description |
|------|--------|-------------|
| Offline | `llm.enabled: false` | Keyword + hotspot scoring -> hypothesis (conservative) |
| LLM | `llm.enabled: true` | Retriever gathers code context -> LLM produces JSON hypothesis |

**Outputs**: `hypotheses.json` - Finding[] with `hypothesis` field populated

### `zeromint generate-tests`

Generate verification tests and harnesses from hypotheses.

```bash
zeromint generate-tests -c config.yaml
zeromint generate-tests -c config.yaml --dry-run
```

- pytest test files with boundary/encoding/length/null/unicode inputs
- libFuzzer harness template for C/C++ targets
- Self-correction loop (up to 3 retries)
- **No network calls** - local execution only

### `zeromint execute`

Run generated tests in a sandbox and produce validation results.

```bash
zeromint execute -c config.yaml
zeromint execute -c config.yaml --dry-run
```

**Sandbox safety**: `--network=none`, CPU/mem limits, hard timeout, read-only mount, `--cap-drop=ALL`

**Outputs**: `validation_results.json` - per-finding outcome (success/failure/crash/timeout)

### `zeromint triage`

Assess findings conservatively.

```bash
zeromint triage -c config.yaml
zeromint triage -c config.yaml --dry-run
```

**Decision rules (very conservative):**
- `confirmed` - ONLY with dynamic crash evidence (sanitizer, signal, exit < 0)
- `potential` - security hypothesis is plausible but no dynamic proof
- `false_positive` - environment error, unknown vuln_type, or all tests pass cleanly
- `candidate` - insufficient data (no validation ran)

**Outputs**: `triage.json` + `findings.json`

### `zeromint report`

Generate the final REPORT.md and evidence bundle.

```bash
zeromint report -c config.yaml
zeromint report -c config.yaml --dry-run
```

**REPORT.md sections:**
1. Executive Summary (finding counts, severity distribution)
2. Findings Table (sorted by status/severity)
3. Finding Details (evidence, hypothesis, reproduction, mitigation)
4. CVE Draft Templates (confirmed + potential only)
5. Responsible Disclosure guidance

**Evidence bundle** (`evidence_bundle.zip`): REPORT.md + all JSON artifacts + logs + harnesses

### `zeromint run`

Run the full 8-stage pipeline end-to-end.

```bash
zeromint run -c config.yaml
```

```
recon -> graph -> static -> hypothesize -> generate -> execute -> triage -> report
```

**Pipeline features:**
- **Checkpointing**: if an artifact exists, the stage is skipped
- **continue_on_fail**: errors in one stage don't abort the pipeline
- **Budget management**: token/cost limits enforced before LLM stages
- **State persistence**: `pipeline_state.json` records per-stage status/error

See `zeromint --help` for all commands including `init` and `doctor`.

## Project Structure

```
cve_agent/
  cli.py            # Typer CLI
  config.py         # YAML + .env config loading
  pipeline.py       # State-machine pipeline (8 stages, checkpointing)
  run_context.py    # Run ID, directory setup, logging
  logging.py        # Structured dual logging (console + file)
  agents/
    hypothesis_agent.py  # Hypothesis generation (offline + LLM)
    llm_clients/
      base.py       # Abstract LLM client interface
      dummy.py      # Deterministic placeholder LLM
  analyzers/
    repo_indexer.py       # File indexing + hotspot scoring
    semgrep_scanner.py    # Semgrep integration
    codeql_runner.py      # CodeQL integration
    normalize_findings.py # Raw -> Finding normalisation
    execution.py          # Validation runner + sanitizer logic
  fuzz/
    test_generator.py     # pytest test generation
    harness_generator.py  # libFuzzer harness generation
    self_correction.py    # Run -> parse -> fix loop (max 3 iterations)
  graph/
    code_parser.py  # tree-sitter AST parsing
    code_units.py   # CodeUnit / CallGraph schemas
    call_graph.py   # Graph builder
    retriever.py    # Keyword + TF-IDF code retrieval
  reporting/
    report_md.py    # REPORT.md generator
    bundler.py      # evidence_bundle.zip creator
  sandbox/
    docker_runner.py  # Docker container execution
  triage/
    triage_agent.py   # Conservative triage assessment
  schemas/
    config.py       # RunConfig pydantic schema
    findings.py     # CodeLocation, EvidenceItem, Hypothesis, Finding
    run.py          # RunResult
  utils/
    fs.py           # Filesystem helpers
    hashing.py      # Hashing utilities
```

## Configuration

Edit `config.yaml` (generated via `zeromint init`):

```yaml
target:
  type: repo
  path_or_url: ./my-project
  languages_hint: [python]
  ignore_patterns: []

features:
  enable_graph: true
  enable_semgrep: false
  enable_codeql: false
  enable_fuzz: true
  enable_sanitizers: false

sandbox:
  enabled: true
  network_off: true
  cpu: 1.0
  mem_mb: 512
  timeout_sec: 60

llm:
  enabled: false
  provider: null
  model: null

budget:
  max_tokens: null
  max_cost_usd: null

retriever:
  top_k: 10
  max_snippet_len: 500

continue_on_fail: false
```

## Testing

```bash
pytest
pytest --cov=cve_agent
```

## License

MIT - Research and authorized security testing only.
