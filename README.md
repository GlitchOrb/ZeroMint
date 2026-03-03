# ZeroMint

> **WARNING ??AUTHORIZED TARGETS ONLY**
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

1. **Code Indexing** ??Parse & build call/data-flow graphs (tree-sitter)
2. **Static Analysis** ??Narrow candidates via Semgrep / CodeQL
3. **Hypothesis Generation** ??LLM reasons about potential vulnerabilities
4. **Harness Generation** ??LLM creates non-destructive PoC test harnesses
5. **Sandbox Execution** ??Run in Docker (network=none, resource limits, ASan/UBSan)
6. **Self-Correction** ??Feed errors back to LLM for iterative repair
7. **Triage** ??Validate evidence, deduplicate, assign severity
8. **Reporting** ??Generate CVE-draft-ready REPORT.md + evidence bundle

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
# Basic usage
zeromint recon -c config.yaml

# With custom run ID and verbose output
zeromint recon -c config.yaml --run-id recon-001 --verbose
```

**Outputs** (`runs/<run_id>/artifacts/`):
- `repo_index.json` ??file catalogue with language guess, size, counts
- `hotspots.json` ??top-50 candidates scored by keyword signals

**Hotspot scoring** considers:
- Filename signals: `auth`, `jwt`, `token`, `session`, `crypto`,
  `deserialize`, `eval`, `exec`, `shell`, `sql`, `upload`, ...
- Code content keywords: `eval()`, `exec()`, `subprocess`, `pickle`,
  `os.system`, `strcpy`, `innerHTML`, SQL keywords, ...

**Ignore patterns**: Built-in defaults (`.git`, `node_modules`, `__pycache__`,
`dist`, `build`, `venv`, ...) plus user-defined patterns via
`target.ignore_patterns` in `config.yaml`.

### `zeromint graph`

Parse source files with tree-sitter, extract function/class code units,
and build a call graph.

```bash
# Basic usage
zeromint graph -c config.yaml

# With custom run ID
zeromint graph -c config.yaml --run-id graph-001 --verbose
```

**Outputs** (`runs/<run_id>/artifacts/`):
- `code_units.json` ??extracted functions/classes with signatures, text, location
- `call_graph.json` ??nodes + directed edges (caller ??callee symbol)

**Supported languages**: Python, JavaScript/TypeScript.

**Retriever** (programmatic API):
```python
from cve_agent.graph.retriever import CodeRetriever
retriever = CodeRetriever(units_artifact)
results = retriever.retrieve("eval injection", top_k=10)
for unit, score in results:
    print(f"  [{score:.1f}] {unit.unit_id}")
```

### `zeromint static`

Run static analysis using Semgrep and/or CodeQL. Automatically runs
recon and graph (if enabled) first.

```bash
# Basic usage (runs recon ??graph ??static)
zeromint static -c config.yaml

# Verbose with custom run ID
zeromint static -c config.yaml --run-id static-001 --verbose
```

**Tool behaviour:**

| Tool | Installed | Not installed |
|------|-----------|---------------|
| Semgrep | Runs `semgrep --json --config auto`, normalises results | Logs warning, skips |
| CodeQL | Creates DB + runs security-extended suite | Logs warning, skips |

**Outputs** (`runs/<run_id>/artifacts/`):
- `semgrep_raw.json` / `semgrep_candidates.json` ??raw + normalized Semgrep findings
- `codeql_raw.json` / `codeql_candidates.json` ??raw SARIF + normalized CodeQL findings

**Normalisation rules:**
- `Finding.status = "candidate"` (never auto-confirmed)
- `Finding.id` = stable SHA-256 hash of `file + rule + line` (deterministic across runs)
- Severity mapping: ERROR/error ??HIGH, WARNING/warning ??MEDIUM, INFO/note ??LOW
- Confidence is conservative (0.2??.7 depending on tool severity)
- Each Finding includes an EvidenceItem with `kind="tool_output"`, location, and snippet

**Installing tools:**
```bash
# Semgrep (recommended)
pip install semgrep

# CodeQL (optional)
# Download from https://github.com/github/codeql-cli-binaries/releases
```

### `zeromint hypothesize`

Generate vulnerability hypotheses from hotspots + static analysis results.

```bash
# Offline mode (no LLM ??rule-based)
zeromint hypothesize -c config.yaml

# With DummyLLM (for testing)
# Set llm.enabled: true, llm.provider: dummy in config.yaml
zeromint hypothesize -c config.yaml --verbose
```

**Modes:**

| Mode | Config | Description |
|------|--------|-------------|
| Offline | `llm.enabled: false` | Keyword + hotspot scoring ??hypothesis (conservative) |
| LLM | `llm.enabled: true` | Retriever gathers code context ??LLM produces JSON hypothesis |

**Outputs** (`runs/<run_id>/artifacts/`):
- `hypotheses.json` ??Finding[] with `hypothesis` field populated

**Every hypothesis includes:**
- `vuln_type`, `attack_surface`, `preconditions`, `exploit_idea`
- `confidence` (conservative: ??0.4 offline, ??0.5 LLM)
- `related_sinks`, `related_sources`
- `self_critique` (mandatory ??agent's own false-positive assessment)

### `zeromint generate-tests`

Generate verification tests and harnesses from hypotheses.

```bash
# Generate + run tests
zeromint generate-tests -c config.yaml

# Generate only (skip execution)
zeromint generate-tests -c config.yaml --dry-run
```

**Python targets:**
- pytest test files with boundary/encoding/length/null/unicode inputs
- Parametrized tests per vulnerability type
- Optional: property-based tests (if `hypothesis` library installed)

**C/C++ targets (optional):**
- libFuzzer `LLVMFuzzerTestOneInput` harness template
- Makefile or CMakeLists.txt build script with `-fsanitize=fuzzer,address`

**Self-correction loop:**
- Runs generated tests in subprocess
- Parses failures, generates fix instructions
- Up to 3 retry iterations with auto-fix for common issues
- **No network calls** ??local execution only

**Outputs** (`runs/<run_id>/artifacts/`):
- `harnesses/<finding_id>/test_<id>.py` ??generated pytest files
- `harnesses/<finding_id>/harness.c` + `Makefile` ??C/C++ harnesses
- `fuzz_attempts.json` ??status tracking for each generation attempt

### `zeromint execute`

Run generated tests in a sandbox and produce validation results.

```bash
# Full execution (uses Docker if available, local fallback)
zeromint execute -c config.yaml

# Dry-run (validate structure without running)
zeromint execute -c config.yaml --dry-run
```

**Sandbox safety:**
- `--network=none` by default (can't be overridden in production)
- CPU / memory limits enforced
- Hard timeout with forced container kill
- Repository mounted read-only
- All capabilities dropped (`--cap-drop=ALL`)
- stdout/stderr logs saved to `artifacts/logs/`

**Sanitizers (C/C++ only, if `enable_sanitizers: true`):**
- ASan / UBSan flags injected into Makefile / CMakeLists.txt
- Sanitizer output parsed and attached as EvidenceItem

**Outputs:**
- `validation_results.json` ??per-finding outcome (success/failure/crash/timeout)
- `logs/<label>.log` ??stdout/stderr capture per execution

### `zeromint init / doctor / run`

### `zeromint triage`

Assess findings conservatively. Runs full pipeline through triage.

```bash
zeromint triage -c config.yaml
zeromint triage -c config.yaml --dry-run   # skip execution, triage on stale artifacts
```

**Decision rules (very conservative):**
- `confirmed` ??ONLY with dynamic crash evidence (sanitizer, signal, exit < 0)
- `potential` ??security hypothesis is plausible but no dynamic proof
- `false_positive` ??environment error, unknown vuln_type, or all tests pass cleanly
- `candidate` ??insufficient data (no validation ran)

**Outputs:**
- `triage.json` ??per-finding verdict, rationale, next investigation steps
- `findings.json` ??updated Finding[] with final statuses

### `zeromint report`

Generate the final REPORT.md and evidence bundle (full pipeline).

```bash
zeromint report -c config.yaml
zeromint report -c config.yaml --dry-run
```

**REPORT.md sections:**
1. Executive Summary (finding counts, severity distribution)
2. Findings Table (sorted by status/severity)
3. Finding Details (evidence, hypothesis, reproduction, mitigation)
4. CVE Draft Templates (confirmed + potential only, with TBD fields)
5. False Positives (collapsed section)
6. Responsible Disclosure guidance

**Evidence bundle** (`evidence_bundle.zip`):
- REPORT.md + all JSON artifacts + logs + harnesses

### `zeromint init / doctor / run`

See `zeromint --help` for full details.

The `run` command executes the **full 8-stage pipeline** end-to-end:

```
recon ??graph ??static ??hypothesize ??generate ??execute ??triage ??report
```

**Pipeline features:**
- **Checkpointing**: if an artifact exists from a previous run, the stage is skipped
- **continue_on_fail**: if `true`, errors in one stage don't abort the pipeline
- **Budget management**: token/cost limits enforced before LLM stages
- **State persistence**: `pipeline_state.json` records per-stage status/error

## Project Structure

```
cve_agent/
  cli.py            # Typer CLI (init ~ report, run)
  config.py         # YAML + .env config loading
  run_context.py    # Run ID, directory setup, logging
  logging.py        # Structured dual logging (console + file)
  pipeline.py       # State-machine pipeline (8 stages, checkpointing)
  agents/
    hypothesis_agent.py  # Hypothesis generation (offline + LLM)
    llm_clients/
      base.py       # Abstract LLM client interface
      dummy.py      # Deterministic placeholder LLM
  analyzers/
    repo_indexer.py       # File indexing + hotspot scoring
    semgrep_scanner.py    # Semgrep integration
    codeql_runner.py      # CodeQL integration
    normalize_findings.py # Raw ??Finding normalisation
    execution.py          # Validation runner + sanitizer logic
  fuzz/
    test_generator.py     # pytest test generation
    harness_generator.py  # libFuzzer harness generation
    self_correction.py    # Run?’parse?’fix loop (max 3 iterations)
  graph/
    code_parser.py  # tree-sitter AST parsing
    code_units.py   # CodeUnit / CallGraph schemas
    call_graph.py   # Graph builder
    retriever.py    # Keyword + TF-IDF code retrieval
  reporting/
    report_md.py    # REPORT.md generator
    bundler.py      # evidence_bundle.zip creator
  sandbox/
    docker_runner.py  # Docker container execution with resource limits
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
  ignore_patterns: []              # extra globs on top of built-in ignores

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
  max_tokens: null                 # max total tokens (null = unlimited)
  max_cost_usd: null               # max cost in USD

retriever:
  top_k: 10                       # max code snippets per LLM query
  max_snippet_len: 500             # max chars per snippet

continue_on_fail: false            # true = continue past stage failures
```

## Testing

```bash
pytest
pytest --cov=cve_agent
```

## License

MIT ??Research and authorized security testing only.

