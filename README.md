# CloudScanner-AI

**AI-assisted penetration testing of AWS cloud environments — automated discovery, validation and classification of IAM privilege-escalation paths.**

CloudScanner-AI enumerates an AWS account's services, identities and access
policies, resolves the caller's *effective* permissions, and systematically
discovers, validates and classifies **privilege-escalation paths** (for example
policy-version rollback, access-key rotation, role and instance-profile abuse,
and Lambda-based escalation). Each finding is rated on two independent axes
(severity and validation status) and compiled into a report with reproducible
AWS CLI steps.

The system pairs a layer of **deterministic Python scanners** with a layer of
**multi-agent AI evaluation** that curates, prioritises, reviews and classifies
findings. It was built as a bachelor's thesis and tested against a vulnerable
[CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) scenario.

> **Authorized use only.** This is a security-assessment tool. Run it only
> against AWS accounts you own or have **explicit written permission** to test.
> Unauthorised scanning or exploitation of AWS accounts is illegal. The author
> accepts no liability for misuse. See [LICENSE](LICENSE).

---

## Table of contents

- [How it works](#how-it-works)
- [Deterministic scanners](#deterministic-scanners)
- [AI agents](#ai-agents)
- [Core and tool modules](#core-and-tool-modules)
- [Classification model](#classification-model)
- [Output artifacts](#output-artifacts)
- [Project layout](#project-layout)
- [Requirements and installation](#requirements-and-installation)
- [Usage](#usage)
- [Safety and privacy](#safety-and-privacy)

---

## How it works

An analysis run flows through an ordered pipeline. Every stage writes one JSON
artifact into `runs/<run_id>/`, and each stage reads only the small artifacts it
needs from the stage before it.

```
collect  ->  analyze  ->  curate paths  ->  plan candidates
   ->  validate (IAM / Lambda / general)  ->  summarize  ->  report
```

Two layers cooperate:

- **Deterministic core** — plain Python with `boto3`. It collects evidence and
  produces reproducible JSON artifacts. This layer needs no AI and never
  performs active exploitation. Its output is a *potential* attack path.
- **Multi-agent evaluation** — ten agents running on **Kiro CLI** (LLM
  inference through **Amazon Bedrock**) and coordinated by the
  **[CLI Agent Orchestrator, CAO](https://github.com/awslabs/cli-agent-orchestrator)**.
  A supervisor hands work to single-purpose workers that curate, route,
  validate and report on the findings.

> The deterministic layer and CAO orchestration run locally, but LLM inference
> is delegated to Amazon Bedrock, so an AWS connection is required and the
> multi-agent mode cannot run fully offline.

---

## Deterministic scanners

The scanners live in `scanners/`. Each one reads from the shared `workspace.json`
state and the artifacts of earlier stages, and writes a normalised JSON result.

| File | Stage | What it does | Output |
|------|-------|--------------|--------|
| `iam_user_scan.py` | collect | Identifies the current IAM identity and collects its attached, inline and group policies together with all policy versions. Normalises policy documents and gathers their statements. | `01_iam_user_scan.json` |
| `policy_resource_followup.py` | collect | Follows the policies discovered above to the resources they reference, analyses role **trust policies**, and builds initial **pivot candidates** (identities the caller might move to). | `02_policy_resource_followup.json` |
| `targeted_service_probing.py` | service probe | Probes concrete services — **S3, EC2, Lambda, KMS, Secrets Manager** — against targeted detection rules. Every normalised finding carries a service, category, target, the tested API, the supporting evidence, a severity and a remediation hint. | `03_targeted_service_probing.json` |
| `permission_summary.py` | analyze | Builds a structured overview of the identity's **effective permissions** by expanding allow actions and resources and matching action patterns. | `11_permission_summary.json` |
| `iam_role_audit.py` | analyze | Audits roles reachable by the caller, inspects their trust policies and **assume-role paths**, and derives an assume-path **confidence** that feeds the role's risk level. | `12_iam_role_audit.json` |
| `review_path_curator.py` | review | Deterministic fallback that turns collected evidence into neutral **review paths** when the AI security analyst is not used. | `13_review_paths.json` |
| `access_candidate_builder.py` | review | Deterministic fallback that turns review paths into small, validator-ready **review candidates**. | `14_review_candidates.json` |
| `service_common.py` | shared | Helper library used by the scanners. Holds the shared risk scorer `score_risk`, a `policy_allows_public` check, safe AWS error handling, and environment helpers. | — |

---

## AI agents

The agents are defined in `agents/` (Markdown prompts) and `.kiro/agents/`
(JSON definitions for Kiro CLI). Every worker is a strict single-stage agent — it
does one job, never delegates, never runs stages in parallel, and then stops.
Only the supervisor orchestrates.

| Agent | Role | Reads | Writes |
|-------|------|-------|--------|
| `cloudscanner_supervisor` | **Orchestrator.** The only agent allowed to delegate. Hands off sequentially through CAO to each worker, routes by which finding families are present, composes the final overview and writes it out. | stage artifacts | `final_result_supervisor.txt` |
| `cloudscanner_scan_operator` | Runs the deterministic **collect** stage and returns the canonical `run_id` and artifact paths. | run manifest | collect artifacts |
| `cloudscanner_analyze_operator` | Runs the deterministic **analyze** stage. | run manifest | analyze artifacts |
| `cloudscanner_security_analyst` | **Review-path curator.** Converts deterministic evidence into a compact set of 0 to 6 review paths, normalised into the families `iam`, `lambda`, `general`. Captures the full multi-stage logical chain of each path and explicitly flags `SetDefaultPolicyVersion` escalation. | `01`, `12`, `03`, `11` | `13_review_paths.json` |
| `cloudscanner_risk_planner` | **Candidate planner.** Converts review paths into 0 to 8 small, deduplicated, validator-ready candidates. Assigns each one a single `preferred_validator`. | `13`, run manifest | `14_review_candidates.json` |
| `cloudscanner_iam_access_reviewer` | Validates **IAM-family** candidates (assume-role paths, `SetDefaultPolicyVersion` rollback, IAM write on another principal). Reverts any state change it makes. | `14` | `15_review_iam_access.json` |
| `cloudscanner_lambda_access_reviewer` | Validates **Lambda-family** candidates (function visibility, URL exposure, configuration and code review, sensitive-material detection). | `14`, `03` | `15_review_lambda_access.json` |
| `cloudscanner_general_access_reviewer` | Validates **everything else** — S3, KMS, Secrets Manager and other non-IAM, non-Lambda paths. | `14` | `15_review_general_access.json` |
| `cloudscanner_validation_auditor` | Builds the consolidated **validation summary** from the candidate file and the split validator outputs. | `14`, `15_*` | `16_validation_summary.json` |
| `cloudscanner_report_writer` | Runs the deterministic **report** stage and confirms the output files exist. | report artifacts | `report.md`, `report_summary.json` |

All reviewers share the same discipline: never invent ARNs, actions, resources or
proof, never reveal raw secret values, keep sensitive material redacted and record
only the signal plus location plus the high-level commands used, and emit a valid
empty artifact when no candidate of their family exists.

---

## Core and tool modules

**`main.py`** — command-line entry point for the deterministic pipeline. Maps the
actions `scan1`, `scan2`, `services`, `scan3`, `scan4`, `report`, `full` to the
right pipeline or scan command.

**`tools/`**

| File | What it does |
|------|--------------|
| `run_scan.py` | Builds the boto3 context (`build_ctx`) and runs a single scanner module (`run_module`). Normalises each module's return value and stores it into the shared `workspace.json`. |
| `run_pipeline.py` | Orchestrates the deterministic stages (`collect`, `service_collect`, `analyze`, `validation_summary`, `report`, `full`). Maintains `run_manifest.json` with the preflight result and the overall state (RUNNING, COMPLETED, ERROR). |
| `build_report.py` | Summarises validation status, derives follow-up findings and writes the final `report.md` plus the machine-readable `report_summary.json`. |
| `build_validation_summary.py` | Merges the split validator outputs and ranks them by evidence strength (`strength_rank`, `merge_result`). |

**`core/`**

| File | What it does |
|------|--------------|
| `context.py` | `AppContext` dataclass holding the AWS session and credentials plus shared run state. |
| `menu.py` | Interactive menu (`Menu`, `MenuItem`) for manual use. |
| `output.py` | Output and formatting helpers. |
| `runtime/preflight.py` | Preflight check via `sts.get_caller_identity`, run before any scanning. Returns a `PreflightResult` with `ok`, `account_id`, `arn`, `user_id`, `region`. |
| `runtime/run_id.py` | Builds the canonical `run_id` for a run (`build_run_id`). |

---

## Classification model

Findings are rated on **two independent axes**, and the final priority combines
both.

**Severity** (four levels, assigned by the deterministic scanners): **HIGH,
MEDIUM, LOW, INFO.** The shared `score_risk` function in `service_common.py`
derives the level from boolean signals, and `targeted_service_probing` assigns an
explicit severity per detection rule (for example a publicly accessible S3 bucket
is HIGH, and IMDSv1 enabled on an instance that has an attached role is HIGH).

**Confidence** (HIGH, MEDIUM, LOW): assigned to roles and pivot candidates from
the strength of the trust path (`_assume_path_confidence` in `iam_role_audit.py`),
and reflected in the role's `risk_level`.

**Validation status** (assigned by the reviewer agents): the deterministic output
is only a potential. The validation layer gives each candidate one of five
states.

| Status | Meaning |
|--------|---------|
| `confirmed` | Access was actually demonstrated. |
| `capability_only` | The permission exists, but access was not performed. |
| `failed` | A validation attempt was made and denied. |
| `inconclusive` | The result is ambiguous. |
| `not_validated` | The candidate was not validated. |

`build_validation_summary` aggregates these and orders them by evidence strength,
from strongest to weakest: `confirmed`, `capability_only`, `failed`,
`inconclusive`, `not_validated`. For duplicate candidates it keeps the one with
the strongest status.

---

## Output artifacts

All artifacts for a run are written to `runs/<run_id>/`.

| File | Contents |
|------|----------|
| `run_manifest.json` | Run metadata, pipeline state, preflight result. |
| `workspace.json` | Shared context passed between modules. |
| `01_iam_user_scan.json` | IAM identity, user / inline / group policies and versions. |
| `02_policy_resource_followup.json` | Enumerated resources, role trust analysis, pivot candidates. |
| `03_targeted_service_probing.json` | Findings for S3, EC2, Lambda, KMS and Secrets Manager. |
| `11_permission_summary.json` | Structured overview of the identity's permissions. |
| `12_iam_role_audit.json` | Role audit with trust policies and assume paths. |
| `13_review_paths.json` | Attack paths from the security analyst (or the curator fallback). |
| `14_review_candidates.json` | Validation candidates routed by family. |
| `15_review_iam_access.json` | IAM candidate validation. |
| `15_review_lambda_access.json` | Lambda candidate validation. |
| `15_review_general_access.json` | Validation of the remaining candidates. |
| `16_validation_summary.json` | Consolidated validation summary. |
| `report.md` | Final human-readable report. |
| `report_summary.json` | Machine-readable version of the report. |
| `final_result_supervisor.txt` | Final overview composed by the supervisor. |

---

## Project layout

```
core/        runtime helpers, menu, context, output
  runtime/   preflight check and run-id builder
scanners/    deterministic IAM / policy / service scanners
tools/       pipeline runner, scan runner, report builders
agents/      AI agent definitions (Markdown)
.kiro/       Kiro CLI agent definitions (JSON)
main.py      CLI entry point (deterministic pipeline)
runs/        per-run output artifacts (git-ignored)
```

---

## Requirements and installation

For the deterministic core:

- Python 3.11 or newer and `boto3` (see `requirements.txt`)
- AWS CLI v2 and AWS credentials for the target account (read access to IAM and
  the probed services)

For the multi-agent (AI) mode, additionally:

- [uv](https://docs.astral.sh/uv/) as package manager and runner
- **tmux** (CAO runs each agent in its own tmux session)
- **[Kiro CLI](https://kiro.dev/docs/cli/)** as the agent runtime, logged in
  with `kiro-cli login`
- **CAO (CLI Agent Orchestrator)** for multi-agent coordination

Install (AI mode):

```bash
# uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# AWS CLI v2 (Linux example, on macOS use the AWS pkg installer)
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o awscliv2.zip
unzip awscliv2.zip
sudo ./aws/install

# tmux (Debian / Ubuntu, on macOS use brew install tmux)
sudo apt-get install -y tmux

# Kiro CLI
curl -fsSL https://cli.kiro.dev/install | bash
kiro-cli login

# CAO
uv tool install git+https://github.com/awslabs/cli-agent-orchestrator.git@main --upgrade

# CloudScanner-AI
git clone https://github.com/xchabadaj/CloudScanner-AI.git
cd CloudScanner-AI
pip install -r requirements.txt
```

AWS credentials, either as environment variables:

```bash
export AWS_ACCESS_KEY_ID="<ACCESS_KEY>"
export AWS_SECRET_ACCESS_KEY="<SECRET_KEY>"
export AWS_DEFAULT_REGION="us-east-1"
aws sts get-caller-identity
```

or in `~/.aws/credentials`:

```ini
[default]
aws_access_key_id = <AWS_ACCESS_KEY>
aws_secret_access_key = <AWS_SECRET_KEY>
aws_session_token = <AWS_TOKEN>
```

The agent profiles in `.kiro/agents/` are made available to Kiro CLI.

---

## Usage

**Deterministic pipeline (no AI).** Run the full pipeline:

```bash
python3 main.py full
```

Or run individual stages:

```bash
python3 main.py scan1      # IAM user scan
python3 main.py scan2      # policy resource follow-up
python3 main.py services   # targeted service probing
python3 main.py scan3      # permission summary
python3 main.py scan4      # IAM role audit
python3 main.py report     # build report from an existing run
```

**Multi-agent mode (Kiro CLI and CAO).** In two terminals:

```bash
# Terminal 1 — start the CAO server
cao-server

# Terminal 2 — launch the supervisor agent
cao launch --agents cloudscanner_supervisor --provider kiro_cli --auto-approve
```

The supervisor drives collection, analysis, review, validation and reporting
across the worker agents. Each run produces a `runs/<run_id>/` folder with the
stage artifacts and a final `report.md`.

---

## Safety and privacy

- `runs/` is git-ignored because scan outputs contain **real account
  identifiers, ARNs and IAM policy data**. They are never committed.
- Credentials are read only from the environment or the AWS config. No secret is
  written into the repository.
- The deterministic layer performs no active exploitation. Its output is a
  potential path, confirmed only by the validation layer.
- Reviewers keep sensitive material redacted and record only the signal, the
  location and the high-level commands used.

## Author

**Ján Chabada** — bachelor's thesis, 2026.

## License

[MIT](LICENSE)
