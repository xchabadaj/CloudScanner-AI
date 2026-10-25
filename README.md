# CloudScanner-AI

**AI-assisted AWS IAM privilege-escalation path discovery and validation.**

CloudScanner-AI enumerates an AWS account's IAM configuration, reconstructs
the caller's *effective* permissions, and systematically looks for
**privilege-escalation paths** (e.g. policy-version rollback, access-key
rotation, role/instance-profile abuse, Lambda-based escalation). Candidate
paths are reviewed, validated, and compiled into a human-readable report with
reproducible AWS CLI steps.

The project was built as a bachelor's thesis. It combines a layer of
**deterministic Python scanners** with an optional layer of **orchestrated AI
agents** that curate, prioritise, and review findings.

> ⚠️ **Authorized use only.** This is a security-assessment tool. Run it only
> against AWS accounts you own or have **explicit written permission** to test.
> Unauthorised scanning or exploitation of AWS accounts is illegal. The author
> accepts no liability for misuse. See [LICENSE](LICENSE).

---

## How it works

The analysis runs as an ordered pipeline that writes one JSON artifact per
stage into `runs/<run_id>/`:

| Stage | Module | Output |
|-------|--------|--------|
| Collect | `iam_user_scan` | `01_iam_user_scan.json` |
| Collect | `policy_resource_followup` | `02_policy_resource_followup.json` |
| Service probe | `targeted_service_probing` | `03_targeted_service_probing.json` |
| Analyze | `permission_summary` | `11_permission_summary.json` |
| Analyze | `iam_role_audit` | `12_iam_role_audit.json` |
| Review | `review_path_curator` | `13_review_paths.json` |
| Review | `access_candidate_builder` | `14_review_candidates.json` |
| Validate | access reviewers (IAM / Lambda / general) | `15_review_*.json` |
| Summarize | `validation_summary` | `16_validation_summary.json` |
| Report | `report` | `report.md`, `report_summary.json` |

1. **Collect** — enumerate IAM identities, attached/inline policies and the
   resources they reference.
2. **Analyze** — resolve effective permissions, audit roles, and probe
   reachable services.
3. **Review** — turn raw evidence into neutral *review paths*, then into small,
   structured *review candidates*.
4. **Validate** — review each candidate (routed by family: IAM, Lambda, general)
   and mark it confirmed / inconclusive / failed.
5. **Report** — produce a report with the attack-path summary and manual
   validation commands.

### Two layers

- **Deterministic core** (`scanners/`, `tools/`, `core/`) — plain Python +
  `boto3`. Reproducible, no AI required.
- **Agent orchestration** (`agents/`, `.kiro/`) — a supervisor agent hands off
  sequentially to worker agents (scan operator, analyze operator, security
  analyst, risk planner, access reviewers, validation auditor, report writer)
  via the AWS [cli-agent-orchestrator](https://github.com/awslabs/cli-agent-orchestrator).

## Project layout

```
core/        runtime helpers, menu, context, output
scanners/    deterministic IAM / policy / service scanners
tools/       pipeline runner, scan runner, report builders
agents/      AI agent definitions (Markdown)
.kiro/       agent definitions (JSON, for the Kiro CLI)
main.py      CLI entry point
runs/        per-run output artifacts (git-ignored)
```

## Requirements

- Python 3.11+
- `boto3` (see `requirements.txt`)
- AWS credentials for the target account, provided via standard environment
  variables or an AWS profile:

```bash
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...   # if using temporary credentials
```

The tool needs read access to IAM and the services it probes
(e.g. `iam:List*`, `iam:Get*`, `sts:GetCallerIdentity`, and `*:Describe*` /
`*:List*` for probed services). It never requires write access to run the
deterministic scan.

## Installation

```bash
git clone https://github.com/<your-username>/CloudScanner-AI.git
cd CloudScanner-AI
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

Run the full pipeline (collect → analyze → validate → report):

```bash
python3 main.py full
```

Run individual stages:

```bash
python3 main.py scan1      # IAM user scan
python3 main.py scan2      # policy resource follow-up
python3 main.py services   # targeted service probing
python3 main.py scan3      # permission summary
python3 main.py scan4      # IAM role audit
python3 main.py report     # build report from an existing run
```

Each run creates `runs/<run_id>/` with the stage artifacts and a final
`report.md`.

## Notes on safety & privacy

- `runs/` is git-ignored because scan outputs contain **real account
  identifiers, ARNs and IAM policy data**. Do not commit them.
- Credentials are read only from the environment; nothing is written to disk.
- The report's "manual validation" steps are provided so an operator can
  independently reproduce a finding **on their own account**.

## Author

**Ján Chabada** — bachelor's thesis project, 2026.

## License

[MIT](LICENSE)
