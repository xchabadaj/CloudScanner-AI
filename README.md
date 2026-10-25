# CloudScanner-AI

**AI-assisted penetration testing of AWS cloud environments — automated discovery, testing and evaluation of IAM privilege-escalation paths.**

CloudScanner-AI enumerates an AWS account's services, identities and access
policies, resolves the caller's *effective* permissions, and systematically
discovers, validates and classifies **privilege-escalation paths** (e.g.
policy-version rollback, access-key rotation, role / instance-profile abuse,
Lambda-based escalation). Findings are rated by severity and confirmation
status and compiled into a report with reproducible AWS CLI steps.

The system combines a layer of **deterministic Python scanners** with a layer
of **multi-agent AI evaluation** that curates, prioritises, reviews and
classifies findings. It was built as a bachelor's thesis and tested against a
vulnerable [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat)
scenario.

> ⚠️ **Authorized use only.** This is a security-assessment tool. Run it only
> against AWS accounts you own or have **explicit written permission** to test.
> Unauthorised scanning or exploitation of AWS accounts is illegal. The author
> accepts no liability for misuse. See [LICENSE](LICENSE).

---

## Architecture

CloudScanner-AI has two cooperating layers:

- **Deterministic core** (`scanners/`, `tools/`, `core/`) — plain Python +
  `boto3`. Collects data and produces reproducible JSON artifacts, no AI
  required.
- **Multi-agent orchestration** (`agents/`, `.kiro/`) — a *supervisor* agent
  hands off sequentially to worker agents (scan operator, analyze operator,
  security analyst, risk planner, IAM / Lambda / general access reviewers,
  validation auditor, report writer). The agents run on **Kiro CLI** (LLM
  inference via **Amazon Bedrock**) and are coordinated by the
  **[CLI Agent Orchestrator (CAO)](https://github.com/awslabs/cli-agent-orchestrator)**.

> The deterministic scanning layer and CAO orchestration run locally, but LLM
> inference is delegated to Amazon Bedrock, so an AWS connection is required
> and the tool cannot run fully offline in multi-agent mode.

### Pipeline stages

Each stage writes one JSON artifact into `runs/<run_id>/`:

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

## Project layout

```
core/        runtime helpers, menu, context, output
scanners/    deterministic IAM / policy / service scanners
tools/       pipeline runner, scan runner, report builders
agents/      AI agent definitions (Markdown)
.kiro/       Kiro CLI agent definitions (JSON)
main.py      CLI entry point (deterministic pipeline)
runs/        per-run output artifacts (git-ignored)
```

## Requirements

- Python 3.11+ and `boto3` (`requirements.txt`) — for the deterministic core
- **AWS CLI v2** — account access and `aws sts get-caller-identity`
- AWS credentials for the target account (read access to IAM and probed
  services)

For the **multi-agent (AI) mode** additionally:

- [uv](https://docs.astral.sh/uv/) — package manager / runner
- **tmux** — CAO runs each agent in a tmux session
- **[Kiro CLI](https://kiro.dev/docs/cli/)** — agent runtime (LLM via Amazon
  Bedrock), logged in with `kiro-cli login`
- **CAO (CLI Agent Orchestrator)** — multi-agent coordination

### Install (AI mode)

```bash
# uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# AWS CLI v2 (Linux example; on macOS use the AWS pkg installer)
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o awscliv2.zip
unzip awscliv2.zip && sudo ./aws/install

# tmux (Debian/Ubuntu; on macOS: brew install tmux)
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

### AWS credentials

Either via environment variables:

```bash
export AWS_ACCESS_KEY_ID="<ACCESS_KEY>"
export AWS_SECRET_ACCESS_KEY="<SECRET_KEY>"
export AWS_DEFAULT_REGION="us-east-1"
aws sts get-caller-identity
```

or via `~/.aws/credentials`:

```ini
[default]
aws_access_key_id = <AWS_ACCESS_KEY>
aws_secret_access_key = <AWS_SECRET_KEY>
aws_session_token = <AWS_TOKEN>   # only for temporary credentials
```

The agent profiles in `.kiro/agents/` are made available to Kiro CLI.

## Usage

### Deterministic pipeline (no AI)

Run the full pipeline (collect → analyze → validate → report):

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

### Multi-agent mode (Kiro CLI + CAO)

In two terminals:

```bash
# Terminal 1 — start the CAO server
cao-server

# Terminal 2 — launch the supervisor agent
cao launch --agents cloudscanner_supervisor --provider kiro_cli --auto-approve
```

The supervisor orchestrates collection, analysis, review, validation and
reporting across the worker agents. Each run creates `runs/<run_id>/` with the
stage artifacts and a final `report.md`.

## Notes on safety & privacy

- `runs/` is git-ignored because scan outputs contain **real account
  identifiers, ARNs and IAM policy data**. Do not commit them.
- Credentials are read only from the environment / AWS config; nothing secret
  is written into the repository.
- The report's "manual validation" steps let an operator independently
  reproduce a finding **on their own account**.

## Author

**Ján Chabada** — bachelor's thesis, 2026.

## License

[MIT](LICENSE)
