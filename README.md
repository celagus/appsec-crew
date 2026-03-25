

```
....................................................
   █████╗ ██████╗ ██████╗ ███████╗███████╗ ██████╗
  ██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝
  ███████║██████╔╝██████╔╝███████╗█████╗  ██║     
  ██╔══██║██╔═══╝ ██╔═══╝ ╚════██║██╔══╝  ██║     
  ██║  ██║██║     ██║     ███████║███████╗╚██████╗
  ╚═╝  ╚═╝╚═╝     ╚═╝     ╚══════╝╚══════╝ ╚═════╝

        ██████╗██████╗ ███████╗██╗    ██╗
       ██╔════╝██╔══██╗██╔════╝██║    ██║
       ██║     ██████╔╝█████╗  ██║ █╗ ██║
       ██║     ██╔══██╗██╔══╝  ██║███╗██║
       ╚██████╗██║  ██║███████╗╚███╔███╔╝
        ╚═════╝╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝
....................................................

```

# AppSec Crew

**Multi-agent application security automation for GitHub — powered by [CrewAI](https://www.crewai.com/), [Betterleaks](https://github.com/betterleaks/betterleaks), [OSV-Scanner](https://google.github.io/osv-scanner/), and [Semgrep](https://semgrep.dev/).**

[CI](https://github.com/celagus/appsec-crew/actions/workflows/ci.yml)
[License: MIT](./LICENSE)
[Python 3.10+](./pyproject.toml)

**[Quick start](#local-usage)** · **[GitHub Actions](#github-actions)** · **[Configuration](#configuration-resolution)** · **[Contributing](./CONTRIBUTING.md)**



---

## Overview

AppSec Crew runs **four sequential agents** that execute real security tools and post results to **GitHub** (PR comments, Issues, and/or PRs — see [PR vs scheduled](#pr-vs-scheduled-cron--workflow_dispatch)).


| Agent                     | Tooling                         | Outcome (depends on [run mode](#pr-vs-scheduled-cron--workflow_dispatch)) |
| ------------------------- | ------------------------------- | ------------------------------------------------------------------------- |
| **secrets_reviewer**      | Betterleaks                     | **PR**: summary on the PR, no Issues · **Batch**: one Issue per finding (no secret values in body) |
| **dependencies_reviewer** | OSV-Scanner (`scan -r`)         | **PR**: summary only · **Batch**: one umbrella Issue (vulnerable rows)    |
| **code_reviewer**         | Semgrep (`scan`; batch uses `--autofix` when opening a PR) | **PR**: review with inline comments · **Batch**: autofix PR or tracking Issue if no fix commit |
| **reporter**              | Markdown + optional Jira / webhook / Splunk | **PR**: summary comment on the PR only (integrations **off**). **Batch**: same summary plus Jira / webhook / Splunk when enabled under `agents.reporter.tools`. |


Orchestration is **always CrewAI**. Every **enabled** agent must resolve an LLM API key (`llm.api_key` or `llm.api_key_env`).

### How it works

1. Install the package and run `appsec-crew`, or call the [reusable workflow](#github-actions) from another repo.
2. Load YAML config ([resolution order](#configuration-resolution)).
3. Each agent runs a tool that shells out to scanners and uses `GITHUB_TOKEN` for GitHub API actions.
4. `**global.min_severity`** filters OSV (CVSS) and Semgrep severities. Betterleaks ignores live in `.betterleaks.toml` / `.gitleaks.toml` in the **scanned** repo.
5. Tool-specific allowlists stay in **native config files** in the target repository — not duplicated in `appsec_crew.yaml`.

---

## Requirements


|                    |                                                                                           |
| ------------------ | ----------------------------------------------------------------------------------------- |
| **Python**         | 3.10–3.13                                                                                 |
| **LLM**            | e.g. `OPENAI_API_KEY` (or per-agent keys in YAML) for each enabled agent                  |
| **GitHub**         | Token with `contents:write`, `issues:write`, `pull-requests:write` when mutating the repo |
| **Scanners in CI** | Betterleaks, OSV-Scanner, Semgrep — installed by the reusable workflow on Ubuntu          |
| **Network**        | Registry rules / OSV API unless you configure offline flows yourself                      |


Never commit secrets. Use **GitHub Actions secrets** and optional YAML overrides for non-sensitive tuning only.

---

## Repository layout

```
├── assets/                    # Branding (ASCII banner, optional png mark)
├── examples/                  # `osv-scanner.toml.example`, `semgrep-local-rules.example.yml` (see [below](#example-configuration-and-tool-files))
├── src/appsec_crew/           # Package source
│   ├── bundled_appsec_crew.yaml
│   ├── config/                # Crew agent & task YAML
│   ├── integrations/          # GitHub, Jira, webhook, Splunk
│   ├── scanners/
│   └── utils/                 # severity, filters, llm helpers
├── tests/
├── appsec_crew.yaml
├── pyproject.toml
└── README.md
```

---

## Configuration resolution

If you **omit** `--config`:

1. `<repo>/appsec_crew.yaml` if present
2. File at `APPSEC_CREW_CONFIG` if it exists
3. Packaged `**bundled_appsec_crew.yaml`** (reporter Jira / webhook / Splunk **off**)

An explicit `--config /path` must point to an existing file.

### Example configuration and tool files

| What you need | Where to get it |
| ------------- | --------------- |
| **Main AppSec Crew config** | Copy [`appsec_crew.yaml`](./appsec_crew.yaml) from this repository into the **root of the repository you scan** (same filename). That file is the maintained template; comments describe PR vs batch behavior and env vars. |
| **Fallback when no file in the scan target** | The Python package ships [`src/appsec_crew/bundled_appsec_crew.yaml`](./src/appsec_crew/bundled_appsec_crew.yaml) — same baseline (reporter integrations off). Use the repo-root template when you want to customize. |
| **OSV-Scanner ignores / overrides** | Start from [`examples/osv-scanner.toml.example`](./examples/osv-scanner.toml.example) → save as `osv-scanner.toml` in the scanned repo. Full reference: [OSV-Scanner configuration](https://google.github.io/osv-scanner/configuration/). |
| **Semgrep local rules / metadata** | Sample rules in [`examples/semgrep-local-rules.example.yml`](./examples/semgrep-local-rules.example.yml) → merge or adapt into `.semgrep.yml` at the scan root. Rule syntax: [Semgrep docs](https://semgrep.dev/docs/writing-rules/rule-syntax/). |
| **Secrets scanning allowlists** | `.betterleaks.toml` and/or `.gitleaks.toml` in the scanned repo ([Betterleaks](https://github.com/betterleaks/betterleaks)). |

### Tool versions (per agent)

Pin external scanners for **reproducible CI** and for the reporter summary under each tool block:

```yaml
agents:
  secrets_reviewer:
    tools:
      betterleaks:
        version: v1.1.1   # GitHub release tag
  dependencies_reviewer:
    tools:
      osv_scanner:
        version: v2.3.3   # GitHub release tag (google/osv-scanner)
  code_reviewer:
    tools:
      semgrep:
        version: "1.156.0"  # PyPI → pip install semgrep==…
```

Omit `version` and the runtime loads pins from the packaged [`bundled_appsec_crew.yaml`](./src/appsec_crew/bundled_appsec_crew.yaml) only (no duplicate defaults in Python). Locally, install matching versions yourself; the CLI does not download binaries. To print the resolved pins (e.g. debugging CI): `appsec-crew-print-tool-versions --repo /path/to/scanned/repo [--config path]`.

### GitHub Actions path (`…/work/repo/repo`)

`GITHUB_WORKSPACE` is always `/home/runner/work/<repo-name>/<repo-name>`. The path is **not** duplicated by mistake: the first segment is the workflow “share”, the second is the clone directory ([GitHub Actions reference](https://docs.github.com/en/actions/learn-github-actions/variables#default-environment-variables)).

### Scanner workspace, logging, triage, and CLI overrides

- **Scope**: Betterleaks runs `dir` on the repository root (full tree), OSV uses `scan -r`, Semgrep uses `scan` on the repo path (recursive by default).
- **Logging**: Each subprocess prints a line to **stderr**: `[appsec-crew] executing: {"tool":"…","argv":[…],"shell":"…"}` plus the same argv is stored in workflow JSON as `commands_executed`.
- **False positives**: Optional **LLM triage** (`llm_triage: true` under each tool block) can dismiss likely false positives after scanning. **Default is off** so CI matches raw scanner output unless you opt in.
- **Semgrep severity**: `global.min_severity` filters by rule severity. **`WARNING` counts like HIGH/ERROR** (rank 4) for the `high` threshold — Semgrep labels many real issues as WARNING. Missing / unknown severities default to HIGH. Explicit `INFO` / `LOW` / `MEDIUM` use the usual map.
- **Semgrep registry packs**: Each `extra_configs` value is a Registry id (`p/...`). If any pack returns **404** or is invalid, Semgrep reports `errors` in the JSON and may scan **no files** (`paths.scanned` empty) — not a silent success. The bundled defaults use **`p/golang`** for Go rules (`p/go` no longer resolves on the registry).
- **Overrides**: Append flags with `extra_args` / `scan_extra_args`, or replace the built argv with a formatted `command` / `scan_command` string. Placeholders: `{binary}`, `{repo}`, `{report}`, `{config}`; Semgrep also `{config_args}` (quoted `--config …` tokens) and `{autofix}` (`--autofix ` or empty). Put a **space before `--json`** in custom Semgrep templates, e.g. `… {config_args} --json -o {report} {repo}`. The schema still accepts `fix_extra_args` for OSV for backward compatibility; the current **batch** flow does not run `osv-scanner fix` (dependencies are reported via Issues).

### CI: “0 Semgrep findings” vs `global.min_severity`

The summary line **raw from scan** is the Semgrep JSON **before** `global.min_severity`; **after severity filter** is after that gate; **findings** is after LLM triage (if enabled). If **raw > 0** but counts after the severity line are **0**, relax `global.min_severity` (e.g. `high` → `medium`) or adjust rules — the scanner is working; the gate is policy. If **raw is 0** and you expected issues, inspect Semgrep’s JSON **`errors`** (registry 404s invalidate the whole config), network/registry access, and that files are tracked (Semgrep uses `git` by default).

The reusable workflow runs `git config --global --add safe.directory '*'` so Git 2.35.2+ does not block the checkout and Semgrep sees tracked files ([Semgrep: git command errors](https://semgrep.dev/docs/kb/semgrep-ci/git-command-errors)). To change how targets are chosen (e.g. `--novcs`, `--no-git-ignore`, `--scan-unknown-extensions`), use `extra_args` or a custom `command` — see the [Semgrep CLI reference](https://semgrep.dev/docs/cli-reference).

---

## Local usage

```bash
git clone https://github.com/celagus/appsec-crew.git
cd appsec-crew
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

export GITHUB_TOKEN=...
export GITHUB_REPOSITORY=owner/repo    # outside GitHub Actions
export OPENAI_API_KEY=...

# Optional: simulate PR mode (comments + Semgrep review, no Issues)
# export GITHUB_EVENT_NAME=pull_request
# export APPSEC_CREW_PR_NUMBER=123

# Install betterleaks, osv-scanner, semgrep on PATH, then:
appsec-crew --repo /path/to/repo-to-scan
# appsec-crew --repo /path/to/repo --config /path/to/appsec_crew.yaml
```

Copy [`appsec_crew.yaml`](./appsec_crew.yaml) into the **target** repo when you want a custom policy; add tool configs from [`examples/`](./examples/) as needed ([details](#example-configuration-and-tool-files)).

---

## GitHub Actions

This repo publishes:


| Workflow                                                                   | Purpose                                                 |
| -------------------------------------------------------------------------- | ------------------------------------------------------- |
| `[ci.yml](./.github/workflows/ci.yml)`                                     | `pytest` on push / PR                                   |
| `[appsec-crew-reusable.yml](./.github/workflows/appsec-crew-reusable.yml)` | **Reusable** — install scanners + run `appsec-crew`     |
| `[run-reusable.yml](./.github/workflows/run-reusable.yml)`                 | Dogfood: calls the reusable workflow with `package_path: .` |


### Reusable workflow inputs


| Input                                         | Description                                                                                                             |
| --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `install_from_github`                         | If **true**, clone `appsec_crew_repository` at `appsec_crew_ref` and `pip install` from there (typical for app repos that do not vendor this package). |
| `appsec_crew_repository` / `appsec_crew_ref`    | Used when `install_from_github` is true (default repo `celagus/appsec-crew`, ref `main`).                               |
| `package_path`                                | When `install_from_github` is **false**: path from caller root to a folder with this package’s `pyproject.toml` (vendor/submodule). Default `.` (same repo as the workflow). |
| `scan_path`                                   | Directory to scan (usually `.`)                                                                                         |
| `config_file`                                 | Relative path to `appsec_crew.yaml`, or **empty** for [auto-resolution](#configuration-resolution)                      |

Scanner **versions** are **not** workflow inputs: they come from `agents.*.tools.*.version` in the resolved `appsec_crew.yaml` (see template). The job runs `python -m appsec_crew.ci_versions` before downloading Betterleaks / OSV-Scanner or pinning Semgrep.


Use `secrets: inherit` (or map secrets) for `GITHUB_TOKEN`, `OPENAI_API_KEY`, and optional reporter secrets.

### Example — pull request (install from GitHub; no vendored copy)

Most application repos should install the package from this repository:

```yaml
name: AppSec Crew

on:
  pull_request:
    branches: [main]

permissions:
  contents: write
  issues: write
  pull-requests: write

jobs:
  scan:
    uses: celagus/appsec-crew/.github/workflows/appsec-crew-reusable.yml@v1
    with:
      install_from_github: true
      appsec_crew_ref: main
      scan_path: .
      config_file: ""
    secrets: inherit
```

Pin `uses: ...@v1` (or a **commit SHA**) to a revision you trust; match `appsec_crew_ref` to that line if you need an exact pairing.

### Example — pull request (vendored package in monorepo)

If you copy or submodule this repo under e.g. `third_party/appsec-crew`:

```yaml
jobs:
  scan:
    uses: celagus/appsec-crew/.github/workflows/appsec-crew-reusable.yml@v1
    with:
      package_path: third_party/appsec-crew
      scan_path: .
      config_file: ""
    secrets: inherit
```

### Example — scheduled scan (default branch)

```yaml
name: AppSec Crew (schedule)

on:
  schedule:
    - cron: "0 6 * * 1"
  workflow_dispatch:

permissions:
  contents: write
  issues: write
  pull-requests: write

jobs:
  scan:
    uses: celagus/appsec-crew/.github/workflows/appsec-crew-reusable.yml@v1
    with:
      install_from_github: true
      appsec_crew_ref: main
      scan_path: .
      config_file: ""
    secrets: inherit
```

`schedule` only runs on the **default** branch. Combine `pull_request`, `schedule`, and `workflow_dispatch` in one file if you prefer a single workflow.

### PR vs scheduled (cron / `workflow_dispatch`)

GitHub sets `GITHUB_EVENT_NAME` (and the action provides `GITHUB_EVENT_PATH`). AppSec Crew uses that plus a resolved PR number (`pull_request.number` from the event, or override `APPSEC_CREW_PR_NUMBER`) to choose behavior:

| Mode | Betterleaks | OSV-Scanner | Semgrep | Exit / integrations |
| ---- | ----------- | ------------ | ------- | ------------------- |
| **PR** (`pull_request` / `pull_request_target` with PR #) | Summary on the PR (no Issues) | Same | **PR review** + inline comments when possible | **Exit code 5** if any actionable findings remain; comment lists tool-native files for allowlists. **Jira, webhook, and Splunk are not called.** |
| **Batch** (e.g. `schedule`, `workflow_dispatch`, `push`) | **GitHub Issues** (one per finding) | **One umbrella Issue** (no OSV remediation PR) | **Autofix PR** or **tracking Issue** | **Exit 0** even with findings (job succeeds). Reporter may send **Jira / webhook / Splunk** when enabled. |

---

## Exit codes


| Code | Meaning                              |
| ---- | ------------------------------------ |
| 0    | Success                              |
| 2    | Validation failed                    |
| 3    | Missing LLM key for an enabled agent |
| 4    | Config path error                    |
| 5    | **PR scan only**: actionable findings after filters/triage (fails the check; see PR comment for suppression hints) |


---

## Tests

```bash
pip install -e ".[dev]"
pytest
```

---

## Community & visibility (GitHub settings)

Suggested **repository topics** for discoverability:

`security` `devsecops` `github-actions` `crewai` `semgrep` `osv-scanner` `betterleaks` `sast` `dependency-scanning` `secrets-scanning` `python` `automation`

**Recommended repo settings**


| Setting               | Suggestion                                                                                                                                                                                         |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Description**       | Short line: e.g. *CrewAI agents + Betterleaks, OSV-Scanner & Semgrep — PR comments on review, Issues & autofix PRs on schedule*                                                                  |
| **Website**           | Link to this README or future docs site                                                                                                                                                            |
| **Social preview**    | Screenshot the README banner or design a 1280×640 image in Settings → General                                                                                                                      |
| **Security**          | Enable *Private vulnerability reporting* if you want GitHub’s advisory flow                                                                                                                        |
| **Branch protection** | Require CI (`CI` workflow) on `main` before merge                                                                                                                                                  |
| **Rulesets / tags**   | Sign release tags (`v1.0.0`) for consumers pinning `uses: ...@v1.0.0`                                                                                                                              |
| **Sponsors**          | `[.github/FUNDING.yml](./.github/FUNDING.yml)` points to [@celagus](https://github.com/celagus); the button appears once [GitHub Sponsors](https://github.com/sponsors) is set up for that account |
| **Code owners**       | `[.github/CODEOWNERS](./.github/CODEOWNERS)` — enable “Require review from Code Owners” on protected branches if you want mandatory review from [@celagus](https://github.com/celagus)             |


---

## License

[MIT](./LICENSE)

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md). Security disclosures: [SECURITY.md](./SECURITY.md).