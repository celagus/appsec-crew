

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

AppSec Crew runs **four sequential agents** that execute real security tools and open **GitHub issues / pull requests** from your workflow or CLI.


| Agent                     | Tooling                                     | Outcome                                              |
| ------------------------- | ------------------------------------------- | ---------------------------------------------------- |
| **secrets_reviewer**      | Betterleaks                                 | Issues per finding (secrets never pasted in body)    |
| **dependencies_reviewer** | OSV-Scanner + `fix`                         | One remediation PR where supported                   |
| **code_reviewer**         | Semgrep + `--autofix`                       | One PR with rationale                                |
| **reporter**              | Markdown + optional Jira / webhook / Splunk | Summary & integrations under `agents.reporter.tools` |


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
├── examples/                  # Sample Semgrep / OSV snippets
├── src/appsec_crew/           # Package source
│   ├── bundled_appsec_crew.yaml
│   ├── config/                # Crew agent & task YAML
│   ├── integrations/          # GitHub, Jira, webhook, Splunk
│   ├── scanners/
│   └── utils/                 # severity, filters, llm helpers
├── tests/
├── appsec_crew.yaml.example
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

# Install betterleaks, osv-scanner, semgrep on PATH, then:
appsec-crew --repo /path/to/repo-to-scan
# appsec-crew --repo /path/to/repo --config /path/to/appsec_crew.yaml
```

Copy `[appsec_crew.yaml.example](./appsec_crew.yaml.example)` into the **target** repo as `appsec_crew.yaml` when you want a custom policy.

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
| `betterleaks_version` / `osv_scanner_version` | Release tags for binaries                                                                                               |


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

---

## Exit codes


| Code | Meaning                              |
| ---- | ------------------------------------ |
| 0    | Success                              |
| 2    | Validation failed                    |
| 3    | Missing LLM key for an enabled agent |
| 4    | Config path error                    |


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
| **Description**       | Short line: e.g. *CrewAI agents + Betterleaks, OSV-Scanner & Semgrep for GitHub — issues & PRs from CI*                                                                                            |
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