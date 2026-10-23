# sast

[![CI](https://github.com/openasy/sast/actions/workflows/ci.yml/badge.svg)](https://github.com/openasy/sast/actions/workflows/ci.yml)
[![Node.js 26 LTS](https://img.shields.io/badge/node-26%20LTS-339933?logo=nodedotjs&logoColor=white)](./.nvmrc)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](./LICENSE)

The [OpenAsy](https://github.com/openasy) SAST product: static analysis findings for every repository, where **a pull
request fails only for what it adds** (ADR 0036). Your pipeline runs an analyser that writes
[SARIF](https://sarifweb.azurewebsites.net/), such as [Opengrep](https://github.com/opengrep/opengrep), Semgrep or
CodeQL, and sends the result here. sast compares it with the default branch and answers whether the check passes.

```
CI: opengrep scan --sarif-output=results.sarif  ──POST /api/v1/scans──▶  sast  ──▶  { new, blocking, passed }
                                                                           └── baseline: the default branch's findings, triage, history
```

sast reads SARIF and nothing else: it holds no scanner and runs no one's code. Cloning repositories and scanning them
in an agent, and checks posted to GitHub and GitLab, come next (ADR 0036).

## How a scan is compared

- A scan of the **default branch** becomes the baseline. It adopts what is there and never fails a pipeline. What the
  branch stops reporting is marked fixed, and opens again if it returns.
- Any other scan, or any scan with `pullRequest`, reports only findings the baseline does not have and nobody has
  triaged. `blocking` counts those at or above the repository's **fail on** severity (high by default; set under the
  repository).
- A finding is found again by **rule, file and the code it matched**, not by its line, so moving code does not make it
  new. A second copy of the same code is a new finding.
- A **false positive** or **accepted risk** (with a reason, and an end date for accepted risk) follows the finding to
  every branch. A finding that is only in a pull request can be triaged too.

## Run

```bash
openssl rand -hex 32 > openasy-kek
export SAST_INGEST_TOKEN=$(openssl rand -hex 32)
docker compose up -d
docker compose logs sast | grep 'no owner yet'
```

Open the link from the log once to create the owner account; there is no default password (ADR 0013). The UI and API
are on http://localhost:8080, the API reference at http://localhost:8080/api/docs/.

Send a scan from CI:

```bash
opengrep scan --sarif-output=results.sarif .
curl -sf -X POST -H "Authorization: Bearer $SAST_INGEST_TOKEN" -H 'content-type: application/json' \
  --data-binary @results.sarif \
  "https://sast.example.com/api/v1/scans?repository=acme/web&branch=$BRANCH&commit=$SHA&pullRequest=$PR" > scan.json
jq -e '.passed' scan.json
```

`repository` and `branch` are required. A new repository uses `main` as its default branch unless you send
`defaultBranch`. The body may be gzipped (`Content-Encoding: gzip`), up to 64 MiB unpacked and 50,000 results.

`openasy-kek` encrypts sign-in secrets in sast's database (ADR 0021). Keep it apart from the volume and with your
backups.

| Variable | Default | |
| --- | --- | --- |
| `PORT` | `8080` | HTTP port |
| `SAST_PUBLIC_URL` | `http://localhost:8080` | The address people open, with `https://` behind your TLS proxy |
| `OPENASY_PRODUCTS` | | The install's other OpenAsy products, for the product switcher. Give every product the same value |
| `SAST_INGEST_TOKEN` | | Lets CI send scans and nothing else. An API token with the editor role works too |
| `SAST_SECRETS_KEY_FILE` | `/run/secrets/openasy-kek` | 32-byte key-encryption key |
| `SAST_DB` | `/data/sast.db` | SQLite file (WAL), on the `/data` volume |
| `SAST_RETENTION_DAYS` | `365` | Scans, and fixed findings nobody triaged, older than this are deleted |
| `SAST_METRICS_PORT` | | Serve `/metrics` on this port only (ADR 0026) |
| `SAST_HEADLESS` | `false` | `true` serves only the API |
| `SAST_PASSWORD_SIGN_IN`, `OPENASY_OIDC_*` | | Sign-in, as in every OpenAsy product ([@openasy/auth](https://github.com/openasy/auth)). Owners can also add identity providers under Settings, Sign-in |

The container runs as non-root with a read-only root filesystem, no capabilities and `no-new-privileges`.

Findings hold snippets of your code. Anyone with the viewer role reads them, and deleting a repository deletes them.

## Roles

Viewers see everything; editors also triage findings and send scans; admins also change a repository's policy and
delete it, and manage members and API tokens (ADR 0003).

## Develop

```bash
npm install
npm test        # SARIF parsing, comparison with the baseline, triage, and every API response against openapi.json
npm run dev     # the UI, with the API on :8080
```

## Licence

AGPL-3.0 (ADR 0008).
