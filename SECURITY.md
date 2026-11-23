# Security policy

This is a defensive research/portfolio project. It analyzes logs and never attacks anything. It is **not** hardened for hostile multi-user deployment; this file states what it does and does not protect against.

## Reporting a problem
Please use GitHub's private vulnerability reporting for this repository (Security tab → "Report a vulnerability"), or open an issue for non-sensitive problems. Do not post exploit details publicly first.

## Trust model
| Area | What is assumed / enforced |
|---|---|
| Dashboard access | **No authentication.** Intended for a single trusted analyst on localhost. `docker compose` binds `127.0.0.1` only. Put an authenticating reverse proxy in front before exposing it. |
| Analyst SQL box | Single `SELECT` over `events`, `alerts`, `incidents` only, validated by DuckDB's own parser (no file readers, no `glob`, no environment/settings/system functions, no ground-truth tables). 5,000-row cap and a 15 s timeout. |
| Webhook | `http(s)` only; redirects are not followed; link-local / cloud-metadata addresses are always blocked (`CTD_WEBHOOK_STRICT=1` also blocks loopback/private ranges). Rate-limited and queue-bounded. The URL is a secret: prefer the `CTD_WEBHOOK_URL` environment variable; the settings file is written owner-only. Alert details leave the machine when a real webhook is configured. |
| Log content | Treated as untrusted: values from logs are escaped before they enter the Markdown report and page headers. Ingestion caps gzip expansion (1 GiB) and skips unreadable files. |
| Model files | `models/*.joblib` and `demo/models/*.joblib` are **pickles**. Only load model files you created or trust; a malicious pickle executes code on load. |
| Downloads | The flaws.cloud tarball is verified by size and a pinned SHA-256 before use. |
| Container | Runs as an unprivileged user; no AWS credentials are used or needed. |

## Known limitations
- DNS rebinding between the webhook destination check and the connection is not mitigated.
- The settings file stores the webhook URL in plain text unless `CTD_WEBHOOK_URL` is used.
- The live engine keeps state in memory and in DuckDB under `data/`; there is no multi-tenant isolation.
