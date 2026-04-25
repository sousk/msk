# msk

Pipe-friendly CLI that masks secrets and tokens from stdin before they reach your clipboard, logs, or terminal history.

```sh
some-command | msk | pbcopy
cat logfile.txt | msk
```

## Install

```sh
go install github.com/YOUR_USERNAME/msk@latest
```

Or build from source:

```sh
git clone https://github.com/YOUR_USERNAME/msk.git
cd msk
go build -o msk .
```

## Usage

`msk` reads from stdin, replaces detected secrets with redaction placeholders, and writes to stdout. No flags required.

```sh
# Mask a log file before sharing
cat app.log | msk > safe.log

# Mask before copying to clipboard (macOS)
cat .env | msk | pbcopy

# Mask inline environment variables
env | msk

# Mask command output
kubectl get secret mysecret -o yaml | msk
```

## What gets masked

| Pattern | Placeholder |
|---|---|
| Private key blocks (PEM / OpenSSH) | `<REDACTED_PRIVATE_KEY_BLOCK>` |
| GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, fine-grained PATs) | `<REDACTED_GITHUB_TOKEN>` |
| Slack tokens (`xoxb-`, `xoxp-`, `xapp-`, …) | `<REDACTED_SLACK_TOKEN>` |
| NPM tokens (`npm_…`, `.npmrc` authToken) | `<REDACTED_NPM_TOKEN>` |
| PyPI tokens (`pypi-…`) | `<REDACTED_PYPI_TOKEN>` |
| SendGrid API keys (`SG.…`) | `<REDACTED_SENDGRID_KEY>` |
| OpenAI keys (`sk-…`, `sk-proj-…`) | `<REDACTED_OPENAI_KEY>` |
| Anthropic keys (`sk-ant-…`) | `<REDACTED_ANTHROPIC_KEY>` |
| JWTs (`eyJ…`) | `<REDACTED_JWT>` |
| Google OAuth tokens (`ya29.…`) | `<REDACTED_OAUTH_TOKEN>` |
| `Authorization: Bearer …` headers | `Bearer <REDACTED_TOKEN>` |
| AWS access keys (`AKIA…`) | `<REDACTED_AWS_KEY>` |
| AWS secret access keys (contextual) | `<REDACTED_AWS_SECRET>` |
| Stripe keys (`sk_live_…`, `sk_test_…`) | `<REDACTED_STRIPE_KEY>` |
| Database URL passwords (`postgres://user:pass@…`) | `<REDACTED_PASSWORD>` |
| `x-api-key` headers | `<REDACTED_API_KEY>` |
| `api_key=` / `api-key=` assignments | `<REDACTED_API_KEY>` |
| `password=` / `password:` assignments | `<REDACTED_PASSWORD>` |
| URL embedded credentials | `<REDACTED_PASSWORD>` |
| Sensitive URL query params (`token=`, `api_key=`, `secret=`, …) | `<REDACTED_URL_PARAM>` |

## Design

- **No configuration** — works out of the box with zero flags.
- **Order-aware** — multi-line key blocks are matched first so partial material is not leaked by later rules.
- **Non-destructive** — non-secret text passes through unchanged.
- **Single binary** — no runtime dependencies.

## License

MIT
