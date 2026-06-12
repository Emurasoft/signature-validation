# Signature Validation

[![Validate signature](https://github.com/Emurasoft/signature-validation/actions/workflows/validate.yml/badge.svg)](https://github.com/Emurasoft/signature-validation/actions/workflows/validate.yml)

Every 1 hour at most, `main.go` is executed to:

1. Navigate to the [download page](https://www.emeditor.com/download/) via Playwright.
2. Scrape the direct download URL from the `a[aria-label='Download Desktop Installer directly']` link.
3. Download the installer via HTTP.
4. Validate the PE digital signature using `ValidateMSISignature`.
5. Clean up the temp file and output the result as JSON.

## Output

The result is written to [`status.json`](https://github.com/Emurasoft/signature-validation/blob/validation-results/status.json) in the `validation-results` branch. Each run produces a JSON object with the following shape:

```json
{"result":{"valid":true},"time":"2026-06-11T12:00:00Z"}
```

| Field | Description |
|---|---|
| `result.valid` | `true` if the signature is valid |
| `result.reason` | Error message when the signature is invalid |
| `error` | Set if the script itself failed (navigation, download, etc.) |
| `time` | UTC timestamp of the run |

If the signature is invalid or a script error occurs, a new issue is created on GitHub to alert Makoto.