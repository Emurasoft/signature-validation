# Signature Validation

[![Validate signature](https://github.com/Emurasoft/signature-validation/actions/workflows/validate.yml/badge.svg)](https://github.com/Emurasoft/signature-validation/actions/workflows/validate.yml)

This repository verifies the download link for [emeditor.com](https://www.emeditor.com/).

Every 1 hour at most, `main.go` is executed to:
1. Navigate to the [download page](https://www.emeditor.com/download/).
2. Locate and download the installer file.
3. Validate the digital signature using `Get-AuthenticodeSignature`.

## Results

The output is saved to [`status.json`](https://github.com/Emurasoft/signature-validation/blob/validation-results/status.json) in the `validation-results` branch.

### Valid Signature
```json
{"result":{"valid":true},"time":"..."}
```

### Invalid Signature
The `status.json` file will show `{"valid":false}` along with the reason.

### Script Error
```json
{"error":"..."}
```

If the signature is invalid or a script error occurs, a new issue is created to alert Makoto.