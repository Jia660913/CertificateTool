# CSI Certificate Wizard

Local web UI for guiding users through certificate generation with `CsiCertificateTool.exe`.

## Run

```powershell
npm start
```

Then open:

```text
http://localhost:4177
```

## What It Does

- Provides a step-by-step wizard instead of asking users to write JSON.
- Builds the `Structure`, `Data`, and `Signature` JSON configuration.
- Supports a basic template flow and an advanced ASN.1 structure builder.
- Supports Offline and DLM signing flows.
- Shows generated JSON and a redacted command preview before execution.
- Calls:

```text
C:\Users\z0242332\OneDrive - ZF Friedrichshafen AG\Desktop\CSI_Bundle\bin\windows\x64\CsiCertificateTool.exe
```

The `CSI_Bundle` folder is read-only from this project. Generated job files are written under `.jobs/`.

## Notes

- Secrets such as JWT and private keys are redacted in the command preview.
- DLM file inputs can be uploaded through the browser or supplied as server-local paths.
- The basic template uses the certificate structure from `samples/certificate-tool-cfg`.
