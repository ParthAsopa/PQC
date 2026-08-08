# Backend Service

This backend provides the scanning logic for the PQC Privacy Auditor. It exposes a small FastAPI service that receives a URL from the frontend and returns a structured report about the target website’s TLS and cryptographic posture.

## Responsibilities

- Validates the submitted URL
- Opens a TLS connection to the target server
- Extracts certificate data
- Parses the public-key and signature algorithms
- Evaluates quantum-related risk using a built-in threat matrix
- Returns a JSON response to the frontend

## Files

- main.py - FastAPI application and route definitions
- quantum_scanner.py - scanner logic, certificate parsing, and risk evaluation

## Requirements

Install the required Python packages:

```bash
pip install fastapi uvicorn cryptography
```

## Run locally

From the backend directory:

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

## Example requests

### Root endpoint

```bash
curl http://localhost:8000/
```

### Scan a target URL

```bash
curl "http://localhost:8000/scan?url=https://example.com"
```

## Response overview

The scan response includes:

- hostname and certificate subject information
- TLS version and cipher details
- cryptographic algorithm findings
- overall risk level
- suggested remediation guidance

## Notes

The backend intentionally performs a lightweight inspection rather than a full browser-based telemetry audit. It is designed to demonstrate how post-quantum exposure can be assessed from TLS metadata.
