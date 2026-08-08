# PQC Privacy Auditor

A lightweight web-based security audit tool for evaluating whether a website’s encryption setup appears vulnerable to future quantum computing threats. The project combines a Python backend with a simple frontend UI to scan a target URL, inspect TLS certificate details, and report cryptographic risk using a Post-Quantum Cryptography (PQC) awareness model.

## What the project does

- Accepts a website URL from the user
- Connects to the target over HTTPS/TLS
- Extracts certificate and cipher information
- Evaluates the site’s cryptographic algorithms against a NIST-inspired quantum-risk matrix
- Displays a readable security report in the browser

## Project structure

- backend/ - FastAPI server and scanning logic
  - main.py - API entry point
  - quantum_scanner.py - certificate parsing and quantum-risk evaluation
- frontend/ - Simple browser-based interface
  - index.html - UI for entering a URL and viewing results

## Tech stack

- Python 3.x
- FastAPI
- Uvicorn
- cryptography
- HTML, CSS, and JavaScript

## Getting started

### 1. Create and activate a Python virtual environment

```bash
python -m venv .venv
.venv\Scripts\activate
```

### 2. Install dependencies

```bash
pip install fastapi uvicorn cryptography
```

### 3. Run the backend

```bash
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at:

- http://localhost:8000/
- http://localhost:8000/scan?url=https://example.com

### 4. Run the frontend

You can open the frontend directly in a browser, or serve it locally with a simple static server:

```bash
cd frontend
python -m http.server 5500
```

Then open:

- http://localhost:5500/

## API behavior

### Health check

```bash
GET /
```

Returns a simple confirmation that the API is running.

### Scan endpoint

```bash
GET /scan?url=https://example.com
```

Returns a JSON report containing:

- TLS version
- certificate information
- cryptographic algorithm findings
- quantum-risk level and remediation guidance

## Notes

- The scanner focuses on an awareness-style audit and is intended for learning and demonstration purposes.
- Results are advisory and should not be treated as a formal compliance assessment.
- Some websites may reject connections or return incomplete certificate data depending on their TLS configuration.

## License

This project is intended for educational and demonstration use.
