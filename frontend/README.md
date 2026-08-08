# Frontend Interface

This frontend provides a simple browser-based experience for running the PQC Privacy Auditor. It lets users enter a target website URL, sends the request to the backend, and displays a structured report.

## What it does

- Collects a website URL from the user
- Sends the URL to the backend scan API
- Shows loading state while the audit runs
- Displays the resulting report with findings and remediation guidance

## Files

- index.html - The complete single-page interface

## How to open it

You can open the page directly in a browser, but serving it locally is recommended:

```bash
cd frontend
python -m http.server 5500
```

Then visit:

```text
http://localhost:5500/
```

## Connection to the backend

The frontend sends requests to:

```text
http://localhost:8000/scan?url=...
```

Make sure the backend is running before using the UI.

## UI highlights

- URL input field
- loading animation while scanning
- executive-style security report
- dynamic display of discovered cryptographic findings
- print/export-friendly report layout

## Notes

The interface is intentionally simple and focused on readability. It is meant to showcase the backend analysis in a polished, user-friendly format.
