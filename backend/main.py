from quantum_scanner import scan as quantum_scan
from fastapi import FastAPI, Query, HTTPException
from urllib.parse import urlparse

app = FastAPI(
    title="URL Scanner API",
    description="FastAPI wrapper for the URL scanning service",
    version="1.0.0"
)


@app.get("/")
def home():
    return {
        "message": "URL Scanner API is running"
    }


@app.get("/scan")
def scan(url: str = Query(..., description="URL to scan")):
    try:
        # Validate URL
        parsed_url = urlparse(url)

        if parsed_url.scheme not in ["http", "https"] or not parsed_url.netloc:
            raise HTTPException(
                status_code=400,
                detail="Invalid URL. Please provide a valid http/https URL."
            )

        # -----------------------------------------
        # YOUR SCANNING LOGIC GOES HERE
        # -----------------------------------------
        result = quantum_scan(parsed_url.netloc)
        return result

    except HTTPException:
        raise

    except Exception as e:
        return {
            "url": url,
            "status": "error",
            "message": "An unexpected error occurred",
            "error": str(e)
        }