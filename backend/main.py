
from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from urllib.parse import urlparse

app = FastAPI(
    title="URL Scanner API",
    description="FastAPI wrapper for the URL scanning service",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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

        result = {
            "url": url,
            "status": "scanned",
            "message": "URL scan completed successfully"
        }

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

