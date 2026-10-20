"""FastAPI application for local Backend Atlas scans."""

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.scanner import (
    RepositoryNotAllowedError,
    ScannerSafetyError,
    ScannerConfigurationError,
    scan_repository,
)


app = FastAPI(title="Backend Atlas", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5174", "http://127.0.0.1:5174"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(
    request: Request, error: RequestValidationError
) -> JSONResponse:
    return JSONResponse(status_code=422, content={"detail": "Invalid scan request."})


class ScanRequest(BaseModel):
    repository_path: str = Field(min_length=1)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/scan")
def scan(request: ScanRequest) -> dict[str, object]:
    try:
        return scan_repository(request.repository_path)
    except ScannerConfigurationError as error:
        raise HTTPException(
            status_code=500, detail="Scanner authorization is not configured."
        ) from error
    except ScannerSafetyError as error:
        raise HTTPException(
            status_code=503, detail="Secure scanning is unavailable on this platform."
        ) from error
    except RepositoryNotAllowedError as error:
        raise HTTPException(
            status_code=403, detail="Repository path is not authorized for scanning."
        ) from error
    except FileNotFoundError as error:
        raise HTTPException(
            status_code=400, detail="Repository path does not exist or is inaccessible."
        ) from error
    except NotADirectoryError as error:
        raise HTTPException(
            status_code=400, detail="Repository path must be an existing directory."
        ) from error
    except ValueError as error:
        raise HTTPException(status_code=400, detail="Invalid repository path.") from error