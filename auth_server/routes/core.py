from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from . import oauth, management
from ..utils import exceptions

app = FastAPI()
app.include_router(oauth.router)
app.include_router(management.router)

@app.exception_handler(exceptions.HTTPException)
async def unicorn_exception_handler(_: Request, exc: exceptions.HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.error.value,
            "error_description": exc.error_description
        },
    )