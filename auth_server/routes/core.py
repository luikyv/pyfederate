from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse

from . import oauth, management
from ..utils import constants, telemetry, tools, exceptions

logger = telemetry.get_logger(__name__)

app = FastAPI()
app.include_router(oauth.router)
app.include_router(management.router)


@app.get(
    "/healthcheck",
    status_code=status.HTTP_204_NO_CONTENT
)
def check_health() -> None:
    return


@app.middleware("http")
async def set_telemetry_ids(request: Request, call_next) -> Response:
    """Set the tracking and correlation IDs for each request
    """

    # Set the default values for the tracking and correlation IDs
    telemetry.tracking_id.set(tools.generate_uuid())
    x_correlation_id: str | None = request.headers.get(
        constants.HTTPHeaders.X_CORRELATION_ID.value)
    if (x_correlation_id):
        telemetry.correlation_id.set(x_correlation_id)

    # Ensure clients don't cache the response
    response: Response = await call_next(request)
    response.headers["Cache-Control"] = "no-cache, no-store"

    return response


@app.exception_handler(exceptions.HTTPException)
def handle_general_http_exception(_: Request, exc: exceptions.HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.error.value,
            "error_description": exc.error_description
        },
    )
