from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.exceptions import RequestValidationError
from fastapi.staticfiles import StaticFiles

from . import oauth, management
from ..utils import constants, telemetry, tools, exceptions

logger = telemetry.get_logger(__name__)

app = FastAPI()
app.mount("/templates/static", StaticFiles(directory="templates/static"), name="static")
app.include_router(oauth.router)
app.include_router(management.router)

######################################## Shared ########################################


@app.get("/healthcheck", status_code=status.HTTP_200_OK)
def check_health() -> None:
    return


@app.middleware("http")
async def set_telemetry_ids(request: Request, call_next) -> Response:
    """Set the tracking and correlation IDs for each request"""

    # Set the default values for the tracking and correlation IDs
    telemetry.tracking_id.set(tools.generate_uuid())
    x_correlation_id: str | None = request.headers.get(
        constants.HTTPHeaders.X_CORRELATION_ID.value
    )
    if x_correlation_id:
        telemetry.correlation_id.set(x_correlation_id)

    response: Response = await call_next(request)
    # Ensure clients don't cache the response
    response.headers[constants.HTTPHeaders.CACHE_CONTROL.value] = "no-cache, no-store"
    response.headers[constants.HTTPHeaders.PRAGMA.value] = "no-cache"

    return response


######################################## Exceptions ########################################

#################### Model Validation Exceptions ####################


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "error": constants.ErrorCode.INVALID_REQUEST.name.lower(),
            "error_description": str(exc),
        },
    )


#################### Custom Exceptions ####################


@app.exception_handler(exceptions.JsonResponseException)
def handle_json_exception(_: Request, exc: exceptions.JsonResponseException):
    return JSONResponse(
        status_code=exc.error.value,
        content={
            "error": exc.error.name.lower(),
            "error_description": exc.error_description,
        },
    )


@app.exception_handler(exceptions.RedirectResponseException)
def handle_redirect_exception(_: Request, exc: exceptions.RedirectResponseException):
    return RedirectResponse(
        url=tools.prepare_redirect_url(
            url=exc.redirect_uri,
            params={
                "error": exc.error.name.lower(),
                "error_description": exc.error_description,
            },
        ),
        status_code=status.HTTP_302_FOUND,
    )


@app.exception_handler(exceptions.EntityAlreadyExistsException)
def handle_entity_already_exists_exception(
    _: Request, exc: exceptions.EntityAlreadyExistsException
):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"error": "bad_request", "error_description": "entity already exists"},
    )


@app.exception_handler(exceptions.EntityDoesNotExistException)
def handle_entity_does_not_exist_exception(
    _: Request, exc: exceptions.EntityDoesNotExistException
):
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"error": "bad_request", "error_description": "entity does not exist"},
    )
