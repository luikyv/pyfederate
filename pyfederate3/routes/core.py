from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.exceptions import RequestValidationError
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager

from . import oauth, scope, client, token
from ..utils import constants, telemetry, tools, config

from ..crud.auth import AuthCRUDManager
from ..utils.exceptions import OAuthJsonResponseException, OAuthRedirectResponseException
from ..crud.exceptions import EntityAlreadyExistsException, EntityDoesNotExistException

logger = telemetry.get_logger(__name__)

app = FastAPI(title="Custom Authorization Server", version=config.VERSION)
# app.mount("/templates/static", StaticFiles(directory="templates/static"), name="static")
app.include_router(oauth.router)
app.include_router(scope.router)
app.include_router(client.router)
app.include_router(token.router)

######################################## Shared ########################################


@app.get("/healthcheck", status_code=status.HTTP_204_NO_CONTENT)
def check_health() -> None:
    return

@asynccontextmanager
async def lifespan(app: FastAPI):
    AuthCRUDManager.get_manager().check_config()
    yield


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


@app.exception_handler(OAuthJsonResponseException)
def handle_json_exception(_: Request, exc: OAuthJsonResponseException):
    return JSONResponse(
        status_code=exc.error.value,
        content={
            "error": exc.error.name.lower(),
            "error_description": exc.error_description,
        },
    )


@app.exception_handler(OAuthRedirectResponseException)
def handle_redirect_exception(_: Request, exc: OAuthRedirectResponseException):

    redirect_params = {
        "error": exc.error.name.lower(),
        "error_description": exc.error_description,
    }
    if exc.state:
        redirect_params["state"] = exc.state

    return RedirectResponse(
        url=tools.prepare_redirect_url(
            url=exc.redirect_uri,
            params=redirect_params,
        ),
        status_code=status.HTTP_302_FOUND,
    )


@app.exception_handler(EntityAlreadyExistsException)
def handle_entity_already_exists_exception(
    _: Request, exc: EntityAlreadyExistsException
):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"error": "bad_request", "error_description": "entity already exists"},
    )


@app.exception_handler(EntityDoesNotExistException)
def handle_entity_does_not_exist_exception(
    _: Request, exc: EntityDoesNotExistException
):
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"error": "bad_request", "error_description": "entity does not exist"},
    )
