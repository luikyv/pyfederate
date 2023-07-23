from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse

from . import oauth, management
from ..utils import constants, telemetry, tools, exceptions

logger = telemetry.get_logger(__name__)

app = FastAPI()
app.include_router(oauth.router)
app.include_router(management.router)

######################################## Shared ########################################


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

######################################## Exceptions ########################################


@app.exception_handler(exceptions.TokenModelAlreadyExistsException)
def handle_token_model_already_exists_exception(_: Request, exc: exceptions.TokenModelAlreadyExistsException):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "error": constants.ErrorCode.INVALID_REQUEST,
            "error_description": exc.message if exc.message else "token model id already exists"
        },
    )


@app.exception_handler(exceptions.TokenModelDoesNotExistException)
def handle_token_model_does_not_exist_exception(_: Request, exc: exceptions.TokenModelDoesNotExistException):
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={
            "error": constants.ErrorCode.INVALID_REQUEST,
            "error_description": exc.message if exc.message else "token model id does not exist"
        },
    )


@app.exception_handler(exceptions.ScopeAlreadyExistsException)
def handle_scope_already_exists_exception(_: Request, exc: exceptions.ScopeAlreadyExistsException):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "error": constants.ErrorCode.INVALID_REQUEST,
            "error_description": exc.message if exc.message else "scope already exists"
        },
    )


@app.exception_handler(exceptions.ScopeDoesNotExistException)
def handle_scope_does_not_exist_exception(_: Request, exc: exceptions.ScopeDoesNotExistException):
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={
            "error": constants.ErrorCode.INVALID_REQUEST,
            "error_description": exc.message if exc.message else "scope does not exist"
        },
    )


@app.exception_handler(exceptions.ClientAlreadyExistsException)
def handle_client_already_exists_exception(_: Request, exc: exceptions.ClientAlreadyExistsException):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "error": constants.ErrorCode.INVALID_REQUEST,
            "error_description": exc.message if exc.message else "client already exists"
        },
    )


@app.exception_handler(exceptions.ClientDoesNotExistException)
def handle_client_does_not_exist_exception(_: Request, exc: exceptions.ClientDoesNotExistException):
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={
            "error": constants.ErrorCode.INVALID_REQUEST,
            "error_description": exc.message if exc.message else "client does not exist"
        },
    )


@app.exception_handler(exceptions.SessionInfoDoesNotExistException)
def handle_authn_session_does_not_exist_exception(_: Request, exc: exceptions.SessionInfoDoesNotExistException):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "error": constants.ErrorCode.INVALID_REQUEST,
            "error_description": exc.message if exc.message else "client does not exist"
        },
    )


@app.exception_handler(exceptions.ClientIsNotAuthenticatedException)
def handle_unauthenticated_client_exception(_: Request, exc: exceptions.ClientIsNotAuthenticatedException):
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={
            "error": constants.ErrorCode.INVALID_CLIENT,
            "error_description": exc.message if exc.message else "invalid credentials"
        },
    )


@app.exception_handler(exceptions.RequestedScopesAreNotAllowedException)
def handle_scopes_not_allowed_exception(_: Request, exc: exceptions.RequestedScopesAreNotAllowedException):
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={
            "error": constants.ErrorCode.INVALID_SCOPE,
            "error_description": exc.message if exc.message else "the scopes requested are invalid"
        },
    )
