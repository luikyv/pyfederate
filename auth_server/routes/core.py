from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from . import oauth, management
from ..utils import constants, telemetry, tools, exceptions
from ..auth_manager import manager as auth_manager

logger = telemetry.get_logger(__name__)

app = FastAPI()
app.include_router(oauth.router)
app.include_router(management.router)

@app.middleware("http")
async def set_telemetry_ids(request: Request, call_next) -> Response:
    """Set the tracking and flow IDs for each request
    """

    x_flow_id: str | None = request.headers.get(constants.HTTPHeaders.X_FLOW_ID.value)
    callback_id: str | None = request.query_params.get("callback_id") # FIXME: Would that be a breach?

    if callback_id is not None:
        # If the callback_id is not None, fetch the session associated to it if it exists,
        # then set the tracking and flow IDs using the session information
        try:
            session_info = await auth_manager.session_manager.get_record_by_callback_id(callback_id=callback_id)
        except exceptions.SessionInfoDoesNotExist:
            logger.info(f"The callback ID: {callback_id} has no session associated with it")
            raise exceptions.SessionExpired(f"The session associated to the callback ID: {callback_id} has expired")
        
        telemetry.tracking_id.set(session_info.tracking_id)
        telemetry.flow_id.set(session_info.flow_id)
        return await call_next(request)
    
    # Set the default values for the tracking and flow IDs
    telemetry.tracking_id.set(tools.generate_uuid())
    if(x_flow_id): telemetry.flow_id.set(x_flow_id)

    return await call_next(request)

@app.exception_handler(exceptions.HTTPException)
def unicorn_exception_handler(_: Request, exc: exceptions.HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.error.value,
            "error_description": exc.error_description
        },
    )