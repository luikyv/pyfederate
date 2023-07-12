import typing
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from . import oauth, management
from ..utils import constants, telemetry, tools, exceptions

app = FastAPI()
app.include_router(oauth.router)
app.include_router(management.router)

@app.middleware("http")
async def set_telemetry_ids(request: Request, call_next) -> Response:
    """Set the tracking and flow IDs for each request
    """

    telemetry.tracking_id.set(tools.generate_uuid())
    x_flow_id: typing.Optional[str] = request.headers[constants.HTTPHeaders.X_FLOW_ID.value]
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