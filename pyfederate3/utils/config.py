from enum import Enum
import logging
import os
from dotenv import load_dotenv
import base64
import json


class Environment(Enum):
    PROD = "PROD"
    TEST = "TEST"
    LOCAL = "LOCAL"


ENVIRONMENT = Environment(os.getenv("ENVIRONMENT", "TEST"))
if ENVIRONMENT == Environment.TEST:
    load_dotenv("tests/test.env")
LOG_LEVEL = logging.getLevelName(os.environ.get("LOG_LEVEL", "DEBUG"))
CLIENT_ID_MIN_LENGH = int(os.getenv("CLIENT_ID_MIN_LENGH", 5))
CLIENT_ID_MAX_LENGH = int(os.getenv("CLIENT_ID_MAX_LENGH", 50))
CLIENT_SECRET_MIN_LENGH = int(os.getenv("CLIENT_SECRET_MIN_LENGH", 10))
CLIENT_SECRET_MAX_LENGH = int(os.getenv("CLIENT_SECRET_MAX_LENGH", 50))
CALLBACK_ID_LENGTH = int(os.getenv("CALLBACK_ID_LENGTH", 20))
SESSION_ID_LENGTH = int(os.getenv("SESSION_ID_LENGTH", 20))
REFRESH_TOKEN_LENGTH = int(os.getenv("REFRESH_TOKEN_LENGTH", 20))
AUTHORIZATION_CODE_LENGTH = int(os.getenv("AUTHORIZATION_CODE_LENGTH", 20))
STATE_PARAM_MAX_LENGTH = int(os.getenv("STATE_PARAM_MAX_LENGTH", 100))
SECRET_ENCODING = os.getenv("SECRET_ENCODING", "utf-8")
AUTHORIZATION_CODE_TIMEOUT = int(os.getenv("AUTHORIZATION_SESSION_TIMEOUT", 300))
REQUEST_URI_LENGTH = int(os.getenv("REQUEST_URI_LENGTH", 20))
REQUEST_URI_TIMEOUT = int(os.getenv("REQUEST_URI_TIMEOUT", 60))
SERVER_PORT = int(os.getenv("SERVER_PORT", 80))
VERSION = os.getenv("VERSION", "0.1.0")
PRIVATE_JWKS_JSON = json.loads(
    # The privates jwks are passed as a base64 enconded json through the env var PRIVATE_JWKS_JSON
    base64.b64decode(os.environ["PRIVATE_JWKS_JSON"]).decode(SECRET_ENCODING)
)
