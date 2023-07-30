from typing import Dict
from requests.models import PreparedRequest
import secrets
import string
import bcrypt
import uuid
from random import randint
from urllib.parse import quote
from hashlib import sha256
import base64
import json
import time
import functools

from . import constants

alphabet = string.ascii_letters + string.digits


def singleton(cls):
    """Make a singleton class"""

    @functools.wraps(cls)
    def singleton_wrapper(*args, **kwargs):
        if singleton_wrapper.instance is None:
            singleton_wrapper.instance = cls(*args, **kwargs)
        return singleton_wrapper.instance

    singleton_wrapper.instance = None  # type: ignore
    return singleton_wrapper


def generate_uuid() -> str:
    return str(uuid.uuid4())


def generate_fixed_size_random_string(length: int) -> str:
    return "".join(
        secrets.choice(alphabet)
        for _ in range(length)
    )


def generate_random_string(min_length: int, max_length: int) -> str:
    return "".join(
        secrets.choice(alphabet)
        for _ in range(randint(min_length, max_length))
    )


def generate_client_id() -> str:
    return generate_random_string(constants.CLIENT_ID_MIN_LENGH, constants.CLIENT_ID_MAX_LENGH)


def generate_client_secret() -> str:
    return generate_random_string(constants.CLIENT_SECRET_MIN_LENGH, constants.CLIENT_SECRET_MAX_LENGH)


def generate_callback_id() -> str:
    return generate_fixed_size_random_string(constants.CALLBACK_ID_LENGTH)


def generate_authz_code() -> str:
    return generate_fixed_size_random_string(constants.AUTHORIZATION_CODE_LENGTH)


def generate_session_id() -> str:
    return generate_fixed_size_random_string(constants.SESSION_ID_LENGTH)


def generate_refresh_token() -> str:
    return generate_fixed_size_random_string(constants.REFRESH_TOKEN_LENGTH)


def hash_secret(secret: str) -> str:
    return bcrypt.hashpw(
        secret.encode(constants.SECRET_ENCODING),
        bcrypt.gensalt()
    ).decode(constants.SECRET_ENCODING)


def prepare_redirect_url(url: str, params: Dict[str, str]) -> str:
    """Add path params to the redirect url"""

    request_url_builder = PreparedRequest()
    request_url_builder.prepare_url(url=url, params=params)  # type: ignore
    return quote(str(request_url_builder.url), safe=":/%#?=@[]!$&'()*+,;")


def is_pkce_valid(code_verifier: str, code_challenge: str) -> bool:
    hashed_code_verifier = base64.urlsafe_b64encode(
        sha256(code_verifier.encode(constants.SECRET_ENCODING)).digest()
    ).decode(constants.SECRET_ENCODING).replace("=", "")  # Remove padding '='
    return hashed_code_verifier == code_challenge


def to_base64_string(extra_params: Dict[str, str]) -> str:
    return base64.b64encode(json.dumps(extra_params).encode(constants.SECRET_ENCODING)).decode(constants.SECRET_ENCODING)


def to_json(base64_string: str) -> Dict[str, str]:
    return json.loads(base64.b64decode(base64_string.encode(constants.SECRET_ENCODING)))


def get_timestamp_now() -> int:
    return int(time.time())
