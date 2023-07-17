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

from . import constants

alphabet = string.ascii_letters + string.digits


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


def hash_secret(secret: str) -> str:
    return bcrypt.hashpw(
        secret.encode(constants.SECRET_ENCODING),
        bcrypt.gensalt()
    ).decode(constants.SECRET_ENCODING)


def prepare_redirect_url(url: str, params: Dict[str, str]) -> str:
    """Add path params to the redirect url"""

    request_url_builder = PreparedRequest()
    request_url_builder.prepare_url(url=url, params=params)
    return quote(str(request_url_builder.url), safe=":/%#?=@[]!$&'()*+,;")


def verify_matches_challenge(code_verifier: str, code_challenge: str) -> bool:
    return base64.urlsafe_b64encode(
        sha256(code_verifier.encode(constants.SECRET_ENCODING)).digest()
    ).decode(constants.SECRET_ENCODING) == code_challenge
