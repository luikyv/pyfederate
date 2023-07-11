import secrets
import string
import bcrypt
import uuid

from . import constants

alphabet = string.ascii_letters + string.digits

def generate_uuid() -> str:
    return str(uuid.uuid4())

def generate_client_id() -> str:
    return "".join(secrets.choice(alphabet) for _ in range(constants.CLIENT_ID_LENGH))

def generate_client_secret() -> str:
    return "".join(secrets.choice(alphabet) for _ in range(constants.CLIENT_SECRET_LENGH))

def hash_secret(secret: str) -> str:
    return bcrypt.hashpw(secret.encode(constants.SECRET_ENCODING), bcrypt.gensalt()).decode(constants.SECRET_ENCODING)