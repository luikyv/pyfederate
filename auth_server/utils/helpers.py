import secrets
import string
import bcrypt

from .constants import CLIENT_SECRET_LENGH, CLIENT_ID_LENGH, SECRET_ENCODING

alphabet = string.ascii_letters + string.digits

def generate_client_id() -> str:
    return "".join(secrets.choice(alphabet) for _ in range(CLIENT_ID_LENGH))

def generate_client_secret() -> str:
    return "".join(secrets.choice(alphabet) for _ in range(CLIENT_SECRET_LENGH))

def hash_secret(secret: str) -> str:
    return bcrypt.hashpw(secret.encode(SECRET_ENCODING), bcrypt.gensalt()).decode(SECRET_ENCODING)