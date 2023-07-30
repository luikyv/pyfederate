from auth_server.utils import tools
from auth_server.utils import constants


def test_generate_uuid() -> None:
    """Test if generate_uuid generates random values"""
    first_uuid = tools.generate_uuid()
    second_uuid = tools.generate_uuid()
    assert first_uuid != second_uuid


def test_generate_fixed_size_random_string() -> None:
    """Test if generate_fixed_size_random_string strings with the specified size"""
    assert len(tools.generate_fixed_size_random_string(10)) == 10


def test_generate_random_string() -> None:
    """Test if generate_random_string generates random values with the specified size"""
    first_string = tools.generate_random_string(10, 15)
    second_string = tools.generate_random_string(10, 15)

    assert len(first_string) >= 10 and len(first_string) <= 15
    assert first_string != second_string


def test_generate_client_id() -> None:
    """Test if the client id generated has the right size and is random"""
    first_client_id = tools.generate_client_id()
    second_client_id = tools.generate_client_id()

    assert len(first_client_id) >= constants.CLIENT_ID_MIN_LENGH and len(
        first_client_id) <= constants.CLIENT_ID_MAX_LENGH
    assert first_client_id != second_client_id


def test_generate_client_secret() -> None:
    """Test if the client secret generated has the right size and is random"""
    first_client_secret = tools.generate_client_secret()
    second_client_secret = tools.generate_client_secret()

    assert len(first_client_secret) >= constants.CLIENT_SECRET_MIN_LENGH and len(
        first_client_secret) <= constants.CLIENT_SECRET_MAX_LENGH
    assert first_client_secret != second_client_secret


def test_generate_callback_id() -> None:
    """Test if the callback id generated has the right size and is random"""
    first_callback_id = tools.generate_callback_id()
    second_callback_id = tools.generate_callback_id()

    assert len(first_callback_id) == constants.CALLBACK_ID_LENGTH
    assert first_callback_id != second_callback_id


def test_generate_authz_code() -> None:
    """Test if the authz code generated has the right size and is random"""
    first_authz_code = tools.generate_authz_code()
    second_authz_code = tools.generate_authz_code()

    assert len(first_authz_code) == constants.AUTHORIZATION_CODE_LENGTH
    assert first_authz_code != second_authz_code


def test_generate_session_id() -> None:
    """Test if the session id generated has the right size and is random"""
    first_session_id = tools.generate_session_id()
    second_session_id = tools.generate_session_id()

    assert len(first_session_id) == constants.SESSION_ID_LENGTH
    assert first_session_id != second_session_id


def test_generate_refresh_token() -> None:
    """Test if the refresh token generated has the right size and is random"""
    first_refresh_token = tools.generate_refresh_token()
    second_refresh_token = tools.generate_refresh_token()

    assert len(first_refresh_token) == constants.REFRESH_TOKEN_LENGTH
    assert first_refresh_token != second_refresh_token
