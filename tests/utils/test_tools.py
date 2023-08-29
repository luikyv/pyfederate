from pyfederate.utils import tools
from pyfederate.utils import constants


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

    assert (
        len(first_client_id) >= constants.CLIENT_ID_MIN_LENGH
        and len(first_client_id) <= constants.CLIENT_ID_MAX_LENGH
    ), "The client ID length is wrong"
    assert first_client_id != second_client_id, "The client ID generation is not random"


def test_generate_client_secret() -> None:
    """Test if the client secret generated has the right size and is random"""
    first_client_secret = tools.generate_client_secret()
    second_client_secret = tools.generate_client_secret()

    assert (
        len(first_client_secret) >= constants.CLIENT_SECRET_MIN_LENGH
        and len(first_client_secret) <= constants.CLIENT_SECRET_MAX_LENGH
    ), "The client secret length is wrong"
    assert (
        first_client_secret != second_client_secret
    ), "The client secret generation is not random"


def test_generate_callback_id() -> None:
    """Test if the callback id generated has the right size and is random"""
    first_callback_id = tools.generate_callback_id()
    second_callback_id = tools.generate_callback_id()

    assert (
        len(first_callback_id) == constants.CALLBACK_ID_LENGTH
    ), "The callback ID length is wrong"
    assert (
        first_callback_id != second_callback_id
    ), "The callback ID generation is not random"


def test_generate_authz_code() -> None:
    """Test if the authz code generated has the right size and is random"""
    first_authz_code = tools.generate_authz_code()
    second_authz_code = tools.generate_authz_code()

    assert (
        len(first_authz_code) == constants.AUTHORIZATION_CODE_LENGTH
    ), "The authorization code length is wrong"
    assert (
        first_authz_code != second_authz_code
    ), "The authorization code generation is not random"


def test_generate_session_id() -> None:
    """Test if the session id generated has the right size and is random"""
    first_session_id = tools.generate_session_id()
    second_session_id = tools.generate_session_id()

    assert (
        len(first_session_id) == constants.SESSION_ID_LENGTH
    ), "The session ID length is wrong"
    assert (
        first_session_id != second_session_id
    ), "The session ID generation is not random"


def test_generate_refresh_token() -> None:
    """Test if the refresh token generated has the right size and is random"""
    first_refresh_token = tools.generate_refresh_token()
    second_refresh_token = tools.generate_refresh_token()

    assert (
        len(first_refresh_token) == constants.REFRESH_TOKEN_LENGTH
    ), "The refresh token has the wrong length"
    assert (
        first_refresh_token != second_refresh_token
    ), "The refresh token generation is not random"


def test_prepare_redirect_url() -> None:
    """Test if the query string are well formatted in the redirect URL"""

    base_url = "https://localhost:8080/callback"
    assert f"{base_url}?param=value" == tools.prepare_redirect_url(
        base_url, params={"param": "value"}
    ), "The redirect URL is not correctly formatted"

    base_url = "https://localhost:8080/callback?param1=value1"
    assert f"{base_url}&param2=value2" == tools.prepare_redirect_url(
        base_url, params={"param2": "value2"}
    ), "The redirect URL is not correctly formatted"


def test_is_pkce_valid() -> None:
    """Test if the PKCE verifier is valid"""

    code_verifier = "ddd27dbe773010c9c3285b7450149cb3aeca3614fdb44f9a3261f46c"

    right_code_challenge = "zEoYP65FtQf2MGS5rK5OZjBuY_6BiFvr4LFzO4VC_IU"
    assert tools.is_pkce_valid(
        code_verifier=code_verifier, code_challenge=right_code_challenge
    ), "The code challenge should be right"

    wrong_code_challenge = "wrong_code_challenge"
    assert not tools.is_pkce_valid(
        code_verifier=code_verifier, code_challenge=wrong_code_challenge
    ), "The code challenge should be wrong"


def test_encode_decode_json() -> None:
    original_json = {"key1": "value1", "key2": {"key2_1": "value2_1"}}

    assert (
        tools.to_json(tools.to_base64_string(extra_params=original_json))
        == original_json
    ), "Problem converting json to base64"
