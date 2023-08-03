from tests import conftest
from auth_server.utils import schemas, helpers, exceptions
from auth_server.auth_manager import manager
import pytest
from unittest.mock import Mock, patch
import asyncio
asyncio.create_task


@pytest.mark.asyncio
async def test_get_authenticated_client_no_secret_provided(client: schemas.Client) -> None:

    manager.client_manager = Mock()
    manager.client_manager.get_client = Mock(
        side_effect=lambda *args, **kwargs: conftest.async_return(o=client))

    with pytest.raises(exceptions.ClientIsNotAuthenticatedException):
        _: schemas.Client = await helpers.get_authenticated_client(
            client_id=conftest.CLIENT_ID,
            client_secret=None
        )
