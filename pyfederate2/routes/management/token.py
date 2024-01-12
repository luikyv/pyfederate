from typing import Annotated, List
from fastapi import Path, APIRouter, status

from ...utils.schemas.token import TokenModelAPIIn, TokenModelAPIOut, TokenModel
from ...utils.managers.auth import AuthManager
from ...utils.managers.token import TokenModelManager

router = APIRouter(tags=["management", "token"])
auth_manager = AuthManager()
token_model_manager: TokenModelManager = auth_manager.token_model_manager


@router.post(
    "/token-model",
    status_code=status.HTTP_201_CREATED,
)
async def create_token_model(
    token_model_input: TokenModelAPIIn,
) -> None:
    await token_model_manager.create_token_model(
        token_model=token_model_input.to_token_model()
    )


@router.put(
    "/token-model/{id}",
    status_code=status.HTTP_200_OK,
)
async def update_token_model(
    token_model_id: Annotated[str, Path(alias="id")],
    token_model_input: TokenModelAPIIn,
) -> None:
    await token_model_manager.update_token_model(
        token_model_id=token_model_id, token_model=token_model_input.to_token_model()
    )


@router.get(
    "/token-model/{id}",
    status_code=status.HTTP_200_OK,
)
async def get_token_model(
    token_model_id: Annotated[str, Path(alias="id")]
) -> TokenModelAPIOut:
    token_model: TokenModel = await token_model_manager.get_token_model(
        token_model_id=token_model_id
    )
    return token_model.to_output()  # type: ignore


@router.get(
    "/token-models",
    status_code=status.HTTP_200_OK,
)
async def get_token_models() -> List[TokenModelAPIOut]:
    token_models: List[TokenModel] = await token_model_manager.get_token_models()

    # type: ignore
    return [token_model.to_output() for token_model in token_models]


@router.delete(
    "/token-model/{id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_token_model(
    token_model_id: Annotated[str, Path(alias="id")],
) -> None:
    await token_model_manager.delete_token_model(token_model_id=token_model_id)
