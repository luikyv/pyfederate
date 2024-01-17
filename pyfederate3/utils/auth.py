from abc import ABC, abstractmethod
from fastapi import Request, Response
from inspect import isawaitable
from typing import Awaitable, Callable, Dict

from ..utils.constants import AuthnStatus
from ..schemas.auth import AuthnStepChain, AuthnStepInfo


class AuthnStepResult(ABC):
    @abstractmethod
    def get_status(
        self,
    ) -> AuthnStatus:
        ...


class AuthnStepInProgressResult(AuthnStepResult):
    def __init__(self, response: Response) -> None:
        self._response = response

    def get_response(self) -> Response:
        return self._response

    def get_status(self) -> AuthnStatus:
        return AuthnStatus.IN_PROGRESS


class AuthnStepSuccessResult(AuthnStepResult):
    def get_status(self) -> AuthnStatus:
        return AuthnStatus.SUCCESS


class AuthnStepFailureResult(AuthnStepResult):
    def get_status(self) -> AuthnStatus:
        return AuthnStatus.FAILURE


class AuthnStep:

    AUTHN_STEPS: Dict[str, "AuthnStep"] = {}

    def __init__(
        self,
        step_id: str,
        authn_func: Callable[[Request], AuthnStepResult | Awaitable[AuthnStepResult]],
    ) -> None:

        self._step_id = step_id
        self._authn_func = authn_func
        self._register_itself()

    def _register_itself(self) -> None:
        if self._step_id in AuthnStep.AUTHN_STEPS:
            raise RuntimeError(
                f"An authentication step with ID: {self._step_id} already exists"
            )
        AuthnStep.AUTHN_STEPS[self._step_id] = self

    async def authenticate(self, request: Request) -> AuthnStepResult:
        step_result = self._authn_func(request)
        return (
            await step_result if isawaitable(step_result) else step_result
        )  # type: ignore


class AuthnPolicy:
    def __init__(self, authn_step_chain: AuthnStepChain) -> None:
        self._authn_step_chain = authn_step_chain

    async def authenticate(self) -> Response:
        raise NotImplementedError()
