from abc import ABC, abstractmethod
from fastapi import Request, Response
from inspect import isawaitable
from typing import Awaitable, Callable, Dict, List

from .constants import AuthnStatus
from ..utils.client import Client
from ..schemas.auth import AuthnStepChain, NextAuthnSteps


class AuthnResponse(ABC):
    @abstractmethod
    def get_status(
        self,
    ) -> AuthnStatus:
        ...

    @abstractmethod
    def get_response(
        self,
    ) -> Response:
        ...


class AuthnStepInProgressResult(AuthnResponse):
    def __init__(self, response: Response) -> None:
        self._response = response

    def get_response(self) -> Response:
        return self._response

    def get_status(self) -> AuthnStatus:
        return AuthnStatus.IN_PROGRESS


class AuthnStepSuccessResult(AuthnResponse):
    def get_status(self) -> AuthnStatus:
        return AuthnStatus.SUCCESS

    def get_response(self) -> Response:
        raise NotImplementedError()


class AuthnStepFailureResult(AuthnResponse):
    def get_status(self) -> AuthnStatus:
        return AuthnStatus.FAILURE

    def get_response(self) -> Response:
        raise NotImplementedError()


class AuthnStep:

    AUTHN_STEPS: Dict[str, "AuthnStep"] = {}

    def __init__(
        self,
        step_id: str,
        authn_func: Callable[[Request], AuthnResponse | Awaitable[AuthnResponse]],
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

    def get_step_id(self) -> str:
        return self._step_id

    @classmethod
    def get_step(cls, step_id: str) -> "AuthnStep":
        return AuthnStep.AUTHN_STEPS[step_id]

    async def authenticate(self, request: Request) -> AuthnResponse:
        step_result = self._authn_func(request)
        return (
            await step_result if isawaitable(step_result) else step_result
        )  # type: ignore


class AuthnPolicy:

    AUTHN_POLICIES: Dict[str, "AuthnPolicy"] = {}

    def __init__(
        self,
        policy_id: str,
        authn_step_chain: AuthnStepChain,
        is_available: Callable[[Client, Request], bool],
    ) -> None:
        self._policy_id = policy_id
        self._authn_step_chain = authn_step_chain
        self._is_available = is_available
        self._register_itself()

    def _register_itself(self) -> None:
        if self._policy_id in AuthnPolicy.AUTHN_POLICIES:
            raise RuntimeError(
                f"An authentication policy with ID: {self._policy_id} already exists"
            )
        AuthnPolicy.AUTHN_POLICIES[self._policy_id] = self

    @classmethod
    def get_policy(cls, client: Client, request: Request) -> "AuthnPolicy":
        available_policies: List[AuthnPolicy] = list(
            filter(
                lambda policy: policy.is_available(client, request),
                AuthnPolicy.AUTHN_POLICIES.values(),
            )
        )
        if len(available_policies) == 0:
            raise RuntimeError("No authentication policy available")

        return available_policies[0]

    def is_available(self, client: Client, request: Request) -> bool:
        return self.is_available(client, request)

    async def authenticate(self, request: Request) -> Response:

        authn_step: AuthnStep | None = AuthnStep.get_step("")
        last_response: AuthnResponse
        while authn_step:

            last_response = await authn_step.authenticate(request=request)
            if last_response.get_status() == AuthnStatus.IN_PROGRESS:
                return last_response.get_response()

            authn_step = self._get_next_step_when_failure_or_success(
                current_step_id=authn_step.get_step_id(),
                current_status_status=last_response.get_status(),
            )

        return last_response  # type: ignore

    def _get_next_step_when_failure_or_success(
        self, current_step_id: str, current_status_status: AuthnStatus
    ) -> AuthnStep | None:
        next_steps: NextAuthnSteps = self._authn_step_chain.next_authn_step_map[
            current_step_id
        ]
        if current_status_status == AuthnStatus.SUCCESS:
            return (
                AuthnStep.get_step(next_steps.next_step_id_if_success)
                if next_steps.next_step_id_if_success
                else None
            )
        elif current_status_status == AuthnStatus.FAILURE:
            return (
                AuthnStep.get_step(next_steps.next_step_id_if_failure)
                if next_steps.next_step_id_if_failure
                else None
            )
        else:
            return AuthnStep.get_step(current_step_id)
