from typing import List

from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import Table, Column, ForeignKey, String, Integer, Boolean

from .constants import TokenType, SigningAlgorithm
from . import schemas, constants, tools


class Base(DeclarativeBase):
    pass


class TokenModel(Base):
    __tablename__ = "token_models"

    id: Mapped[str] = mapped_column(String(50), primary_key=True)
    token_type: Mapped[str] = mapped_column(String(10))
    issuer: Mapped[str] = mapped_column(String(200))
    expires_in: Mapped[int] = mapped_column(Integer())
    key_id: Mapped[str | None] = mapped_column(
        String(50), nullable=True)
    signing_algorithm: Mapped[
        str | None
    ] = mapped_column(String(10), nullable=True)

    def to_schema(self) -> schemas.TokenModel:
        if (self.token_type == TokenType.JWT.value):
            if (self.key_id is None):
                raise RuntimeError("The key id is never null for jwt tokens")

            jwk: constants.JWKInfo = constants.PRIVATE_JWKS[self.key_id]
            return schemas.JWTTokenModel(
                id=self.id,
                issuer=self.issuer,
                expires_in=self.expires_in,
                key_id=self.key_id,
                key=jwk.key,
                signing_algorithm=SigningAlgorithm(jwk.signing_algorithm)
            )

        raise NotImplementedError()


class Scope(Base):
    __tablename__ = "scopes"

    name: Mapped[str] = mapped_column(String(50), primary_key=True)
    description: Mapped[str] = mapped_column(String(200))

    def to_schema(self) -> schemas.Scope:
        return schemas.Scope(
            name=self.name,
            description=self.description
        )


class Client(Base):
    __tablename__ = "clients"

    id: Mapped[str] = mapped_column(String(50), primary_key=True)
    authn_method: Mapped[str] = mapped_column(String(50))
    hashed_secret: Mapped[str | None] = mapped_column(
        String(100), nullable=True)
    redirect_uris: Mapped[str] = mapped_column(String(1000))
    response_types: Mapped[str] = mapped_column(String(100))
    grant_types: Mapped[str] = mapped_column(String(200))
    is_pcke_required: Mapped[bool] = mapped_column(Boolean())
    extra_params: Mapped[str] = mapped_column(String(1000))
    scopes: Mapped[List[Scope]] = relationship(
        secondary=Table(
            "client_scope",
            Base.metadata,
            Column("client_id", ForeignKey("clients.id")),  # type: ignore
            Column("scope_name", ForeignKey("scopes.name")),  # type: ignore
        ),
        lazy="joined"
    )

    token_model_id: Mapped[int] = mapped_column(ForeignKey("token_models.id"))
    token_model: Mapped[TokenModel] = relationship(lazy="joined")

    def to_schema(self, secret: str | None = None) -> schemas.Client:
        return schemas.Client(
            id=self.id,
            authn_method=constants.ClientAuthnMethod(self.authn_method),
            secret=secret,
            hashed_secret=self.hashed_secret,
            redirect_uris=self.redirect_uris.split(","),
            response_types=[constants.ResponseType(
                response_type) for response_type in self.response_types.split(",")],
            grant_types=[constants.GrantType(
                grant_type) for grant_type in self.grant_types.split(",")],
            scopes=[scope.name for scope in self.scopes],
            is_pcke_required=self.is_pcke_required,
            token_model=self.token_model.to_schema(),
            extra_params=tools.to_json(base64_string=self.extra_params)
        )

    @classmethod
    def to_db_model(
        cls,
        client: schemas.ClientUpsert,
        scopes: List[Scope],
    ) -> "Client":
        return Client(
            id=client.id,
            authn_method=client.authn_method.value,
            hashed_secret=tools.hash_secret(
                client.secret
            ) if client.secret else None,
            redirect_uris=",".join(client.redirect_uris),
            response_types=",".join([r.value for r in client.response_types]),
            grant_types=",".join([gt.value for gt in client.grant_types]),
            is_pcke_required=client.is_pcke_required,
            scopes=scopes,
            token_model_id=client.token_model_id,
            extra_params=tools.to_base64_string(
                extra_params=client.extra_params
            )
        )
