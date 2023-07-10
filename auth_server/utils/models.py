from typing import List

from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import Table, Column, ForeignKey, String

from . import schemas

class Base(DeclarativeBase):
    pass

client_scope_association_table = Table(
    "client_scope",
    Base.metadata,
    Column("client_id", ForeignKey("clients.id")),
    Column("scope_name", ForeignKey("scopes.name")),
)

class Scope(Base):
    __tablename__ = "scopes"

    name: Mapped[str] = mapped_column(String(50), primary_key=True, unique=True)
    description: Mapped[str] = mapped_column(String(200))

    def export(self) -> schemas.Scope:
        return schemas.Scope(
            name=self.name,
            description=self.description
        )

class Client(Base):
    __tablename__ = "clients"

    id: Mapped[str] = mapped_column(String(50), primary_key=True)
    hashed_secret: Mapped[str] = mapped_column(String(100))

    scopes: Mapped[List[Scope]] = relationship(secondary=client_scope_association_table, lazy='joined')

    def export(self) -> schemas.Client:
        return schemas.Client(
            id=self.id,
            hashed_secret=self.hashed_secret,
            scopes=[scope.name for scope in self.scopes]
        )
