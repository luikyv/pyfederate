from typing import List, Dict
from pydantic import BaseModel
from pyfederate.utils import exceptions


class A(BaseModel):
    a: str


class A1(A):
    a1: str


class B(BaseModel):
    a: A


a1 = A1(a="a", a1="a1")
b = B(a=a1)
b1 = B(**dict(b))
print(b)
print(b1)
print(dict(b))
