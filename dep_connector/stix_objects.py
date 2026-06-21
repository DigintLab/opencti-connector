from collections.abc import Iterable
from typing import Protocol, TypeVar


class StixObject(Protocol):
    id: str


TStixObject = TypeVar("TStixObject", bound=StixObject)


def dedupe_by_stix_id(objects: Iterable[TStixObject]) -> list[TStixObject]:
    return list({stix_object.id: stix_object for stix_object in objects}.values())
