# -*- coding: utf-8 -*-

from typing import Any


def _get(obj, key) -> Any:
    return obj[int(key) if key.isdecimal() else key]


def array_get(array, accessor: str, default=None) -> Any | None:
    for chunk in accessor.split('.'):
        try:
            array = _get(array, chunk)
            if isinstance(array, (str, bytes, bytearray, memoryview)):
                return default
        except (KeyError, IndexError, TypeError):
            return default
    return array


def array_has(array, accessor: str) -> bool:
    for chunk in accessor.split('.'):
        try:
            array = _get(array, chunk)
            if isinstance(array, (str, bytes, bytearray, memoryview)):
                return False
        except (KeyError, IndexError, TypeError):
            return False
    return True


def get_signed_atom(molecule: "Molecule") -> "Atom":
    return array_get(molecule.atoms, '0')
