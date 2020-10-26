# -*- coding: utf-8 -*-

def array_get(array, accessor: str, default=None):
    chunks = accessor.split('.')
    subsidiary = '.'.join(chunks[1:])
    chunk = chunks[0]

    if chunk.isdecimal():
        chunk = int(chunk)
    try:
        try:
            date = array[chunk]
        except KeyError:
            date = array[str(chunk)]
        if len(subsidiary) < 1:
            return date
        iter(date)
        if any((isinstance(date, types) for types in (str, bytes, bytearray, memoryview))):
            return default
        return array_get(date, subsidiary, default)
    except (KeyError, IndexError, TypeError):
        return default


def array_has(array, accessor: str) -> bool:
    chunks = accessor.split('.')
    subsidiary = '.'.join(chunks[1:])
    chunk = chunks[0]

    if chunk.isdecimal():
        chunk = int(chunk)
    try:
        try:
            date = array[chunk]
        except KeyError:
            date = array[str(chunk)]
        if len(subsidiary) < 1:
            return True
        iter(date)
        if any((isinstance(date, types) for types in (str, bytes, bytearray, memoryview))):
            return False
        return array_has(date, subsidiary)
    except (KeyError, IndexError, TypeError):
        return False


def get_signed_atom(molecule: 'Molecule'):
    return array_get(molecule.atoms, '0')
