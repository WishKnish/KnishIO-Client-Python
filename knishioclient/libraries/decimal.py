# -*- coding: utf-8 -*-

MULTIPLIER = 10 ** 18


def val(value) -> float:
    if abs(float(value) * MULTIPLIER) < 1:
        return 0.0
    return float(value)


def cmp(val1, val2) -> int:
    value1 = val(val1) * MULTIPLIER
    value2 = val(val2) * MULTIPLIER

    if abs(value1 - value2) < 1:
        return 0

    return 1 if value1 > value2 else -1


def equal(val1, val2) -> bool:
    return cmp(val1, val2) == 0
