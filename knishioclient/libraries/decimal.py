# -*- coding: utf-8 -*-

MULTIPLIER = 10 ** 18


def val(value) -> float:
    # Handle None, empty strings, and other invalid values gracefully
    if value is None or value == "" or value == "null":
        return 0.0
    try:
        float_val = float(value)
        if abs(float_val * MULTIPLIER) < 1:
            return 0.0
        return float_val
    except (ValueError, TypeError):
        return 0.0


def cmp(val1, val2) -> int:
    try:
        value1 = val(val1) * MULTIPLIER
        value2 = val(val2) * MULTIPLIER

        if abs(value1 - value2) < 1:
            return 0

        return 1 if value1 > value2 else -1
    except (TypeError, ValueError, AttributeError):
        # If any operation fails, treat as equal (return 0)
        return 0


def equal(val1, val2) -> bool:
    return cmp(val1, val2) == 0
