# -*- coding: utf-8 -*-
"""
Rule, Condition and Callback: the structure of an R-isotope rule.

Ported from the JS reference (src/instance/Rules/{Rule,Condition,Callback,Meta}.js). The
``to_json`` dicts carry JS's key order and drop the same empty fields, because
``Molecule.init_rule_creation`` serializes them into the atom's hashed ``rule`` meta.
"""

import math
from typing import Any, Dict, List

from ..exception import CodeException, MetaMissingException, RuleArgumentException


def _is_js_falsy(value: Any) -> bool:
    """JS truthiness: None, False, '', 0 and NaN are falsy; [] and {} are truthy."""
    if value is None or value is False:
        return True
    if isinstance(value, str):
        return value == ''
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value == 0 or (isinstance(value, float) and math.isnan(value))
    return False


def _is_numeric(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return math.isfinite(value)
    if isinstance(value, str):
        try:
            return math.isfinite(float(value))
        except ValueError:
            return False
    return False


class Condition:
    """A rule condition: key, value and comparison, all mandatory."""

    def __init__(self, key: Any, value: Any, comparison: Any) -> None:
        if any(_is_js_falsy(item) for item in (key, value, comparison)):
            raise RuleArgumentException(
                'Condition::constructor( { key, value, comparison } ) - not all class parameters are initialised!'
            )
        self.key = key
        self.value = value
        self.comparison = comparison

    @classmethod
    def to_object(cls, obj: Dict[str, Any]) -> 'Condition':
        return cls(obj.get('key'), obj.get('value'), obj.get('comparison'))

    def to_json(self) -> Dict[str, Any]:
        return {'key': self.key, 'value': self.value, 'comparison': self.comparison}


class Callback:
    """A rule callback: a mandatory action plus optional fields."""

    def __init__(self, action: Any, meta_type: Any = None, meta_id: Any = None, meta: Any = None,
                 address: Any = None, token: Any = None, amount: Any = None, comparison: Any = None) -> None:
        if _is_js_falsy(action):
            raise RuleArgumentException('Callback structure violated, missing mandatory "action" parameter.')
        if not _is_js_falsy(amount) and not _is_numeric(amount):
            raise CodeException('Parameter amount should be a string containing numbers')
        self.action = action
        self.meta_type = meta_type
        self.meta_id = meta_id
        self.meta = None if _is_js_falsy(meta) else dict(meta)
        self.address = address
        self.token = token
        self.amount = amount
        self.comparison = comparison

    @classmethod
    def to_object(cls, obj: Dict[str, Any]) -> 'Callback':
        return cls(
            obj.get('action'),
            meta_type=obj.get('metaType'),
            meta_id=obj.get('metaId'),
            meta=obj.get('meta'),
            address=obj.get('address'),
            token=obj.get('token'),
            amount=obj.get('amount'),
            comparison=obj.get('comparison')
        )

    def to_json(self) -> Dict[str, Any]:
        # JS Callback.toJSON: `action` first, then each optional field only when truthy.
        result: Dict[str, Any] = {'action': self.action}
        for key, value in (('metaType', self.meta_type), ('metaId', self.meta_id), ('meta', self.meta),
                           ('address', self.address), ('token', self.token), ('amount', self.amount),
                           ('comparison', self.comparison)):
            if not _is_js_falsy(value):
                result[key] = value
        return result


class Rule:
    """A rule: its conditions and the callbacks that run when they hold."""

    def __init__(self, condition: List[Condition] | None = None, callback: List[Callback] | None = None) -> None:
        condition = condition or []
        callback = callback or []
        if not all(isinstance(item, Condition) for item in condition) \
                or not all(isinstance(item, Callback) for item in callback):
            raise RuleArgumentException()
        self.condition = condition
        self.callback = callback

    @classmethod
    def to_object(cls, obj: Dict[str, Any]) -> 'Rule':
        if _is_js_falsy(obj.get('condition')):
            raise MetaMissingException('Rule::toObject() - Incorrect rule format! There is no condition field.')
        if _is_js_falsy(obj.get('callback')):
            raise MetaMissingException('Rule::toObject() - Incorrect rule format! There is no callback field.')
        return cls(
            [item if isinstance(item, Condition) else Condition.to_object(item) for item in obj['condition']],
            [item if isinstance(item, Callback) else Callback.to_object(item) for item in obj['callback']]
        )

    def to_json(self) -> Dict[str, Any]:
        return {'condition': [item.to_json() for item in self.condition],
                'callback': [item.to_json() for item in self.callback]}
