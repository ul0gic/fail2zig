# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig maintainers
"""Bounded numeric duration expressions, without Python evaluation or name lookup.

Arbitrary executable expressions accepted by a legacy eval() are configuration errors.
Numeric reference preprocessing is retained, including its scientific/hex quirks.
"""
import ast
from dataclasses import dataclass
import math
import operator
import re

UNITS = [
    (r'days?|da|dd?',86400), (r'weeks?|wee?|ww?',604800),
    (r'months?|mon?',2629800.0), (r'years?|yea?|yy?',31557600.0),
    (r'seconds?|sec?|ss?',1), (r'minutes?|min?|mm?',60),
    (r'hours?|hou?|hh?',3600),
]
BINARY = {ast.Add:operator.add,ast.Sub:operator.sub,ast.Mult:operator.mul,
          ast.Div:operator.truediv,ast.FloorDiv:operator.floordiv,ast.Mod:operator.mod,
          ast.Pow:operator.pow,ast.BitAnd:operator.and_,ast.BitOr:operator.or_,
          ast.BitXor:operator.xor,ast.LShift:operator.lshift,ast.RShift:operator.rshift}
UNARY = {ast.UAdd:operator.pos,ast.USub:operator.neg,ast.Invert:operator.invert}


def checked(value):
    if type(value) is int:
        if value.bit_length() > 4096:
            raise ValueError('duration integer exceeds bit budget')
    elif type(value) is float:
        if not math.isfinite(value):
            raise ValueError('duration is not finite')
    else:
        raise ValueError('duration result is not real numeric')
    return value


def expression(text):
    if type(text) in (int,float):
        return checked(text)
    if not isinstance(text,str) or len(text)>4096:
        raise ValueError('invalid duration expression')
    # Unit suffix followed by digits is separated before unit replacement.
    normalized = re.sub(r'(?<=[a-z])(\d)',r' \1',text,flags=re.I)
    for aliases,multiplier in UNITS:
        normalized = re.sub(r'(?<=[\d\s])(?:'+aliases+r')\b','*'+str(multiplier),normalized,flags=re.I)
    normalized = re.sub(r'(\d)\s+(\d)',r'\1+\2',normalized)
    tree = ast.parse(normalized.strip(),mode='eval')
    if sum(1 for _ in ast.walk(tree)) > 256:
        raise ValueError('duration expression exceeds node budget')

    def evaluate(node,depth=0):
        if depth>32:
            raise ValueError('duration expression exceeds depth budget')
        if isinstance(node,ast.Constant):
            return checked(node.value)
        if isinstance(node,ast.UnaryOp) and type(node.op) in UNARY:
            return checked(UNARY[type(node.op)](evaluate(node.operand,depth+1)))
        if isinstance(node,ast.BinOp) and type(node.op) in BINARY:
            left,right = evaluate(node.left,depth+1),evaluate(node.right,depth+1)
            if isinstance(node.op,ast.Pow) and (abs(right)>4096 or (type(left) is int and type(right) is int and right>0 and left.bit_length()*right>4096)):
                raise ValueError('duration power exceeds budget')
            if isinstance(node.op,(ast.LShift,ast.RShift)) and (type(right) is not int or right<0 or right>4096):
                raise ValueError('duration shift exceeds budget')
            return checked(BINARY[type(node.op)](left,right))
        raise ValueError('only numeric arithmetic is permitted in durations')
    return evaluate(tree.body)


@dataclass(frozen=True)
class Duration:
    kind: str
    value: int | float | None


def parse(text,*,history=False):
    value = expression(text)
    if value == -1:
        return Duration('permanent',None)
    if history and value == -2:
        return Duration('legacy_unknown',None)
    if value<0:
        raise ValueError('negative finite duration')
    return Duration('finite',value)
