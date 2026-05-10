"""AST-walking template evaluator for playbook expressions.

Per brief v3 §3.5.7. This is the security primitive that lets playbook YAML
contain ``{{ expr }}`` substrings without exposing the host process to
arbitrary code execution.

**Allowed AST nodes:**

- ``Expression`` (top-level wrapper)
- ``Constant`` (literals: ``str``, ``int``, ``float``, ``bool``, ``None``)
- ``Name`` (only whitelisted: ``ioc``, ``steps``)
- ``Attribute`` (no dunder/underscore-prefixed names)
- ``Subscript`` (string-literal keys only, no underscore prefix)
- ``Compare`` (``==``, ``!=``, ``<``, ``<=``, ``>``, ``>=``, ``in``,
  ``not in``, ``is``, ``is not``)
- ``BoolOp`` (``and``, ``or``)
- ``UnaryOp`` (``Not``, ``USub``)
- ``BinOp`` (``Add``, ``Sub``, ``Mult``, ``Div``, ``Mod`` — numerics only,
  no booleans)
- ``IfExp`` (``x if cond else y``)
- ``List`` / ``Tuple`` of constants

**Disallowed:** ``Call``, ``Lambda``, comprehensions, dict/set literals,
f-strings, walrus, star args, slicing, attribute access to ``_``-prefixed
names, anything else.

Validation runs as a SEPARATE PASS before evaluation. The injection-corpus
tests assert that disallowed expressions fail at validation, never reaching
evaluation.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Mapping
from typing import Any

_ALLOWED_NAMES = frozenset({"ioc", "steps"})

_ALLOWED_BINOP: tuple[type[ast.operator], ...] = (
    ast.Add,
    ast.Sub,
    ast.Mult,
    ast.Div,
    ast.Mod,
)
_ALLOWED_UNARYOP: tuple[type[ast.unaryop], ...] = (ast.Not, ast.USub)
_ALLOWED_BOOLOP: tuple[type[ast.boolop], ...] = (ast.And, ast.Or)
_ALLOWED_CMPOP: tuple[type[ast.cmpop], ...] = (
    ast.Eq,
    ast.NotEq,
    ast.Lt,
    ast.LtE,
    ast.Gt,
    ast.GtE,
    ast.In,
    ast.NotIn,
    ast.Is,
    ast.IsNot,
)

_NUMERIC_TYPES: tuple[type, ...] = (int, float)
_CONST_TYPES: tuple[type, ...] = (int, float, bool, str, type(None))

# Non-greedy match so multiple ``{{ ... }}`` substrings in one template
# are parsed independently. ``re.DOTALL`` lets expressions span newlines.
_TEMPLATE_RE = re.compile(r"\{\{\s*(.*?)\s*\}\}", re.DOTALL)


class SandboxError(Exception):
    """Base class for all sandbox violations."""


class ParseError(SandboxError):
    """Expression failed to parse as a Python expression."""


class DisallowedNode(SandboxError):
    """An AST node type is not in the allowlist."""


class DisallowedName(SandboxError):
    """A ``Name`` reference is not in the whitelist."""


class DisallowedAttribute(SandboxError):
    """Attribute access to a dunder/underscore-prefixed name."""


class DisallowedOperator(SandboxError):
    """Operator within an otherwise-allowed node is not allowed."""


class TypeMismatch(SandboxError):
    """An operation was applied to incompatible types."""


class NotFound(SandboxError):
    """Attribute or subscript key was not in the context."""


# Public API


def parse_expr(expr_str: str) -> ast.Expression:
    """Parse ``expr_str`` as a single Python expression.

    Raises :class:`ParseError` on any syntax error or if the input parses
    as a statement rather than an expression.
    """
    if not expr_str or not expr_str.strip():
        raise ParseError("empty expression")
    try:
        tree = ast.parse(expr_str, mode="eval")
    except SyntaxError as exc:
        raise ParseError(f"could not parse: {exc.msg}") from exc
    if not isinstance(tree, ast.Expression):
        raise ParseError("expected a single expression")
    return tree


def validate(tree: ast.Expression) -> None:
    """Validate every node in ``tree`` against the allowlist. No evaluation occurs.

    Raises a :class:`SandboxError` subclass on the first violation.
    """
    _validate_node(tree.body)


def evaluate(expr_str: str, context: Mapping[str, Any]) -> Any:
    """Parse, validate, and evaluate ``expr_str`` against ``context``.

    ``context`` keys must be in the whitelist (``ioc`` and ``steps``).
    Attribute access and string-key subscript both descend into dict-shaped
    sub-contexts.
    """
    tree = parse_expr(expr_str)
    validate(tree)
    return _eval(tree.body, context)


def evaluate_template(template: str, context: Mapping[str, Any]) -> str:
    """Substitute every ``{{ expr }}`` in ``template`` with its evaluated string."""

    def _replace(match: re.Match[str]) -> str:
        expr_str = match.group(1)
        value = evaluate(expr_str, context)
        return str(value)

    return _TEMPLATE_RE.sub(_replace, template)


# Validation


def _validate_node(node: ast.AST) -> None:
    if isinstance(node, ast.Constant):
        if not isinstance(node.value, _CONST_TYPES):
            raise DisallowedNode(f"constant of type {type(node.value).__name__} not allowed")
        return

    if isinstance(node, ast.Name):
        if node.id not in _ALLOWED_NAMES:
            raise DisallowedName(f"name {node.id!r} not in whitelist {sorted(_ALLOWED_NAMES)}")
        return

    if isinstance(node, ast.Attribute):
        if node.attr.startswith("_"):
            raise DisallowedAttribute(f"attribute {node.attr!r} starts with underscore")
        _validate_node(node.value)
        return

    if isinstance(node, ast.Subscript):
        if not isinstance(node.slice, ast.Constant):
            raise DisallowedNode("subscript only allows constant keys")
        _validate_node(node.slice)
        if not isinstance(node.slice.value, str):
            raise DisallowedNode("subscript key must be a string literal")
        if node.slice.value.startswith("_"):
            raise DisallowedAttribute(f"subscript key {node.slice.value!r} starts with underscore")
        _validate_node(node.value)
        return

    if isinstance(node, ast.Compare):
        for op in node.ops:
            if not isinstance(op, _ALLOWED_CMPOP):
                raise DisallowedOperator(f"comparison operator {type(op).__name__} not allowed")
        _validate_node(node.left)
        for cmp_node in node.comparators:
            _validate_node(cmp_node)
        return

    if isinstance(node, ast.BoolOp):
        if not isinstance(node.op, _ALLOWED_BOOLOP):
            raise DisallowedOperator(f"bool op {type(node.op).__name__} not allowed")
        for v in node.values:
            _validate_node(v)
        return

    if isinstance(node, ast.UnaryOp):
        if not isinstance(node.op, _ALLOWED_UNARYOP):
            raise DisallowedOperator(f"unary op {type(node.op).__name__} not allowed")
        _validate_node(node.operand)
        return

    if isinstance(node, ast.BinOp):
        if not isinstance(node.op, _ALLOWED_BINOP):
            raise DisallowedOperator(f"binary op {type(node.op).__name__} not allowed")
        _validate_node(node.left)
        _validate_node(node.right)
        return

    if isinstance(node, ast.IfExp):
        _validate_node(node.test)
        _validate_node(node.body)
        _validate_node(node.orelse)
        return

    if isinstance(node, (ast.List, ast.Tuple)):
        for elt in node.elts:
            if not isinstance(elt, ast.Constant):
                raise DisallowedNode(f"{type(node).__name__} elements must be constants")
            _validate_node(elt)
        return

    raise DisallowedNode(f"AST node type {type(node).__name__} not allowed")


# Evaluation (assumes validation has already run)


def _eval(node: ast.AST, context: Mapping[str, Any]) -> Any:
    if isinstance(node, ast.Constant):
        return node.value

    if isinstance(node, ast.Name):
        if node.id not in context:
            raise NotFound(f"name {node.id!r} not in context")
        return context[node.id]

    if isinstance(node, ast.Attribute):
        obj = _eval(node.value, context)
        return _access_member(obj, node.attr)

    if isinstance(node, ast.Subscript):
        obj = _eval(node.value, context)
        # Validation guarantees slice is a Constant of str type.
        if not isinstance(node.slice, ast.Constant):
            raise SandboxError("internal: subscript slice not validated")
        key = node.slice.value
        if not isinstance(key, str):
            raise SandboxError("internal: subscript key not validated")
        return _access_member(obj, key)

    if isinstance(node, ast.Compare):
        left = _eval(node.left, context)
        for op, comparator_node in zip(node.ops, node.comparators, strict=True):
            right = _eval(comparator_node, context)
            if not _compare(left, op, right):
                return False
            left = right
        return True

    if isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.And):
            last: Any = True
            for v in node.values:
                last = _eval(v, context)
                if not last:
                    return last
            return last
        # Or
        last_or: Any = False
        for v in node.values:
            last_or = _eval(v, context)
            if last_or:
                return last_or
        return last_or

    if isinstance(node, ast.UnaryOp):
        operand = _eval(node.operand, context)
        if isinstance(node.op, ast.Not):
            return not operand
        # USub — numeric only, exclude bool. Inline `(int, float)` so mypy
        # narrows the type for the negation that follows.
        if isinstance(operand, bool) or not isinstance(operand, (int, float)):
            raise TypeMismatch(f"unary - on non-numeric: {type(operand).__name__}")
        return -operand

    if isinstance(node, ast.BinOp):
        left = _eval(node.left, context)
        right = _eval(node.right, context)
        return _binop(left, node.op, right)

    if isinstance(node, ast.IfExp):
        cond = _eval(node.test, context)
        if cond:
            return _eval(node.body, context)
        return _eval(node.orelse, context)

    if isinstance(node, ast.List):
        return [_eval(e, context) for e in node.elts]

    if isinstance(node, ast.Tuple):
        return tuple(_eval(e, context) for e in node.elts)

    raise DisallowedNode(f"unexpected node at eval time: {type(node).__name__}")


def _access_member(obj: Any, name: str) -> Any:
    """Access ``name`` on ``obj`` (treating ``obj`` as a Mapping)."""
    if name.startswith("_"):
        # Belt-and-suspenders: validation should have caught this.
        raise DisallowedAttribute(f"member {name!r} starts with underscore")
    if isinstance(obj, Mapping):
        if name not in obj:
            raise NotFound(f"key {name!r} not in mapping")
        return obj[name]
    raise SandboxError(
        f"member access on {type(obj).__name__} not allowed; "
        f"only dict-shaped contexts are supported"
    )


def _compare(left: Any, op: ast.cmpop, right: Any) -> bool:
    if isinstance(op, ast.Eq):
        return bool(left == right)
    if isinstance(op, ast.NotEq):
        return bool(left != right)
    if isinstance(op, ast.Lt):
        return bool(left < right)
    if isinstance(op, ast.LtE):
        return bool(left <= right)
    if isinstance(op, ast.Gt):
        return bool(left > right)
    if isinstance(op, ast.GtE):
        return bool(left >= right)
    if isinstance(op, ast.In):
        return bool(left in right)
    if isinstance(op, ast.NotIn):
        return bool(left not in right)
    if isinstance(op, ast.Is):
        return left is right
    if isinstance(op, ast.IsNot):
        return left is not right
    raise DisallowedOperator(f"unexpected cmp op: {type(op).__name__}")


def _binop(left: Any, op: ast.operator, right: Any) -> Any:
    # Numerics only — strict on type, refuse bool (because bool is int subclass).
    for x in (left, right):
        if isinstance(x, bool) or not isinstance(x, _NUMERIC_TYPES):
            raise TypeMismatch(
                f"binop requires numeric operands, got "
                f"{type(left).__name__} and {type(right).__name__}"
            )
    if isinstance(op, ast.Add):
        return left + right
    if isinstance(op, ast.Sub):
        return left - right
    if isinstance(op, ast.Mult):
        return left * right
    if isinstance(op, ast.Div):
        return left / right
    if isinstance(op, ast.Mod):
        return left % right
    raise DisallowedOperator(f"unexpected binop: {type(op).__name__}")
