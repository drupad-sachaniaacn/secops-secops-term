"""Sandbox rejects every classic Python sandbox-escape vector.

These tests are the primary guarantee that the AST-walking evaluator cannot
be coerced into reaching ``__class__``, ``__bases__``, ``__subclasses__``,
or any other dunder pathway that would let a malicious playbook reach
builtins. Failing any of these is a security regression.
"""

from __future__ import annotations

import pytest

from secops_term.playbooks import sandbox

pytestmark = pytest.mark.security


# Direct dunder access via attribute


@pytest.mark.parametrize(
    "expr",
    [
        "ioc.__class__",
        "ioc.__class__.__bases__",
        "ioc.value.__class__",
        "().__class__",
        "(1).__class__.__mro__",
        "[].__class__",
        "ioc.__init__",
        "ioc.__getattribute__",
        "ioc.__dict__",
        "ioc.__module__",
    ],
)
def test_dunder_attribute_rejected(expr: str) -> None:
    with pytest.raises(sandbox.SandboxError):
        sandbox.evaluate(expr, {"ioc": {"value": "x"}})


def test_single_underscore_attribute_rejected() -> None:
    with pytest.raises(sandbox.DisallowedAttribute):
        sandbox.evaluate("ioc._private", {"ioc": {}})


# Dunder access via subscript


@pytest.mark.parametrize(
    "expr",
    [
        "ioc['__class__']",
        "ioc['__bases__']",
        "ioc['__subclasses__']",
        "ioc['_private']",
    ],
)
def test_dunder_subscript_rejected(expr: str) -> None:
    with pytest.raises(sandbox.DisallowedAttribute):
        sandbox.evaluate(expr, {"ioc": {}})


# Calls forbidden


@pytest.mark.parametrize(
    "expr",
    [
        "len('foo')",
        "print('hi')",
        "ioc.value()",
        "open('/etc/passwd')",
        "__import__('os')",
        "globals()",
        "locals()",
        "exec('1+1')",
        "eval('1+1')",
        "ioc.value.upper()",
    ],
)
def test_calls_rejected(expr: str) -> None:
    with pytest.raises(sandbox.SandboxError):
        sandbox.evaluate(expr, {"ioc": {"value": "x"}})


# Lambda forbidden


def test_lambda_rejected() -> None:
    with pytest.raises(sandbox.SandboxError):
        sandbox.evaluate("(lambda x: x)(1)", {"ioc": {}})


# Comprehensions forbidden


@pytest.mark.parametrize(
    "expr",
    [
        "[x for x in [1, 2, 3]]",
        "{x for x in [1, 2, 3]}",
        "{k: v for k, v in [(1, 2)]}",
        "(x for x in [1, 2, 3])",
    ],
)
def test_comprehensions_rejected(expr: str) -> None:
    with pytest.raises(sandbox.SandboxError):
        sandbox.evaluate(expr, {"ioc": {}})


# Dict / set literals forbidden


@pytest.mark.parametrize("expr", ["{1: 2}", "{1, 2, 3}"])
def test_dict_set_literals_rejected(expr: str) -> None:
    with pytest.raises(sandbox.SandboxError):
        sandbox.evaluate(expr, {"ioc": {}})


# f-strings forbidden


def test_fstring_rejected() -> None:
    with pytest.raises(sandbox.SandboxError):
        sandbox.evaluate("f'{ioc}'", {"ioc": "x"})


# Walrus / NamedExpr forbidden


def test_walrus_rejected() -> None:
    with pytest.raises(sandbox.SandboxError):
        sandbox.evaluate("(x := 5)", {"ioc": {}})


# Starred / unpacking forbidden


def test_starred_rejected() -> None:
    with pytest.raises(sandbox.SandboxError):
        sandbox.evaluate("[*[1, 2, 3]]", {"ioc": {}})


# Names not in whitelist


@pytest.mark.parametrize(
    "expr",
    ["os", "sys", "__builtins__", "len", "open", "True_but_not"],
)
def test_unknown_names_rejected(expr: str) -> None:
    with pytest.raises(sandbox.DisallowedName):
        sandbox.evaluate(expr, {"ioc": {}})


# Restricted operators


@pytest.mark.parametrize(
    "expr",
    [
        "2 ** 100",  # Pow: DoS via large int
        "1 << 100",  # LShift: DoS
        "1 >> 1",  # RShift
        "1 & 2",  # BitAnd
        "1 | 2",  # BitOr
        "1 ^ 2",  # BitXor
        "7 // 2",  # FloorDiv (not in allowlist)
        "+1",  # UAdd (not in allowlist; only USub)
        "~1",  # Invert
    ],
)
def test_disallowed_operators_rejected(expr: str) -> None:
    with pytest.raises(sandbox.DisallowedOperator):
        sandbox.evaluate(expr, {"ioc": {}})


# Slicing inside subscript


def test_slice_rejected() -> None:
    with pytest.raises(sandbox.SandboxError):
        sandbox.evaluate("ioc.value[0:2]", {"ioc": {"value": "abc"}})


# Integer subscript


def test_integer_subscript_rejected() -> None:
    with pytest.raises(sandbox.SandboxError):
        sandbox.evaluate("ioc[0]", {"ioc": {"0": "x"}})


# Tuple-key subscript


def test_tuple_subscript_rejected() -> None:
    with pytest.raises(sandbox.SandboxError):
        sandbox.evaluate("ioc[1, 2]", {"ioc": {}})


# String concat (BinOp Add on strings) rejected


def test_string_concat_rejected() -> None:
    with pytest.raises(sandbox.TypeMismatch):
        sandbox.evaluate("'a' + 'b'", {"ioc": {}})


def test_binop_string_and_int_rejected() -> None:
    with pytest.raises(sandbox.TypeMismatch):
        sandbox.evaluate("ioc.value + 1", {"ioc": {"value": "x"}})


def test_binop_with_bool_rejected() -> None:
    # bool is int subclass; we explicitly reject.
    with pytest.raises(sandbox.TypeMismatch):
        sandbox.evaluate("True + 1", {"ioc": {}})


# List/Tuple may only contain constants


def test_list_with_attribute_rejected() -> None:
    with pytest.raises(sandbox.DisallowedNode):
        sandbox.evaluate("[ioc.value]", {"ioc": {"value": "x"}})


def test_tuple_with_attribute_rejected() -> None:
    with pytest.raises(sandbox.DisallowedNode):
        sandbox.evaluate("(ioc.value,)", {"ioc": {"value": "x"}})


def test_list_with_call_rejected() -> None:
    with pytest.raises(sandbox.SandboxError):
        sandbox.evaluate("[len('a')]", {"ioc": {}})


# Parse-level errors


@pytest.mark.parametrize(
    "expr",
    [
        "",  # empty
        "   ",  # whitespace-only
        "(",  # unbalanced
        "1 +",  # incomplete
        "x = 5",  # statement, not expression (mode='eval' rejects)
    ],
)
def test_parse_errors(expr: str) -> None:
    with pytest.raises(sandbox.ParseError):
        sandbox.evaluate(expr, {})


# Classic CPython sandbox-escape attempts


def test_subclasses_chain_rejected() -> None:
    """``[].__class__.__bases__[0].__subclasses__()`` is the canonical escape."""
    with pytest.raises(sandbox.SandboxError):
        sandbox.evaluate("[].__class__.__bases__[0].__subclasses__()", {"ioc": {}})


def test_mro_chain_rejected() -> None:
    with pytest.raises(sandbox.SandboxError):
        sandbox.evaluate("(1).__class__.__mro__[0]", {"ioc": {}})


def test_globals_via_function_rejected() -> None:
    with pytest.raises(sandbox.SandboxError):
        sandbox.evaluate("(lambda: x).__globals__", {"ioc": {}})


def test_format_string_attack_rejected() -> None:
    """`'{0.__class__}'.format(x)` is another classic vector."""
    with pytest.raises(sandbox.SandboxError):
        sandbox.evaluate("'{0.__class__}'.format(ioc)", {"ioc": {}})


def test_attribute_chain_to_dunder_rejected() -> None:
    """Even chained access through legitimate attributes can't reach dunders."""
    with pytest.raises(sandbox.SandboxError):
        sandbox.evaluate("ioc.value.value.__class__", {"ioc": {"value": "x"}})


# DoS: even valid operations on huge constants don't get accepted via Pow / shifts
# (already covered by disallowed-operator tests; this is the explicit DoS check).


def test_pow_dos_rejected() -> None:
    """Pow could materialize a 30 MiB integer and OOM the process."""
    with pytest.raises(sandbox.DisallowedOperator):
        sandbox.evaluate("10 ** 10000000", {"ioc": {}})


def test_lshift_dos_rejected() -> None:
    with pytest.raises(sandbox.DisallowedOperator):
        sandbox.evaluate("1 << 10000000", {"ioc": {}})
