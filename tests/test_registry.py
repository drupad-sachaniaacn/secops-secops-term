"""Generic ``Registry``: decorator, lookup, contains, length, clear, conflicts."""

from __future__ import annotations

import pytest

from secops_term.core import registry


class _Iface:
    """Sentinel base class for the typed registry."""


def test_register_and_get() -> None:
    r = registry.Registry[_Iface]("test")

    @r.register("foo")
    class Foo(_Iface):
        pass

    assert r.get("foo") is Foo


def test_double_register_raises() -> None:
    r = registry.Registry[_Iface]("test")

    @r.register("foo")
    class A(_Iface):
        pass

    with pytest.raises(registry.AlreadyRegistered):

        @r.register("foo")
        class B(_Iface):
            pass


def test_get_missing_raises() -> None:
    r = registry.Registry[_Iface]("test")
    with pytest.raises(registry.NotRegistered):
        r.get("missing")


def test_contains() -> None:
    r = registry.Registry[_Iface]("test")

    @r.register("foo")
    class A(_Iface):
        pass

    assert "foo" in r
    assert "bar" not in r
    assert 42 not in r  # non-string keys never match


def test_len() -> None:
    r = registry.Registry[_Iface]("test")
    assert len(r) == 0

    @r.register("a")
    class A(_Iface):
        pass

    @r.register("b")
    class B(_Iface):
        pass

    assert len(r) == 2


def test_keys_and_items() -> None:
    r = registry.Registry[_Iface]("test")

    @r.register("a")
    class A(_Iface):
        pass

    @r.register("b")
    class B(_Iface):
        pass

    assert sorted(r.keys()) == ["a", "b"]
    items = dict(r.items())
    assert set(items.keys()) == {"a", "b"}
    assert items["a"] is A
    assert items["b"] is B


def test_clear() -> None:
    r = registry.Registry[_Iface]("test")

    @r.register("a")
    class A(_Iface):
        pass

    r.clear()
    assert len(r) == 0
    assert "a" not in r


def test_decorator_returns_class_unchanged() -> None:
    r = registry.Registry[_Iface]("test")

    @r.register("a")
    class A(_Iface):
        pass

    # The decorator must return the class itself so ``A`` retains its identity.
    assert A.__name__ == "A"
    assert r.get("a") is A


def test_name_property() -> None:
    r = registry.Registry[_Iface]("my-registry")
    assert r.name == "my-registry"
