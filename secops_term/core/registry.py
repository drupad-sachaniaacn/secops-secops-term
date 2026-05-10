"""Generic registry + module-discovery helper.

Used by the intel-provider and notifier subsystems to maintain a name → class
mapping populated by ``@register("name")`` decorators on concrete
implementations, with concrete-implementation modules discovered at startup
via ``pkgutil.iter_modules``.

Per brief v3 §5: ``intel/providers/`` and ``notifications/`` follow the same
pattern. This module provides the shared mechanics so the two subsystems
don't duplicate registry code.
"""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Callable, Iterable
from typing import Generic, TypeVar

T = TypeVar("T")


class RegistryError(Exception):
    """Base class for registry errors."""


class AlreadyRegistered(RegistryError):
    """A name is already registered in this registry."""


class NotRegistered(RegistryError):
    """A name is not in the registry."""


class Registry(Generic[T]):
    """Name-keyed mapping of registered classes.

    Concrete classes register themselves via the :meth:`register` decorator.
    Discovery (importing every concrete module under a package) is the
    caller's responsibility — see :func:`discover_modules`.

    Type parameter ``T`` is the Protocol or base class registered classes
    must satisfy. The registry itself does not enforce the contract — Python
    Protocols are checked structurally at use sites.
    """

    def __init__(self, name: str) -> None:
        self._name = name
        self._items: dict[str, type[T]] = {}

    @property
    def name(self) -> str:
        return self._name

    def register(self, key: str) -> Callable[[type[T]], type[T]]:
        """Decorator: register ``cls`` under ``key`` in this registry."""

        def decorator(cls: type[T]) -> type[T]:
            if key in self._items:
                raise AlreadyRegistered(
                    f"{self._name}: key {key!r} already registered to {self._items[key].__name__}"
                )
            self._items[key] = cls
            return cls

        return decorator

    def get(self, key: str) -> type[T]:
        """Return the class registered under ``key`` or raise :class:`NotRegistered`."""
        if key not in self._items:
            raise NotRegistered(f"{self._name}: no entry for {key!r}")
        return self._items[key]

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and key in self._items

    def __len__(self) -> int:
        return len(self._items)

    def keys(self) -> list[str]:
        return list(self._items.keys())

    def items(self) -> list[tuple[str, type[T]]]:
        return list(self._items.items())

    def clear(self) -> None:
        """Remove every entry. Tests only — production code should not call this."""
        self._items.clear()

    def snapshot(self) -> dict[str, type[T]]:
        """Return a shallow copy of the current registry contents. Tests only.

        Used together with :meth:`restore` so a per-test autouse fixture can
        preserve the concrete providers/notifiers loaded at session start
        while still wiping any synthetic entries a single test registered.
        """
        return dict(self._items)

    def restore(self, snapshot: dict[str, type[T]]) -> None:
        """Replace registry contents with ``snapshot``. Tests only."""
        self._items = dict(snapshot)


def discover_modules(package_name: str, *, skip: Iterable[str] = ()) -> list[str]:
    """Import every non-underscore submodule of ``package_name``.

    Returns the names of modules imported (relative to the package).
    Modules in ``skip`` and any starting with ``_`` are excluded. ``base``
    is always skipped — that module conventionally holds Protocol/base-class
    definitions, not concrete registrations.
    """
    skip_set = set(skip) | {"base"}
    package = importlib.import_module(package_name)
    if not hasattr(package, "__path__"):
        return []
    discovered: list[str] = []
    for mod_info in pkgutil.iter_modules(package.__path__):
        if mod_info.name.startswith("_") or mod_info.name in skip_set:
            continue
        importlib.import_module(f"{package_name}.{mod_info.name}")
        discovered.append(mod_info.name)
    return discovered
