"""Dependency injection container."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class Container:
    """Lightweight dependency injection container."""

    def __init__(self) -> None:
        self._services: dict[str, Any] = {}
        self._factories: dict[str, Any] = {}
        self._singletons: dict[str, Any] = {}

    def register(self, name: str, service: Any) -> None:
        self._services[name] = service

    def register_factory(self, name: str, factory: Any) -> None:
        self._factories[name] = factory

    def register_singleton(self, name: str, factory: Any) -> None:
        self._services[name] = ("_singleton_factory", factory)

    def resolve(self, name: str) -> Any:
        if name in self._services:
            entry = self._services[name]
            if isinstance(entry, tuple) and entry[0] == "_singleton_factory":
                if name not in self._singletons:
                    self._singletons[name] = entry[1]()
                return self._singletons[name]
            return entry
        if name in self._factories:
            return self._factories[name]()
        raise KeyError(f"Service '{name}' not registered")

    def has(self, name: str) -> bool:
        return name in self._services or name in self._factories

    def list_services(self) -> list[str]:
        return list(set(list(self._services.keys()) + list(self._factories.keys())))


# Global container
container = Container()
