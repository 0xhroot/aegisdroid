"""Plugin SDK for AegisDroid."""

from __future__ import annotations

import importlib
import logging
import sys
from pathlib import Path
from typing import Any

from aegisdroid.core.domain import PluginMetadata
from aegisdroid.core.events import event_bus

logger = logging.getLogger(__name__)


class PluginBase:
    """Base class for AegisDroid plugins."""

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="base_plugin",
            version="0.0.0",
            description="Base plugin",
        )

    async def on_load(self) -> None:
        pass

    async def on_unload(self) -> None:
        pass


class PluginSDK:
    """Plugin discovery, loading, and management."""

    def __init__(self, plugin_dir: str = "") -> None:
        self._plugin_dir = (
            Path(plugin_dir) if plugin_dir else Path.home() / ".config" / "aegisdroid" / "plugins"
        )
        self._loaded: dict[str, Any] = {}
        self._commands: dict[str, Any] = {}
        self._scanners: dict[str, Any] = {}
        self._rules: dict[str, list[dict[str, Any]]] = {}

    async def discover_plugins(self) -> list[PluginMetadata]:
        plugins: list[PluginMetadata] = []
        if not self._plugin_dir.exists():
            return plugins

        for item in self._plugin_dir.iterdir():
            if item.is_dir() and (item / "__init__.py").exists():
                meta = await self._load_plugin_metadata(item)
                if meta:
                    plugins.append(meta)
            elif item.suffix == ".py" and item.stem != "__init__":
                meta = await self._load_plugin_metadata(item, is_file=True)
                if meta:
                    plugins.append(meta)

        return plugins

    async def load_plugin(self, name: str) -> Any:
        if name in self._loaded:
            return self._loaded[name]

        plugin_path = self._plugin_dir / name
        if plugin_path.is_dir():
            sys.path.insert(0, str(self._plugin_dir))
            try:
                mod = importlib.import_module(name)
                plugin_class = getattr(mod, "Plugin", None)
                if plugin_class and issubclass(plugin_class, PluginBase):
                    plugin = plugin_class()
                    await plugin.on_load()
                    self._loaded[name] = plugin
                    await event_bus.publish(
                        type(
                            "Event",
                            (),
                            {
                                "name": "plugin.loaded",
                                "data": {"name": name},
                                "source": "plugin_sdk",
                            },
                        )()
                    )
                    return plugin
            except Exception as e:
                logger.exception("Failed to load plugin '%s': %s", name, e)
            finally:
                if str(self._plugin_dir) in sys.path:
                    sys.path.remove(str(self._plugin_dir))

        return None

    async def register_command(self, name: str, handler: Any) -> None:
        self._commands[name] = handler

    async def register_scanner(self, name: str, scanner: Any) -> None:
        self._scanners[name] = scanner

    async def register_rule(self, name: str, rule: Any) -> None:
        self._rules.setdefault(name, []).append(rule)

    async def get_plugin(self, name: str) -> Any:
        return self._loaded.get(name)

    def list_loaded(self) -> list[str]:
        return list(self._loaded.keys())

    async def _load_plugin_metadata(
        self, path: Path, is_file: bool = False
    ) -> PluginMetadata | None:
        try:
            if is_file:
                sys.path.insert(0, str(path.parent))
                mod_name = path.stem
            else:
                sys.path.insert(0, str(self._plugin_dir))
                mod_name = path.name

            mod = importlib.import_module(mod_name)
            plugin_class = getattr(mod, "Plugin", None)
            if plugin_class and hasattr(plugin_class, "metadata"):
                inst = plugin_class()
                return inst.metadata
        except Exception:
            pass
        finally:
            pass
        return None
