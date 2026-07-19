"""Configuration management."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG_DIR = Path.home() / ".config" / "aegisdroid"
DEFAULT_DATA_DIR = Path.home() / ".local" / "share" / "aegisdroid"
DEFAULT_RULES_DIR = Path(__file__).parent.parent.parent / "rules"
DEFAULT_DB_PATH = DEFAULT_DATA_DIR / "aegis.db"


@dataclass
class ADBConfig:
    host: str = "127.0.0.1"
    port: int = 5037
    timeout: float = 30.0
    adb_path: str = "adb"


@dataclass
class DatabaseConfig:
    url: str = ""
    pool_size: int = 5
    echo: bool = False

    @property
    def effective_url(self) -> str:
        return self.url or f"sqlite+aiosqlite:///{DEFAULT_DB_PATH}"


@dataclass
class AIConfig:
    provider: str = "ollama"
    model: str = "llama3"
    ollama_host: str = "http://localhost:11434"
    openai_api_key: str = ""
    openai_model: str = "gpt-4"
    max_tokens: int = 4096
    temperature: float = 0.3
    enabled: bool = False


@dataclass
class YaraConfig:
    rules_dir: str = ""
    compiled_dir: str = ""
    max_file_size: int = 50 * 1024 * 1024  # 50MB
    timeout: int = 30

    @property
    def effective_rules_dir(self) -> str:
        return self.rules_dir or str(DEFAULT_RULES_DIR)


@dataclass
class ReportConfig:
    output_dir: str = ""
    formats: list[str] = field(default_factory=lambda: ["markdown", "html", "json"])
    include_evidence: bool = True
    include_timeline: bool = True
    template_dir: str = ""

    @property
    def effective_output_dir(self) -> str:
        return self.output_dir or str(DEFAULT_DATA_DIR / "reports")


@dataclass
class LiveMonitorConfig:
    poll_interval: float = 5.0
    alert_on_new_app: bool = True
    alert_on_permission_change: bool = True
    alert_on_usb_debugging: bool = True
    alert_on_developer_settings: bool = True
    alert_on_accessibility: bool = True
    alert_on_overlay: bool = True
    alert_on_vpn: bool = True
    alert_on_certificate: bool = True
    alert_on_network_change: bool = True


@dataclass
class ScanConfig:
    default_type: str = "quick"
    max_apk_size: int = 500 * 1024 * 1024  # 500MB
    hash_algorithms: list[str] = field(default_factory=lambda: ["sha256", "md5"])
    parallel: bool = True
    max_workers: int = 4
    timeout: float = 300.0


@dataclass
class PluginConfig:
    enabled: bool = True
    directory: str = ""
    auto_discover: bool = True

    @property
    def effective_directory(self) -> str:
        return self.directory or str(Path.home() / ".config" / "aegisdroid" / "plugins")


@dataclass
class ThemeConfig:
    name: str = "dark"
    accent_color: str = "#00ff88"
    error_color: str = "#ff4444"
    warning_color: str = "#ffaa00"
    info_color: str = "#4488ff"
    success_color: str = "#00ff88"


@dataclass
class AegisConfig:
    adb: ADBConfig = field(default_factory=ADBConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    yara: YaraConfig = field(default_factory=YaraConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    live_monitor: LiveMonitorConfig = field(default_factory=LiveMonitorConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    plugin: PluginConfig = field(default_factory=PluginConfig)
    theme: ThemeConfig = field(default_factory=ThemeConfig)
    verbose: bool = False
    debug: bool = False

    @classmethod
    def from_file(cls, path: str) -> AegisConfig:
        config_path = Path(path)
        if not config_path.exists():
            return cls()
        with open(config_path) as f:
            data = yaml.safe_load(f) or {}
        return cls._from_dict(data)

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> AegisConfig:
        config = cls()
        if "adb" in data:
            config.adb = ADBConfig(**data["adb"])
        if "database" in data:
            config.database = DatabaseConfig(**data["database"])
        if "ai" in data:
            config.ai = AIConfig(**data["ai"])
        if "yara" in data:
            config.yara = YaraConfig(**data["yara"])
        if "report" in data:
            config.report = ReportConfig(**data["report"])
        if "live_monitor" in data:
            config.live_monitor = LiveMonitorConfig(**data["live_monitor"])
        if "scan" in data:
            config.scan = ScanConfig(**data["scan"])
        if "plugin" in data:
            config.plugin = PluginConfig(**data["plugin"])
        if "theme" in data:
            config.theme = ThemeConfig(**data["theme"])
        config.verbose = data.get("verbose", False)
        config.debug = data.get("debug", False)
        return config

    def save(self, path: str | None = None) -> None:
        config_path = Path(path or DEFAULT_CONFIG_DIR / "config.yaml")
        config_path.parent.mkdir(parents=True, exist_ok=True)

        data: dict[str, Any] = {
            "adb": self.adb.__dict__,
            "database": self.database.__dict__,
            "ai": self.ai.__dict__,
            "yara": self.yara.__dict__,
            "report": self.report.__dict__,
            "live_monitor": self.live_monitor.__dict__,
            "scan": self.scan.__dict__,
            "plugin": self.plugin.__dict__,
            "theme": self.theme.__dict__,
            "verbose": self.verbose,
            "debug": self.debug,
        }
        with open(config_path, "w") as f:
            yaml.dump(data, f, default_flow_style=False)


def load_config(config_path: str | None = None) -> AegisConfig:
    """Load configuration from file or defaults."""
    if config_path and Path(config_path).exists():
        return AegisConfig.from_file(config_path)

    default_path = DEFAULT_CONFIG_DIR / "config.yaml"
    if default_path.exists():
        return AegisConfig.from_file(str(default_path))

    return AegisConfig()
