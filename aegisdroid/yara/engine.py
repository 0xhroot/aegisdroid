"""YARA rule scanning engine."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from aegisdroid.core.domain import (
    YaraMatch,
)

logger = logging.getLogger(__name__)

YARA_AVAILABLE = False
try:
    import yara

    YARA_AVAILABLE = True
except ImportError:
    logger.warning("yara-python not installed, YARA scanning disabled")


DEFAULT_RULES_DIR = Path(__file__).parent.parent.parent / "rules"


class YaraEngine:
    """YARA rule compilation and scanning."""

    def __init__(self, rules_dir: str = "") -> None:
        self._rules_dir = Path(rules_dir) if rules_dir else DEFAULT_RULES_DIR
        self._compiled_rules: Any = None

    async def compile_rules(self, rules_path: str = "") -> Any:
        if not YARA_AVAILABLE:
            logger.warning("yara-python not available")
            return None

        path = Path(rules_path) if rules_path else self._rules_dir
        rule_files = list(path.rglob("*.yar")) + list(path.rglob("*.yara"))

        if not rule_files:
            logger.info("No YARA rules found in %s", path)
            return None

        try:
            {f.name: str(f) for f in rule_files}
            namespaces = {}
            for f in rule_files:
                ns = f.stem
                namespaces[ns] = str(f)

            self._compiled_rules = yara.compile(filepaths=namespaces)
            logger.info("Compiled %d YARA rule files", len(rule_files))
            return self._compiled_rules
        except yara.SyntaxError as e:
            logger.exception("YARA rule compilation error: %s", e)
            return None

    async def scan_file(self, file_path: str, rules_path: str = "") -> list[YaraMatch]:
        if not YARA_AVAILABLE:
            return []

        rules = self._compiled_rules
        if not rules:
            rules = await self.compile_rules(rules_path)
        if not rules:
            return []

        matches = []
        try:
            results = rules.match(file_path, timeout=30)
            for match in results:
                yara_match = YaraMatch(
                    rule_name=match.rule,
                    namespace=match.namespace,
                    meta=dict(match.meta) if match.meta else {},
                    description=match.meta.get("description", "") if match.meta else "",
                    author=match.meta.get("author", "") if match.meta else "",
                    tags=list(match.tags) if match.tags else [],
                    file_path=file_path,
                    strings=[
                        (
                            s.identifier,
                            s.instances[0].offset if s.instances else 0,
                            str(s.instances[0].matched_data[:50]) if s.instances else "",
                        )
                        for s in match.strings
                    ]
                    if match.strings
                    else [],
                )
                matches.append(yara_match)
        except yara.TimeoutError:
            logger.warning("YARA scan timed out for: %s", file_path)
        except Exception as e:
            logger.exception("YARA scan error for %s: %s", file_path, e)

        return matches

    async def scan_directory(self, dir_path: str, rules_path: str = "") -> list[YaraMatch]:
        all_matches: list[YaraMatch] = []
        dirp = Path(dir_path)
        if not dirp.exists():
            return []

        for file_path in dirp.rglob("*"):
            if file_path.is_file() and file_path.stat().st_size < 50 * 1024 * 1024:
                file_matches = await self.scan_file(str(file_path), rules_path)
                all_matches.extend(file_matches)

        return all_matches

    async def scan_apk(self, apk_path: str, rules_path: str = "") -> list[YaraMatch]:
        all_matches: list[YaraMatch] = []

        file_match = await self.scan_file(apk_path, rules_path)
        all_matches.extend(file_match)

        try:
            import zipfile

            with zipfile.ZipFile(apk_path) as zf:
                for name in zf.namelist():
                    if name.endswith((".dex", ".so", ".xml", ".json", ".js")):
                        try:
                            data = zf.read(name)
                            tmp_path = f"/tmp/_aegis_yara_{name.replace('/', '_')}"
                            with open(tmp_path, "wb") as f:
                                f.write(data)
                            matches = await self.scan_file(tmp_path, rules_path)
                            for m in matches:
                                m.file_path = f"{apk_path}!/{name}"
                            all_matches.extend(matches)
                            os.unlink(tmp_path)
                        except Exception:
                            pass
        except Exception as e:
            logger.exception("APK YARA scan error: %s", e)

        return all_matches

    async def list_rules(self, rules_path: str = "") -> list[str]:
        path = Path(rules_path) if rules_path else self._rules_dir
        rules = []
        for f in path.rglob("*.yar"):
            rules.append(str(f))
        for f in path.rglob("*.yara"):
            rules.append(str(f))
        return rules
