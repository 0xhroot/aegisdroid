# Benchmarks

## Running Benchmarks

```bash
# Install benchmark dependencies
pip install pytest-benchmark

# Run benchmarks
pytest benchmarks/ -v --benchmark-only
```

## Benchmarks

| Benchmark | Description | Target |
|-----------|-------------|--------|
| `test_quick_scan` | Quick scan without device | < 100ms |
| `test_apk_analysis` | APK parsing (small) | < 500ms |
| `test_yara_compile` | YARA rule compilation | < 200ms |
| `test_correlation_engine` | Threat correlation (100 findings) | < 100ms |
| `test_report_generation` | HTML report (50 findings) | < 1s |
| `test_database_write` | SQLite scan write | < 50ms |

## Device Benchmarks

| Benchmark | Description | Target |
|-----------|-------------|--------|
| `test_full_scan_typical` | Full scan on typical device | < 30s |
| `test_deep_scan_typical` | Deep scan with YARA | < 60s |
| `test_device_profiling` | 26-section device profile | < 15s |
