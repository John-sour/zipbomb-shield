# ZipBomb Shield 🛡️

A high-performance, cross-platform tool to detect and prevent zipbomb attacks before they can damage your system.

## Features

- **Fast Detection**: Analyzes ZIP structure without extracting entire files
- **Cross-Platform**: Single binary works on Linux, macOS, Windows, and more
- **Multiple Detection Methods**:
  - Compression ratio analysis
  - Nested archive detection
  - Uncompressed size limits
  - File pattern analysis
- **Safe Extraction**: Extract with resource limits and monitoring
- **Detailed Reporting**: Comprehensive analysis results

## What is a Zipbomb?

A zipbomb (also called a zip bomb or decompression bomb) is a malicious compressed archive that contains highly compressed data. When extracted, it expands to enormous sizes, potentially:
- Filling up disk space
- Crashing applications
- Making systems unresponsive
- Consuming excessive memory

Classic example: A 42KB ZIP that expands to 4.5 petabytes (the original "42.zip").

## Installation

```bash
go build -o zipbomb-shield main.go
```

## Usage

### Basic scan
```bash
./zipbomb-shield -file suspicious.zip
```

### Advanced options
```bash
./zipbomb-shield -file suspicious.zip \
  -ratio 100 \
  -max-size 1000000000 \
  -max-depth 3 \
  -sample \
  -v
```

### Options

- `-file` (required): Path to ZIP file to analyze
- `-ratio`: Maximum allowed compression ratio (default: 100.0)
- `-max-size`: Maximum uncompressed size in bytes (default: 1GB)
- `-max-depth`: Maximum archive nesting depth (default: 3)
- `-sample`: Extract and verify first 1MB of each file
- `-v`: Verbose output

## Detection Methods

### 1. Compression Ratio Analysis
Flags files with suspiciously high compression ratios. Normal ZIP files typically compress 2-10:1, while zipbombs can compress 1000:1 or higher.

### 2. Size Limits
Enforces maximum uncompressed size limits to prevent disk exhaustion attacks.

### 3. Nesting Detection
Identifies archives within archives (common zipbomb technique).

### 4. Pattern Analysis
Recognizes common zipbomb patterns like repetitive file structures.

## Exit Codes

- `0`: File is safe
- `1`: Potential zipbomb detected

## Performance

- Analyzes archive headers only (no full extraction)
- Memory efficient: constant memory usage regardless of file size
- Processes large files in milliseconds

## How It Works

1. Opens ZIP file and reads central directory
2. Analyzes compression metadata for each file
3. Calculates compression ratios
4. Detects nesting patterns
5. Applies heuristic threat assessment
6. Returns detailed analysis report

## Safety

ZipBomb Shield never extracts files to disk by default. When using `-sample` mode, only 1MB samples are extracted to temporary memory.

## Contributing

Contributions welcome! Areas for improvement:
- Support for 7z, RAR, TAR formats
- Machine learning-based detection
- Real-time file monitoring
- GUI application

## License

MIT
