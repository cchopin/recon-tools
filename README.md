# Recon Tool

An automated reconnaissance tool for CTF that chains nmap and gobuster phases without blocking your console.

## Installation

### Quick installation from releases

```bash
# Linux AMD64
wget https://github.com/cchopin/recon-tools/releases/latest/download/recon-tool-linux-amd64
chmod +x recon-tool-linux-amd64
sudo mv recon-tool-linux-amd64 /usr/local/bin/recon-tool

# macOS AMD64
curl -L -o recon-tool-darwin-amd64 https://github.com/cchopin/recon-tools/releases/latest/download/recon-tool-darwin-amd64
chmod +x recon-tool-darwin-amd64
sudo mv recon-tool-darwin-amd64 /usr/local/bin/recon-tool

# macOS ARM64 (M1/M2)
curl -L -o recon-tool-darwin-arm64 https://github.com/cchopin/recon-tools/releases/latest/download/recon-tool-darwin-arm64
chmod +x recon-tool-darwin-arm64
sudo mv recon-tool-darwin-arm64 /usr/local/bin/recon-tool

# Windows
# Download from: https://github.com/cchopin/recon-tools/releases/latest/download/recon-tool-windows-amd64.exe
```

### Compilation from source

```bash
git clone https://github.com/cchopin/recon-tools.git
cd recon-tools
make build
sudo make install
```

## Usage

```bash
# Basic usage
recon-tool 10.10.10.1

# With custom wordlist
recon-tool example.com /path/to/wordlist.txt
```

## Features

The tool automatically executes the following phases **in parallel**:

1. **Initial scan**: `nmap <target>` - Quick scan of common ports
2. **Detailed scan**: `nmap -A -p <found_ports> <target>`
3. **Full scan**: `nmap -p- <target>` - Scan all ports
4. **Gobuster**: If web services are detected (ports 80, 443, 8080, 8443, 8008, 8010)
5. **Final scan**: `nmap -A -p <all_ports> <target>` if new ports are found

## Advantages

- ✅ **Non-blocking**: Scans run in background
- ✅ **Parallelization**: Multiple simultaneous scans
- ✅ **Detailed logging**: All results are saved
- ✅ **Multi-format**: Text and XML output
- ✅ **Cross-platform**: Linux, macOS, Windows
- ✅ **Single binary**: No dependencies

## Prerequisites

- `nmap` installed
- `gobuster` installed (for web scans)

## Example output

```
[15:30:15] Reconnaissance started for 10.10.10.1
[15:30:15] Results in: recon_10.10.10.1_20231027_153015
[15:30:15] Phase 1: Initial scan of common ports
[15:30:25] Completed: Initial scan
[15:30:25] Open ports found: 22, 80, 443
[15:30:25] Phase 2: Detailed scan of found ports
[15:30:25] Starting: Full port scan -p-
[15:30:25] Web services detected, starting gobuster
[15:30:25] Starting: Gobuster on http://10.10.10.1
[15:30:25] Starting: Gobuster on https://10.10.10.1
[15:32:18] Completed: Detailed scan of ports 22,80,443
[15:35:42] Completed: Gobuster on http://10.10.10.1
[15:36:12] Completed: Gobuster on https://10.10.10.1
[15:42:33] Completed: Full port scan -p-
[15:42:34] 🎯 Reconnaissance completed!
[15:42:34] 📁 Results in: recon_10.10.10.1_20231027_153015
```

## Generated files

- `01_initial_scan.txt` - Initial scan
- `02_detailed_scan.txt` - Detailed scan of first ports
- `03_full_scan.txt` - Full scan of all ports
- `04_final_detailed_scan.txt` - Final scan if new ports found
- `gobuster_*.txt` - Gobuster results for each web service
- `*.xml` - XML versions of nmap scans
- `recon.log` - Complete session log

## Development

```bash
# Compile for all platforms
make release

# Clean
make clean

# Install locally
make install
```

## Error handling

- If wordlist is not found, gobuster is skipped with a warning
- Gobuster errors don't stop the entire reconnaissance process
- All errors are logged for debugging
- Timeout added to gobuster to prevent hanging