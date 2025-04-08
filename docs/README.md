# SPIF - Scalable Packet Inspection Framework

SPIF is a cross-platform toolkit for processing network data—both raw packet captures (`.pcap`) and Zeek connection logs (`.log`)—to extract features for analysis or machine learning. Built with Npcap/libpcap (for packets) and C++ (for logs), it supports custom filters and includes a pipeline for preprocessing and training models (e.g., XGBoost), with a focus on IoT and traffic analysis.

## Features
* **Packet Extraction**: Parse `.pcap` files for low-level features like packet size, TCP flags, and payloads (`pcap_extractor`).
* **Log Extraction**: Process Zeek `.log` files for connection-level features and malicious/benign labels (`zeek_extractor`).
* **Preprocessing**: Convert CSV features to NumPy `.npy` files for ML (`zeek_preprocessor`).
* **Custom Filters**: Apply BPF filters (packets) or select log fields dynamically.
* **Flexible Output**: Outputs to CSV or `.npy` with configurable features and stats.
* **Pipeline Integration**: Extractors, preprocessors, and trainers for end-to-end workflows.
* **Cross-Platform**: Runs on Windows (Npcap) and Linux (libpcap), tested on Ubuntu 24.04.

## Installation

### Prerequisites
* **Windows**: Windows 10/11, [Npcap](https://npcap.com/#download) (SDK in `lib/Npcap-SDK`), Winsock2.
* **Linux**: Ubuntu 24.04 (or similar), `libpcap-dev` (`sudo apt install libpcap-dev`), `zlib1g-dev` (`sudo apt install zlib1g-dev`), POSIX sockets.
* **CMake**: For building the project.
* **C++ Compiler**: MSVC (Windows) or GCC/Clang (Linux).
* **Python**: For preprocessing and training scripts (optional, see `scripts` and `trainers`).
* **Zeek Logs**: No Zeek install needed, just `.log` files for `zeek_extractor`.

### Build Steps
1. Clone the repo:
   ```
   git clone https://github.com/opelbn/SPIF.git
   cd SPIF
   ```
2. Configure with CMake:
   * **Windows**:
     ```
     mkdir build
     cd build
     cmake .. -A x64
     ```
   * **Linux**:
     ```
     mkdir build
     cd build
     cmake ..
     ```
   #### Build Individual Tools
   Build only what you need by targeting subdirectories:
   * **Extractors**:
   ```
   cd src/extractors
   mkdir build
   cd build
   cmake ..
   ```
   * **Preprocessors**:
   ```
   cd src/preprocessors
   mkdir build
   cd build
   cmake .. 
   ```
3. Build:
   ```
   cmake --build . --config Release
   ```
4. Binaries will be in `build/Release` (Windows) or `build/` (Linux), e.g., `src/extractors/pcap_extractor`, `src/extractors/zeek_extractor`, `src/preprocessors/zeek_preprocessor`.

### Platform Notes
* **Windows**: Requires Npcap DLLs (`Packet.dll`, `wpcap.dll`) from `src/extractors/static` or installed system-wide.
* **Linux**: Uses system libpcap and zlib; ensure dependencies are installed.

# LogSlicer Documentation

## Overview
LogSlicer is a C++ command-line tool built by moi for processing and analyzing log files from Zeek, GCP, and NetFlow sources. It extracts specified fields, applies suspicion labeling based on customizable profiles, and supports parallel processing of multiple files. Aggregation options are available for NetFlow logs.

## Features
- **Supported Log Types**: Zeek (`.labeled`), GCP (`.jsonl`), NetFlow (`.csv`).
- **Field Profiling**: Lists available fields from input logs.
- **Field Extraction**: Extracts user-specified fields into CSV output.
- **Suspicion Labeling**: Labels entries as malicious/suspicious based on a profile (default or custom JSON).
- **Parallel Processing**: Processes multiple files concurrently using `std::async`.
- **Aggregation (NetFlow)**: Aggregates stats by pair, source, or port within each file.

## Usage
```
log_slicer.exe [options]
```

### Options
- `-i, --input <dir>`: Input directory or file (required).
- `-o, --output <path>`: Output directory or CSV file (required unless `-p`).
- `-t, --log-type <type>`: Log type (`zeek`, `gcp`, `netflow`; default: `zeek`).
- `-a, --agg-type <type>`: Aggregation type for NetFlow (`pair`, `source`, `port`; default: `pair`).
- `-f, --profile-file <file>`: Suspicion profile JSON file (optional).
- `-p, --profile`: Profile fields only, no processing.
- `-h, --help`: Display help message.
- `--<field>`: Extract specific field (e.g., `--ts`, `--duration`; case-sensitive).

### Examples
- Profile Zeek fields:
  ```
  log_slicer.exe -i test_zeek -t zeek -p
  ```
- Process Zeek logs with custom profile:
  ```
  log_slicer.exe -i test_zeek -t zeek -o test_output\zeek.csv -f profile.json --ts --duration --label
  ```
- Process NetFlow with per-port aggregation:
  ```
  log_slicer.exe -i test_netflow -t netflow -o test_output -a port --doctets --dstport
  ```

## Suspicion Profile
A JSON file can override default suspicion criteria. Example (`profile.json`):
```json
{
    "zeek": {
        "malicious_labels": ["malicious", "attack"],
        "duration_threshold": 4.0
    },
    "gcp": {
        "suspicious_methods": ["google.iam.admin.v1.CreateServiceAccount"],
        "non_org_domains": ["@external.com"],
        "bytes_threshold": 1000000
    },
    "netflow": {
        "bytes_threshold": 10000000,
        "packets_threshold": 5000,
        "port_count_threshold": 5,
        "suspicious_ports": [80],
        "rules": [{"field": "doctets", "op": ">", "value": 10000000}]
    }
}
```
- **Zeek**: Labels as `1` if `label` matches `malicious_labels` or `duration > duration_threshold`.
- **GCP**: Labels as `1` if method in `suspicious_methods`, email in `non_org_domains`, or `requestSize > bytes_threshold`.
- **NetFlow**: Labels as `1` if `total_bytes > bytes_threshold`, `total_packets > packets_threshold`, `dst_ports.size() > port_count_threshold`, `dstport` in `suspicious_ports`, or a rule matches.

## Test Suite
### Command-Line Parsing
- `--help`: Displays usage.
- `-o test.csv`: Errors without `-i`.
- `-i test_zeek -t invalid -o out.csv`: Defaults to `zeek`.

### Profiling
- `-i test_zeek -t zeek -p`: Lists `ts, uid, id.orig_h, ...`.
- `-i test_gcp -t gcp -p`: Lists `timestamp, protoPayload.methodName, ...`.
- `-i test_netflow -t netflow -p`: Lists `srcaddr, dstaddr, ...`.

### Processing
- **Zeek**: `-i test_zeek -t zeek -o zeek.csv --ts --duration --label`
  - Output: `ts,duration,label\n1.0,5.0,1\n2.0,2.0,0`
- **GCP**: `-i test_gcp -t gcp -o gcp.csv --protoPayload.methodName --authenticationInfo.principalEmail`
  - Output: `protoPayload.methodName,authenticationInfo.principalEmail,label\n...`
- **NetFlow**: `-i test_netflow -t netflow -o netflow.csv --srcaddr --dstaddr --doctets`
  - Output: `srcaddr,dstaddr,doctets,label\n...`

### Suspicion Profile
- **Zeek**: `-i test_zeek -t zeek -o zeek_profile.csv -f profile.json --ts --duration --label`
  - `5.0 > 4.0` or `malicious` → `1`.
- **GCP**: `-i test_gcp -t gcp -o gcp_profile.csv -f profile.json --protoPayload.requestSize`
  - `2000000 > 1000000` → `1`.
- **NetFlow**: `-i test_netflow -t netflow -o netflow_profile.csv -f profile.json --doctets --dstport`
  - `15000000 > 10000000` → `1`.

### Parallel Processing
- **Zeek**: `-i test_zeek -t zeek -o test_output -f profile.json --ts --duration --label`
  - Processes `conn.log`, `conn2.log` in parallel.

### Aggregation Types (NetFlow)
- **PerPair**: `-i test_netflow -t netflow -o test_output -a pair -f profile.json --doctets --dstport`
  - Aggregates by `srcaddr_dstaddr`.
- **PerSource**: `-a source`
  - Aggregates by `srcaddr`.
- **PerPort**: `-a port`
  - Aggregates by `dstport`.

## Notes
- **Output**: CSVs are written per input file (e.g., `test_output\<parent>_<stem>_features.csv`) unless a single CSV is specified.
- **Threading**: Console output is synchronized with a mutex for readability.
- **Aggregation**: Currently per-file; global aggregation requires code modification.

## Build Instructions
```
g++ -std=c++17 -I. main.cpp logslice.cpp -o log_slicer -pthread
```
Requires `cxxopts.hpp` and `nlohmann/json.hpp`.

## Project Structure
* **`src/extractors/`**: `pcap_extractor.cpp` (packets), `zeek_extractor.cpp` (logs).
* **`src/preprocessors/`**: `zeek_preprocessor.cpp` (CSV to `.npy`), `combine_chunks.py`.
* **`src/trainers/`**: Model training (e.g., `Train_XGB.py`).
* **`data/`**: Datasets, features, and raw files (`.pcap`, `.log`).
* **`models/`**: Trained XGBoost models (e.g., `xgboost_zeek_IoT_model_cuda.json`).
* **`lib/Npcap-SDK/`**: Npcap SDK for Windows packet capture.
* **`tests/`**: Validation scripts (e.g., `model_test.py`).

## TODO
* Add option to not label or apply suspicion criteria (just extract)
* Add generic output stream options for all extractors (send the data elsewhere, not write to a file)
* Add log tailing for zeek_extractor
* Add live capture for pcap_extractor
* Un-screw cross-platform pcap_extractor

## Contributing
Submit issues or PRs to enhance functionality, add features, or improve documentation.

## License
[Apache License 2.0](LICENSE)