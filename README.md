# SPIF - Scalable Packet Inspection Framework

SPIF is a cross-platform toolkit for processing network data—both raw packet captures (`.pcap`) and Zeek connection logs (`.log.labeled`)—to extract features for analysis or machine learning. Built with Npcap/libpcap (for packets) and C++ (for logs), it supports custom filters and includes a pipeline for preprocessing and training models (e.g., XGBoost), with a focus on IoT and traffic analysis.

## Features
* **Packet Extraction**: Parse `.pcap` files for low-level features like packet size, TCP flags, and payloads (`pcap_extractor`).
* **Log Extraction**: Process Zeek `.log.labeled` files for connection-level features and malicious/benign labels (`zeek_extractor`).
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
* **Zeek Logs**: No Zeek install needed, just `.log.labeled` files for `zeek_extractor`.

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

## Usage

### `pcap_extractor`
Extracts features from `.pcap` files to CSV.

#### Syntax
```
pcap_extractor --in <input> --out <output.csv> [options]
```

#### Options
* `--in <path>`: Input `.pcap` file or directory (required).
* `--out <file>`: Output CSV file (required).
* `-<features>`: Comma-separated features (e.g., `-packetsize,srcip,dstip`).
* `--bpf <name>=<filter>`: Custom BPF filter (e.g., `--bpf myfilter="tcp port 80"`).
* `--verbose`: Enable detailed logging.

#### Example
```
pcap_extractor --in data/raw/capture.pcap --out features.csv -packetsize,protocol --bpf synflag="tcp[tcpflags] & tcp-syn != 0" --verbose
```

### `zeek_extractor`
Extracts features from Zeek `.log` files to CSV, with parallel processing.

#### Syntax
```
zeek_extractor -i <input_dir> -o <output_dir_or_file> [options]
```

#### Options
* `-i <dir>`: Input directory with `.log` files (required).
* `-o <path>`: Output directory or CSV file (required).
* `--<feature>`: Select features (e.g., `--ts`, `--proto`); defaults to `protocol,service,duration,orig_bytes,resp_bytes`.
* `--profile`: List available fields and exit.
* `--label`: Include malicious/benign label (1/0). NOTE: this requires that your data have a defined field of "label" containing a string (Benign/Malicious)

#### Example
```
zeek_extractor -i data/raw -o features/ --ts --id.orig_h --service --label
```

### `zeek_preprocessor`
Converts CSV features to NumPy `.npy` chunks for ML.

#### Syntax
```
zeek_preprocessor <input_dir>
```

#### Description
Processes CSV files from `zeek_extractor`, encoding protocol and service, and saving features (X) and labels (y) as `.npy` chunks. Use `combine_chunks.py` to merge into final `X.npy` and `y.npy`.

#### Example
```
zeek_preprocessor features/
```

## Project Structure
* **`src/extractors/`**: `pcap_extractor.cpp` (packets), `zeek_extractor.cpp` (logs).
* **`src/preprocessors/`**: `zeek_preprocessor.cpp` (CSV to `.npy`), `combine_chunks.py`.
* **`src/trainers/`**: Model training (e.g., `Train_XGB.py`).
* **`data/`**: Datasets, features, and raw files (`.pcap`, `.log.labeled`).
* **`models/`**: Trained XGBoost models (e.g., `xgboost_zeek_IoT_model_cuda.json`).
* **`lib/Npcap-SDK/`**: Npcap SDK for Windows packet capture.
* **`tests/`**: Validation scripts (e.g., `model_test.py`).

## Contributing
Submit issues or PRs to enhance functionality, add features, or improve documentation.

## License
[Apache License 2.0](LICENSE)