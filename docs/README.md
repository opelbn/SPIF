# SPIF - Simplified Procedural Inference Framework

Welcome to SPIF, a cross-platform toolkit for analyzing raw packet captures (`.pcap`) and structured logs (Zeek, GCP, NetFlow)—to extract features for security research, incident analysis, or machine learning. Whether you’re debugging traffic, hunting anomalies, or training models, SPIF streamlines the process with modular, high-performance tools (eventually).

## Why SPIF?
- **Versatile**: Handles packets and logs with custom filters and labeling.
- **Scalable**: Parallel processing for large datasets.
- **End-to-End**: From raw data to ML-ready features (experimental pipeline in progress).
- **Open Source**: Built with C++ and Python, tested on Windows and Linux.

## Components

### Stable Tools
- **[TEX (Traffic EXtractor)]([https://github.com/opelbn/SPIF/wiki/pcap_extractor](https://github.com/opelbn/SPIF/wiki/TEX-(Traffic-EXtractor)-Documentation))**: Extracts packet-level features (e.g., size, IP, payload) from `.pcap` files into CSV. Supports live capture and suspicion labeling.
- **[LEX (Log EXtractor)]([https://github.com/opelbn/SPIF/wiki/log_slicer](https://github.com/opelbn/SPIF/wiki/LEX-(Log-EXtractor)-Documentation))**: Processes Zeek (`.log`), GCP (`.jsonl`), and NetFlow (`.csv`) logs, extracting fields and labeling suspicious entries.

### Experimental (Work in Progress)
- **Preprocessors**: Convert CSV features to NumPy `.npy` files for ML (e.g., `zeek_preprocessor`).
- **Trainers**: Build models (e.g., XGBoost) from preprocessed data (e.g., `Train_XGB.py`).

## Getting Started

1. **Clone the Repo**:
   ```bash
   git clone https://github.com/opelbn/SPIF.git
   cd SPIF
   ```
2. **Build**: See [Installation](#installation) or detailed docs:
   - [TEX]([https://github.com/opelbn/SPIF/wiki/TEX-(Traffic-EXtractor)-Documentation])
   - [LEX]([https://github.com/opelbn/SPIF/wiki/LEX-(Log-EXtractor)-Documentation])
3. **Run**:
   - Extract packet features: `pcap_extractor --in data.pcap --out features.csv --features packetsize,srcip`
   - Process Zeek logs: `log_slicer -i logs/zeek -o zeek.csv --ts --label`

## Installation

### Prerequisites
- **Windows**: Npcap, MSVC, CMake.
- **Linux**: libpcap-dev, GCC/Clang, CMake.
- **Optional**: Python 3.x for experimental components.

### Quick Build
```bash
mkdir build
cd build
cmake ..
cmake --build . --config Release
```
Binaries land in `build/Release` (Windows) or `build/` (Linux). See wiki for tool-specific builds.

## Project Structure
- `src/extractors/`: `pcap_extractor.cpp`, `log_slicer.cpp` (formerly `zeek_extractor`).
- `src/preprocessors/`: Experimental CSV-to-NumPy tools.
- `src/trainers/`: Experimental model training scripts.
- `data/`: Sample datasets and features.
- `models/`: Trained models (e.g., `xgboost_zeek_IoT_model_cuda.json`).
- `lib/Npcap-SDK/`: Npcap SDK for Windows.

## Roadmap
- Stabilize preprocessors and trainers for a full ML pipeline.
- Add log tailing to LogSlicer.
- Add configurable and/or logic to suspicion profiles
- Support live capture enhancements in pcap_extractor.
- Improve cross-platform consistency.

## Contributing
Got ideas? Open an [issue](https://github.com/opelbn/SPIF/issues) or submit a PR to enhance tools, fix bugs, or refine docs.

## License
[Apache License 2.0](LICENSE)

---

Questions? Check the [wiki](https://github.com/opelbn/SPIF/wiki) or ping me at [benjamin.n.opel@gmail.com].
