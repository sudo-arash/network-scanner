# Network Scanner

A Python-based network scanner that uses ARP requests to discover active clients on a local network. This tool includes features for device name and operating system detection, with options to export results to CSV or JSON files and support for IPv6 addresses.

## Features
- **Customizable Network Range**: Scan a specific IP range or use the local IP to derive the default range.
- **Concurrency**: Utilizes Python's `ThreadPoolExecutor` for fast scanning with customizable thread count.
- **Timeout Control**: Adjustable ARP request timeout to balance speed and accuracy.
- **Export Results**: Save scan results to CSV or JSON files.
- **Device Name Detection**: Retrieve device names using reverse DNS lookup.
- **Operating System Detection**: Basic OS fingerprinting based on TCP/IP stack analysis.
- **IPv6 Support**: Placeholder for future IPv6 scanning functionality.
- **Colorful Output**: Clear, colorful output using the `colorama` library for easier result interpretation.
- **Modular Design**: Core functionalities split into multiple files for maintainability and scalability.

## Requirements
- Python 3.x
- `scapy` library
- `colorama` library

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/sudo-arash/network-scanner.git
    cd network-scanner
    ```

2. Install required dependencies:
    ```bash
    pip install scapy colorama
    ```

## Usage

Run the `network_scanner.py` with the following customizable options:

```bash
python network_scanner.py [--timeout TIMEOUT] [--threads THREADS] [--range RANGE] [--export FILE]
```

### Arguments:
- `--timeout`: (Optional) Set the timeout for ARP requests (in seconds). Default is `1`.
- `--threads`: (Optional) Number of threads to use for concurrent scanning. Default is `100`.
- `--range`: (Optional) Specify a custom IP range to scan (e.g., `192.168.1.0/24`). If not provided, the script uses the local network IP range.
- `--export`: (Optional) Export results to a file in CSV or JSON format (e.g., `results.csv` or `results.json`).

### Examples:

1. **Scan the default network range (based on local IP) with default settings**:
    ```bash
    python network_scanner.py
    ```

2. **Scan a custom IP range with a 2-second timeout and 50 threads**:
    ```bash
    python network_scanner.py --range 192.168.1.0/24 --timeout 2 --threads 50
    ```

3. **Export results to a CSV file**:
    ```bash
    python network_scanner.py --export results.csv
    ```

## Project Structure

```
network-scanner/
├── network_scanner.py    # Main script with network scanning functionality
├── utils.py              # Utility functions for network scanning
├── README.md             # Project documentation
```

## Future Enhancements

- Implement full IPv6 scanning functionality.
- Advanced network analysis features.
- GUI for easier configuration and result viewing.

## License

This project is licensed under the MIT License.