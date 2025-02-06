# Host scanner

This script scans a given IP address or network, retrieves information about active devices, and optionally detects their operating systems. The results are saved in a CSV file.

## Features
- Scan a single IP or an entire network range
- Skip specific IP addresses
- Detect active hosts via ping
- Retrieve hostname and MAC address
- (Optional) Identify the Windows operating system
- Save results to a CSV file

## Table of Contents

- [Installation](#installation)
- [Requirements](#requirements)
- [Usage](#usage)
- [License](#license)
- [Contact](#contact)

## Installation

1. Clone or download this repository.
2. Open **Command Prompt (cmd) as Administrator**.
3. Install required dependencies if needed:
   ```sh
   pip install argparse
   ```

## Requirements

This script is designed **only for Windows** and requires:
- Python 3.x
- Administrator privileges (to access the ARP table and retrieve OS details)

## Usage

Run the script with the following arguments:

Scan a single IP:
```sh
python scanner.py -i 192.168.1.53
```

Scan an entire network:
```sh
python scanner.py -i 192.168.1.0/24
```

Skip specific IPs during scanning:
```sh
python scanner.py -i 192.168.1.0/24 -s 192.168.1.34 
```

Scan and detect Windows OS:
```sh
python scanner.py -i 192.168.1.0/24 -o
```
## License

Include the project's license information. For example: This project is licensed under the [Creative Commons NonCommercial License (CC BY-NC)](https://creativecommons.org/licenses/by-nc/4.0/deed.en).

## Contact

Contact me: jakub1.gniadek@gmail.com
