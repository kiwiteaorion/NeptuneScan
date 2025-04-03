# Neptune Scanner v2.0

A high-performance network port scanner written in C, inspired by Nmap.

## Features

- **Blazing Fast Scanning**: Utilizes parallel scanning with multiple threads for maximum performance
- **Multiple Scan Types**:
  - TCP SYN scan (stealth)
  - TCP Connect scan
  - UDP scan
- **Flexible Port Selection**:
  - Scan specific port ranges
  - Scan common ports
  - Custom port selection
- **Advanced Features**:
  - Non-blocking socket connections
  - Configurable timeouts
  - Verbose output mode
- **Cross-Platform**: Works on both Windows and Unix-like systems

## Installation

### Prerequisites

- GCC compiler
- Make
- pthread library

### Building from Source

```bash
git clone https://github.com/yourusername/neptune-scanner.git
cd neptune-scanner
make
```

## Usage

Basic usage:

```bash
./neptunescan example.com
```

Scan specific port range:

```bash
./neptunescan -p 1-1024 example.com
```

Stealth scan with verbose output:

```bash
./neptunescan -sS -v example.com
```

### Command Line Options

- `-p <port range>`: Specify port range to scan (e.g., 1-1024)
- `-sS`: TCP SYN scan (stealth)
- `-sT`: TCP Connect scan
- `-sU`: UDP scan
- `-c`: Scan common ports only
- `-v`: Verbose output
- `-t <timeout>`: Set timeout in milliseconds
- `-V`: Show version information
- `-h`: Show help message

## Performance

Neptune Scanner v2.0 introduces significant performance improvements:

- Parallel scanning with multiple threads
- Non-blocking socket connections
- Optimized connection handling
- Reduced scan times by up to 90% compared to v1.x

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Inspired by Nmap
- Created by kiwiteaorion
