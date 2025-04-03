# 🌊 Neptune Scanner v2.0

A high-performance network port scanner written in C, designed to be fast, efficient, and user-friendly. Inspired by Nmap.

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
  - Service detection and identification
  - Robust error handling
- **Cross-Platform**: Works on both Windows and Unix-like systems

## 📋 Prerequisites

- GCC compiler (MinGW for Windows)
- Make build system
- pthread library
- Git (for cloning)

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/kiwiteaorion/neptune-scanner.git

# Navigate to the project directory
cd neptune-scanner

# Compile the project
make
```

## 🎯 Usage

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

## 📚 Version History

### v2.0 (Current)

- Major performance improvements with parallel scanning
- Added multiple scan types (SYN, Connect, UDP)
- Enhanced command-line interface
- Improved error handling and timeout management

### v1.2

- Added common ports scanning mode
- Improved output format with service detection
- Enhanced user interface
- Better cross-platform compatibility

### v1.1

- Renamed executable to neptunescan
- Added ASCII art banner
- Improved cross-platform compatibility

## 🧪 Testing

The project includes several test targets:

```bash
make test-local    # Test on localhost
make test-web      # Test on web server
make test-range    # Test specific port range
```

## Contributing

Contributions are welcome! Feel free to submit pull requests or open issues.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👤 Author

- **kiwiteaorion**

## 🙏 Acknowledgments

- Thanks to all contributors and users of Neptune Scanner
- Inspired by tools like Nmap and other network scanning utilities
