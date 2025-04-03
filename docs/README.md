# 🌊 Neptune Port Scanner

A high-performance network port scanner written in C, designed to be fast, efficient, and user-friendly.

## 🚀 Features

- Fast TCP port scanning
- Common ports scanning mode
- Service detection and identification
- Cross-platform compatibility (Windows, Linux, macOS)
- Clean and informative output format
- Customizable port ranges
- Non-blocking operations for efficient scanning
- Robust error handling

## 📋 Prerequisites

- GCC compiler (MinGW for Windows)
- Make build system
- Git (for cloning)

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/kiwiteaorion/port-scanner.git

# Navigate to the project directory
cd port-scanner

# Compile the project
make
```

## 🎯 Usage

```bash
# Scan common ports on a target
./neptunescan <target>

# Scan a specific port range
./neptunescan <target> <start_port> <end_port>

# Examples:
./neptunescan localhost              # Scan common ports on localhost
./neptunescan example.com 80 443    # Scan ports 80-443 on example.com
./neptunescan 192.168.1.1 22        # Scan only port 22 on 192.168.1.1
```

## 📚 Versions

### v1.2 (Current)

- Added common ports scanning mode
- Improved output format with service detection
- Enhanced user interface
- Better cross-platform compatibility

### v1.1

- Renamed executable to neptunescan
- Added ASCII art banner
- Improved cross-platform compatibility

To use a specific version:

```bash
# Clone the repository
git clone https://github.com/kiwiteaorion/port-scanner.git

# For version 1.2 (current)
git checkout v1.2

# For version 1.1
git checkout v1.1
```

## 🔍 Output Example

## 🧪 Testing

The project includes several test targets:

```bash
make test-local  # Test localhost
make test-web    # Test web server
make test-range  # Test port range
```

## 📁 Project Structure

```
port-scanner/
├── src/
│   ├── scanner.c
│   ├── utils.c
│   └── config.c
├── include/
│   ├── scanner.h
│   ├── utils.h
│   └── config.h
├── main.c
├── Makefile
└── README.md
```

## 🤝 Contributing

Contributions are welcome! Feel free to submit pull requests or open issues.

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👤 Author

- **kiwiteaorion**

## 🙏 Acknowledgments

- Thanks to all contributors and users of Neptune Port Scanner
- Inspired by tools like Nmap and other network scanning utilities
