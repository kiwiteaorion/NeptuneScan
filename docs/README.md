# 🌐 Cross-Platform Port Scanner

A high-performance, cross-platform network port scanner written in C that automatically adapts to Windows, Linux, and macOS environments.

## 🚀 Features

- **Cross-Platform Compatibility**: Seamlessly works on Windows, Linux, and macOS
- **Non-Blocking Operations**: Efficient asynchronous port scanning
- **Customizable Port Ranges**: Scan specific port ranges or use default common ports
- **Error Handling**: Robust error detection and reporting
- **Clean Code**: Well-documented, maintainable code following best practices

## 🛠️ Installation

### Prerequisites

- GCC compiler or equivalent (MinGW for Windows)
- Make build system
- Git for version control

### Building from Source

1. Clone the repository
   git clone https://github.com/kiwiteaorion/port-scanner.git
   cd port-scanner

2. Build the project

```bash
make
```

## 📚 Usage

Basic usage:

```bash
./port_scanner <target_host> [start_port] [end_port]
```

Examples:

```bash
# Scan localhost ports 80-100
./port_scanner localhost 80 100

# Scan specific host with default port range
./port_scanner www.example.com

# Scan custom port range
./port_scanner 192.168.1.1 20 25
```

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

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**kiwiteaorion**

- GitHub: [@kiwiteaorion](https://github.com/kiwiteaorion)

## 🌟 Acknowledgments

- Thanks to all contributors who help improve this project
- Inspired by classic network security tools (mostly nmap)
