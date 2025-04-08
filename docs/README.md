# 🌊 Neptune Scanner v3.0.0 🌊

A powerful and efficient network port scanner written in C, inspired by Nmap.

## 🚀 Features

- 🎯 Multiple scanning techniques:
  - TCP Connect Scan
  - SYN Scan
  - FIN Scan
  - XMAS Scan
  - NULL Scan
  - ACK Scan
  - Window Scan
  - Maimon Scan
- ⚡ High-performance parallel scanning
- 🎨 Beautiful ASCII art banners
- 🖥️ Cross-platform support (Windows & Linux)
- 📊 Service detection and version scanning
- 🎭 OS detection capabilities
- 🎮 Interactive command-line interface
- 📝 Detailed scan reports

## 🛠️ Installation

### Windows

```bash
git clone https://github.com/kiwiteaorion/neptunescan.git
cd neptunescan
make
```

### Linux

```bash
git clone https://github.com/kiwiteaorion/neptunescan.git
cd neptunescan
make
```

## 📋 Usage

Basic usage:

```bash
neptunescan [options] <target> [port-range]
```

Examples:

```bash
# Scan common ports
neptunescan example.com

# Scan specific port range
neptunescan example.com 20-80

# Perform SYN scan
neptunescan -sS example.com

# Service version detection
neptunescan -sV example.com

# OS detection
neptunescan -O example.com
```

## 🎨 Banners

Neptune Scanner includes several ASCII art banners that are randomly displayed:

```
    _   __      __  __  ___  ____  ____  ____  ____  ____  ____
   / | / /___  / /_/ / / _ \/ __ \/ __ \/ __ \/ __ \/ __ \/ __ \
  /  |/ / __ \/ __/ / /  __/ /_/ / /_/ / /_/ / /_/ / /_/ / /_/ /
 / /|  / /_/ / /_/ / /\___/\____/\____/\____/\____/\____/\____/
/_/ |_/\____/\__/_/ /
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📞 Support

For support, please open an issue in the GitHub repository.

## 🎉 Acknowledgments

- Inspired by Nmap
- ASCII art generated using patorjk.com
