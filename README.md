# 🌊 Neptune Scanner v4.1.0 🌊

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
- 📝 Flexible port specification:
  - Port ranges (e.g., 80-443)
  - Port lists (e.g., 22,80,443,8080)
  - Common ports scanning
- ⚡ High-performance parallel scanning
- 🎨 Beautiful ASCII art banners
- 🖥️ Cross-platform support (Windows & Linux)
- 📊 Service detection and version scanning
- 🎭 OS detection capabilities
- 🎮 Interactive command-line interface
- 📝 Detailed scan reports
- 🔧 Improved development environment with clangd support

## 🛠️ Installation

### Windows

```bash
git clone https://github.com/kiwiteaorion/neptunescan.git
cd neptunescan
.\build.ps1
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
neptunescan -p 20-80 example.com

# Scan specific ports
neptunescan -p 22,80,443 example.com

# Perform SYN scan
neptunescan -sS example.com

# Service version detection
neptunescan -sV example.com

# OS detection
neptunescan -O example.com
```

## 🛠️ Development

Neptune Scanner now supports clangd for improved code intelligence and development experience. See the [CLANGD_SETUP.md](CLANGD_SETUP.md) for setup instructions.

### Why clangd instead of Microsoft C/C++ Extension

We've chosen clangd over Microsoft's C/C++ extension for several key reasons:

1. **Better cross-platform compatibility**: clangd works consistently across Windows, Linux, and macOS, providing the same experience regardless of your development environment.

2. **More accurate code intelligence**: Being built on the Clang compiler frontend, clangd provides more precise code completion, error detection, and type information.

3. **Performance**: clangd offers significantly faster indexing and response times, especially for large codebases.

4. **Integration with GCC/MinGW**: clangd works seamlessly with the GCC toolchain we use for this project, while Microsoft's extension is primarily optimized for MSVC.

5. **Modern features**: clangd supports newer C/C++ standards and language features with better accuracy.

6. **Standardized interface**: Using the Language Server Protocol (LSP), clangd integrates well with various editors beyond just VS Code.

7. **Consistent diagnostics**: Error messages and warnings match what you'll see during actual compilation.

8. **Active development**: clangd is actively maintained by the LLVM community, ensuring it stays up-to-date with the latest C/C++ developments.

### Building from Source

On Windows, use the PowerShell build script:

```powershell
.\build.ps1
```

On Linux, use make:

```bash
make
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
