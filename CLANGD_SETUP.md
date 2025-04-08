# Setting up clangd for Neptune Scanner in Cursor

## Why We're Using clangd Instead of Microsoft C/C++ Extension

The Microsoft C/C++ extension (ms-vscode.cpptools) is often the default choice for C/C++ development in Visual Studio Code and its derivatives like Cursor. However, we've encountered several limitations with this extension that prompted our switch to clangd:

### Issues with Microsoft C/C++ Extension

1. **Cursor IDE Compatibility**: The Microsoft extension has shown inconsistent behavior in Cursor IDE, often failing to initialize properly (displaying a perpetual "spinning C" icon).

2. **Performance Issues**: The Microsoft extension can be resource-intensive, especially when indexing larger codebases like Neptune Scanner.

3. **MinGW/GCC Support**: While the Microsoft extension does support MinGW/GCC, its primary focus is on MSVC, which can lead to suboptimal behavior with our GCC-based build system.

4. **Configuration Complexity**: Getting the Microsoft extension to correctly recognize all includes and compiler flags has proven challenging in cross-platform development.

### Benefits of clangd

1. **Faster Analysis**: clangd typically processes code more quickly, providing immediate feedback.

2. **Higher Accuracy**: Because clangd is based on the actual Clang compiler frontend, its understanding of the code matches how it will be compiled.

3. **Better Cross-Platform Support**: clangd works consistently across Windows, Linux, and macOS.

4. **More Detailed Diagnostics**: Error messages and warnings are more comprehensive and actionable.

5. **Superior Code Navigation**: Finding references, definitions, and implementing complex refactorings is more reliable.

6. **Standards Compliance**: clangd has excellent support for modern C/C++ standards and features.

By using clangd, we ensure a more consistent, efficient, and accurate development experience across all environments where Neptune Scanner is developed.

## Install LLVM/clangd

1. Download LLVM from the official website: https://github.com/llvm/llvm-project/releases

   - Look for a file like `LLVM-xx.x.x-win64.exe` (the latest version)
   - For example: `LLVM-17.0.6-win64.exe`

2. Run the installer:

   - Make sure to select the option "Add LLVM to the system PATH"
   - Default installation location is fine (usually `C:\Program Files\LLVM`)

3. Verify installation by opening a new PowerShell window and typing:
   ```
   clangd --version
   ```

## Configure Cursor to use clangd

1. Install the clangd extension in Cursor:

   - Open Cursor
   - Go to Extensions (click the extension icon in the sidebar)
   - Search for "clangd"
   - Install the extension named "clangd" by LLVM

2. Configuration files:

   - We've already created the necessary configuration files in your project:
     - `.clangd`: Config for clangd
     - `.clang-tidy`: Code style checks
     - `compile_commands.json`: Compilation database
     - `.vscode/settings.json`: Disables Microsoft C/C++ and enables clangd
     - `.cursor.config.json`: Cursor-specific settings

3. Restart Cursor:
   - Close and reopen Cursor after installing clangd
   - Make sure to open the "Port Scanner" folder in Cursor

## Using the Configured Environment

1. Build with the PowerShell script:

   ```
   .\build.ps1
   ```

2. Verify clangd is working:

   - Open a `.c` file in the project
   - Hover over a function or variable - you should see documentation
   - Check the bottom status bar - it should not show the spinning C icon
   - You might see "clangd" in the status bar indicating it's active

3. If you still see the Microsoft C++ extension:
   - Open the Command Palette (Ctrl+Shift+P)
   - Type "Reload Window" and press Enter

## Troubleshooting

If you still see issues:

1. Make sure clangd is in your PATH
2. Check if the clangd extension is installed in Cursor
3. Verify you've restarted Cursor
4. Try explicitly selecting clangd as the language server:
   - Command Palette → "clangd: Restart language server"
