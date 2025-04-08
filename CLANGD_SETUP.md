# Setting up clangd for Neptune Scanner in Cursor

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
