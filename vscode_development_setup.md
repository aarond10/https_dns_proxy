# VS Code Development Setup for https_dns_proxy

This document provides setup instructions for developing the https_dns_proxy project in Visual Studio Code with full language support and IntelliSense for this CMake-based C project.

## Platform Support

### Linux (Native)
Development works natively on Linux with all features enabled. Install the required tools on your Linux system and open the project directly in VS Code.

### Windows via Remote SSH
Connect to a remote Linux machine (server, WSL, or VM) from Windows using VS Code's Remote SSH extension:
- Install the "Remote - SSH" extension in VS Code on Windows
- Connect to your Linux development environment
- Open the https_dns_proxy project from the remote machine
- All tools and dependencies run on the Linux machine

### Windows via Remote WSL
Use Windows Subsystem for Linux (WSL) directly from Windows:
- Install WSL 2 on Windows (Ubuntu 24.04 LTS or newer recommended)
- Install the "Remote - WSL" extension in VS Code on Windows
- Open the project in VS Code's WSL environment
- All development happens within the WSL Linux environment

## Prerequisites
- **VS Code** installed (with Remote extensions if using Windows)
- **CMake** installed
- **Clangd** installed (for language support)
- **VS Code Clangd extension** installed

## Setup Steps

1. **Generate compile_commands.json**
   - This file is required by Clangd to understand the compilation flags for each source file.
   - Run the following command in the project root:
     ```
     cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON .
     ```
   - This will create `compile_commands.json` in the project root.

2. **Install Clangd Extension**
   - Open VS Code (locally on Linux, or through Remote - SSH/WSL from Windows)
   - Go to Extensions (Ctrl+Shift+X)
   - Search for "clangd" and install the official Clangd extension by LLVM
   - The extension will automatically work in remote environments

3. **Verify Configuration**
   - Ensure the project is open in VS Code
   - Clangd should automatically detect `compile_commands.json` and provide language features
   - Hover over functions/types to see IntelliSense and go-to-definition

4. **Restart Language Server (if needed)**
   - In VS Code, open Command Palette (Ctrl+Shift+P)
   - Type "Clangd: Restart language server" and select it

## Additional Commands
- **Switch to Clangd**: Use "C/C++: Select Language Server" (Ctrl+Shift+P) and choose Clangd
- **View Clangd Logs**: "Clangd: Show logs" in Command Palette
- **Rebuild IntelliSense**: "Clangd: Reload language server" in Command Palette

## Troubleshooting
- If Clangd doesn't work, ensure `compile_commands.json` exists in the project root
- Check VS Code settings for Clangd configuration (View > Command Palette > "Preferences: Open Settings")
- Set `clangd.path` in settings if Clangd is not in your system PATH
- For remote development, ensure all tools are installed on the target Linux machine/WSL environment
