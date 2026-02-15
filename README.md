# Process-Hollow

A C++ library implementing the Process Hollowing technique for Windows process injection. This library can be integrated into your CMake projects to enable PE image replacement functionality.

## Overview

Process Hollowing (also known as RunPE) is a code injection technique where a legitimate process is created in a suspended state, its memory is unmapped, and replaced with a malicious executable. This library provides a clean, reusable implementation that can be integrated into your projects via CMake's FetchContent.

## Features

- **Easy Integration**: Simple CMake-based integration using FetchContent
- **Cross-Architecture Support**: Works with both x86 and x64 processes
- **PE Image Manipulation**: Complete PE image loading and relocation
- **Windows API Wrappers**: Clean abstractions over Windows process manipulation APIs

## Requirements

- CMake 3.14 or higher
- C++17 or later
- Windows operating system
- MSVC, MinGW, or compatible C++ compiler

## Installation

### Using CMake FetchContent

Add the following to your `CMakeLists.txt`:

```cmake
cmake_minimum_required(VERSION 3.14)
project(YourProject)

include(FetchContent)

# Fetch the Process-Hollow library
FetchContent_Declare(
    ProcessHollowing
    GIT_REPOSITORY https://github.com/TechMecca/Process-Hollow.git
    GIT_TAG        1.2
)

FetchContent_MakeAvailable(ProcessHollowing)

# Link against the library
add_executable(YourExecutable main.cpp)
target_link_libraries(YourExecutable PRIVATE ProcessHollowing::ProcessHollowing)
```

### Manual Installation

Alternatively, you can clone the repository and add it as a subdirectory:

```bash
git clone https://github.com/TechMecca/Process-Hollow.git
```

```cmake
add_subdirectory(Process-Hollow)
target_link_libraries(YourExecutable PRIVATE ProcessHollowing::ProcessHollowing)
```

## Usage

### Basic Example - Using File Paths

```cpp
#include <ProcessHollowing/ProcessHollowing.h>

int main() {
    // Hollow notepad++.exe and inject chrome.exe into it
    Process::Hollow(
        (LPSTR)"C:\\Program Files\\Notepad++\\notepad++.exe",  // Target process
        (LPSTR)"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"  // Source payload
    );
    
    return 0;
}
```

### Advanced Example - Using Byte Array

```cpp
#include <ProcessHollowing/ProcessHollowing.h>
#include <vector>
#include <fstream>

int main() {
    // Read payload from file into byte array
    std::ifstream file("payload.exe", std::ios::binary | std::ios::ate);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<char> buffer(size);
    if (file.read(buffer.data(), size)) {
        // Hollow process using byte array
        Process::Hollow(
            (LPSTR)"C:\\Windows\\System32\\svchost.exe",  // Target process
            buffer.data()                                 // Payload as bytes
        );
    }
    
    return 0;
}
```

### Parameters

- **Target Process**: Path to the legitimate executable that will be hollowed (first parameter)
- **Payload**: Either a file path to the executable to inject OR raw bytes of the PE image
- **Size** (for byte arrays): The size of the payload in bytes

## Installation Output

To install the built executables to a specific directory:

```cmake
# Set installation prefix
set(CMAKE_INSTALL_PREFIX "${CMAKE_BINARY_DIR}/install" CACHE PATH "" FORCE)

# Install targets
install(TARGETS Loader
        RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/$<CONFIG>
)
```

This will install the `Loader` executable to:
- `build/install/Debug/` for Debug builds
- `build/install/Release/` for Release builds

## Building

```bash
# Configure
cmake -B build -S .

# Build
cmake --build build --config Release

# Install (optional)
cmake --install build --config Release
```

## How Process Hollowing Works

1. **Create Target Process**: A legitimate process (e.g., `svchost.exe`) is created in a suspended state
2. **Unmap Original Image**: The original executable image is unmapped from the process memory
3. **Allocate Memory**: Memory is allocated in the target process for the new image
4. **Write New Image**: The replacement PE image is written to the allocated memory
5. **Fix Relocations**: If necessary, the image is rebased to match the target address space
6. **Update Entry Point**: The thread context is updated to point to the new entry point
7. **Resume Process**: The process is resumed, executing the injected code

## Security Considerations

⚠️ **Important**: This library implements techniques commonly associated with malware. Use responsibly and only for:

- Security research
- Penetration testing (with proper authorization)
- Red team exercises
- Educational purposes
- Legitimate software protection

**Do not use this library for malicious purposes.** Misuse may violate laws including:
- Computer Fraud and Abuse Act (CFAA)
- Digital Millennium Copyright Act (DMCA)
- Local and international cybercrime laws

## Detection and Prevention

Modern security solutions can detect process hollowing through:
- Memory scanning for mismatched PE headers
- Monitoring of suspicious API call sequences
- Behavioral analysis of process creation patterns
- Checking for discrepancies between disk and memory images

## Version History

- **1.2** (Latest): Removed unused variables, code cleanup
- **1.1**: Bug fixes and improvements
- **1.0**: Initial release

## Credits

This library is based on the original implementation by [adamhlt](https://github.com/adamhlt):
- [adamhlt/Process-Hollowing](https://github.com/adamhlt/Process-Hollowing)

Special thanks to adamhlt for providing the foundational code that made this library possible.

## License

Please refer to the repository's LICENSE file for licensing information.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## Disclaimer

This software is provided for educational and research purposes only. The authors and contributors are not responsible for any misuse or damage caused by this software. Users are responsible for ensuring their use complies with all applicable laws and regulations.

## Resources

For more information on process hollowing:

- [MITRE ATT&CK - Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [Windows Internals Documentation](https://docs.microsoft.com/en-us/windows/)
- [PE Format Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)

## Support

For issues, questions, or contributions, please visit the [GitHub repository](https://github.com/TechMecca/Process-Hollow).

---

**Made by TechMecca** | [GitHub](https://github.com/TechMecca)
