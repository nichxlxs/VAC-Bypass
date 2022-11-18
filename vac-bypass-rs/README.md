# vac-bypass-rs

Educational Rust reimplementation of the **original** VAC bypass (Daniel Krupinski style) described in the parent repo. **32-bit only** (old Steam; current Steam is 64-bit). Same design: steamservice patch, LoadLibraryExW interception, then GetProcAddress + GetSystemInfo and failsafe hooks so VAC's page-size check fails. No production or injection testing; this crate only ensures the code compiles and unit tests pass.

## What it does

- **steamservice.dll patch**: Scans for `74 47 6A 01 6A` and patches the first byte to `0xEB` (JE → JMP).
- **LoadLibraryExW hook**: In steamservice's IAT. When any module is loaded, the hook runs the real `LoadLibraryExW`, then hooks that module's IAT for the 7 APIs below so every VAC module gets the chain.
- **GetProcAddress hook**: When the module resolves APIs by name, returns our hook for `GetSystemInfo`, `GetVersionExA`, `GetSystemDirectoryW`, `GetWindowsDirectoryW`, `GetCurrentProcessId`, `GetCurrentThreadId`; otherwise returns the real address.
- **GetSystemInfo hook**: Calls the real `GetSystemInfo`, then sets `dwPageSize = 1337` so VAC's check fails and the scan is aborted.
- **Failsafes**: `GetVersionExA`, `GetSystemDirectoryW`, `GetWindowsDirectoryW` call `ExitProcess(1)` so if the page-size trick fails, Steam exits before a report is sent.
- **GetCurrentProcessId / GetCurrentThreadId**: Return `0` to obscure process/thread identity.

## Build and test

From this directory:

```bash
cargo test
```

**32-bit only**. To build the DLL:

```bash
rustup target add i686-pc-windows-msvc
cargo build --release --target i686-pc-windows-msvc
```

Output: `target/i686-pc-windows-msvc/release/vac_bypass.dll`.

## Tests

- `pattern_find_finds_steam_je`: pattern scan finds the steamservice JE bytes in a buffer.
- `pattern_find_empty_miss`: empty or short buffers return `None`.

No tests load Steam or inject the DLL; they only exercise pattern-scan logic.
