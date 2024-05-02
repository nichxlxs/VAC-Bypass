# Alternative Approaches to VAC Bypass

Other ways to bypass or evade VAC from user-mode, whether encrypted comms can be intercepted, and threats VAC cannot address (DMA, network, kernel). Based on Daniel Krupinski's reverse engineering and bypass.

> **Disclaimer:** Educational only.

---

## Table of Contents

- [What Daniel Got Right](#what-daniel-got-right)
- [Alternative User-Mode Bypass Approaches](#alternative-user-mode-bypass-approaches)
  - [A. Syscall-Level Data Poisoning](#a-syscall-level-data-poisoning)
  - [B. File Mapping Manipulation](#b-file-mapping-manipulation)
  - [C. Module Delivery Interception](#c-module-delivery-interception)
  - [D. Report Layer Poisoning](#d-report-layer-poisoning)
  - [E. Thread Suspension Timing Attack](#e-thread-suspension-timing-attack)
  - [F. Full Data Fabrication](#f-full-data-fabrication)
- [Intercepting VAC's Encrypted Communications](#intercepting-vacs-encrypted-communications)
- [Beyond User-Mode: Threats VAC Cannot Address](#beyond-user-mode-threats-vac-cannot-address)
  - [DMA Cheats](#dma-cheats)
  - [Network-Level Cheats](#network-level-cheats)
  - [Kernel Cheats via Custom Driver](#kernel-cheats-via-custom-driver)
  - [BYOVD - Bring Your Own Vulnerable Driver](#byovd----bring-your-own-vulnerable-driver)
- [The Fundamental Insight](#the-fundamental-insight)
- [Credits](#credits)

---

## What Daniel Got Right

VAC has five modules, 172 API pointers, multiple `NtQuerySystemInformation` classes, handle enumeration, VMT validation, and more. Daniel avoided fighting any of it. He targeted the one gate everything passes through: `Utils_getSystemInformation` checks `dwPageSize == 4096` before any scan. Hook `GetSystemInfo`, return 1337, and the scan bails. Valve gets nothing.

Small surface area (8 hooks, 1 patched byte), early exit so no module runs, and failsafes that kill Steam on fallback so no report is sent. VAC's dynamic API resolution means every lookup goes through `GetProcAddress`; hook that and you control what VAC gets. ~200 lines of C.

Other user-mode strategies exist, each with different trade-offs. Most are fragile or noisier. A few are worth noting.

---

## Alternative User-Mode Bypass Approaches

### A. Syscall-Level Data Poisoning

Daniel's approach kills the scan before it starts. But what if you let it run and just fed it garbage?

VAC calls `NtQuerySystemInformation` with 7 different information classes. None are hooked by Daniel's bypass. Instead of preventing the scan, we could hook the `ntdll.dll` syscall stub for `NtQuerySystemInformation` and filter the results in real time.

```mermaid
flowchart TD
    subgraph DANIELS["Daniel's Approach"]
        direction TB
        D1["Hook GetSystemInfo"] --> D2["Return fake page size"] --> D3["Scan aborts<br/>before any data collected"]
    end

    subgraph ALTERNATIVE["Syscall Poisoning Approach"]
        direction TB
        A1["Hook NtQuerySystemInformation<br/>in ntdll.dll"] --> A2["Let scan run normally"]
        A2 --> A3["Intercept each info class"]
        A3 --> FILTER{"Which class?"}
        FILTER --> F1["SystemHandleInformation<br/>Remove suspicious handles"]
        FILTER --> F2["SystemKernelDebuggerInformation<br/>Report no debugger"]
        FILTER --> F3["SystemCodeIntegrityInformation<br/>Report CI intact"]
        FILTER --> F4["Other classes<br/>Pass through real data"]
        F1 --> REPORT["Scan completes<br/>Reports 'nothing found'"]
        F2 --> REPORT
        F3 --> REPORT
        F4 --> REPORT
    end

    style DANIELS fill:#1a1a2e,stroke:#533483,color:#fff
    style ALTERNATIVE fill:#1a1a2e,stroke:#e94560,color:#fff
    style D3 fill:#ff0000,stroke:#1a1a2e,color:#fff
    style REPORT fill:#533483,stroke:#1a1a2e,color:#fff
    style FILTER fill:#e94560,stroke:#1a1a2e,color:#fff
    style F1 fill:#0f3460,stroke:#1a1a2e,color:#fff
    style F2 fill:#0f3460,stroke:#1a1a2e,color:#fff
    style F3 fill:#0f3460,stroke:#1a1a2e,color:#fff
    style F4 fill:#0f3460,stroke:#1a1a2e,color:#fff
```

**What you could do with this:**
- Strip your cheat's handles out of the `SystemHandleInformation` results so ProcessHandleList never sees them
- Remove cheat drivers from `EnumServicesStatusW` output
- Tell VAC there's no kernel debugger even when you're actively debugging
- Report code integrity as clean even with DSE bypassed

From a telemetry perspective this is cleaner: no report at all can be a signal; a full scan that sends "nothing found" looks like a clean host. In practice you must know every `NtQuerySystemInformation` output layout and edit buffers without corrupting them; `SystemHandleInformation` is variable-length with huge entry counts. The `ntdll` syscall stub format also varies across Windows builds, and some setups use direct `syscall`; the approach tends to break across versions.

---

### B. File Mapping Manipulation

VAC's ProcessMonitor module communicates with `steamservice.dll` through a Windows file mapping with a predictable name:

```
Steam_{E9FD3C51-9B58-4DA0-962C-734882B19273}_Pid:%08X
```

This mapping contains a magic value (`0x30004`) and a pointer to a `VacProcessMonitor` object (292 bytes) with a virtual method table (6 methods, 24 bytes). ProcessMonitor validates that each VMT pointer falls within `steamservice.dll`'s address range.

The name is deterministic. Any process that knows the game's PID can open this mapping.

```mermaid
flowchart TD
    subgraph NORMAL["Normal Operation"]
        SS["steamservice.dll<br/>creates file mapping"] --> MAP["Shared Memory<br/>Magic: 0x30004<br/>VacProcessMonitor ptr"]
        MAP --> PM["ProcessMonitor reads<br/>and validates VMT"]
    end

    subgraph ATTACK["File Mapping Attack Vectors"]
        direction TB
        V1["Vector 1: Corrupt Magic<br/>Set magic to 0x00000<br/>ProcessMonitor sees<br/>uninitialized mapping<br/>scan skipped"]
        V2["Vector 2: Replace VMT Pointers<br/>Point methods to benign<br/>RET instructions within<br/>steamservice.dll range<br/>validation passes,<br/>methods do nothing"]
        V3["Vector 3: Null the Object Pointer<br/>Set VacProcessMonitor ptr to NULL<br/>ProcessMonitor cannot<br/>read the object"]
    end

    MAP -.->|"External process<br/>opens by name"| ATTACK

    style NORMAL fill:#1a1a2e,stroke:#533483,color:#fff
    style ATTACK fill:#1a1a2e,stroke:#e94560,color:#fff
    style V1 fill:#e94560,stroke:#1a1a2e,color:#fff
    style V2 fill:#e94560,stroke:#1a1a2e,color:#fff
    style V3 fill:#e94560,stroke:#1a1a2e,color:#fff
    style SS fill:#533483,stroke:#1a1a2e,color:#fff
    style MAP fill:#0f3460,stroke:#1a1a2e,color:#fff
    style PM fill:#0f3460,stroke:#1a1a2e,color:#fff
```

Vector 2 is the one that matters: validation only checks `(method_ptr & 0xFFFF0000) == steamservice_base`, so any address in `steamservice.dll` passes. Point VMT entries at `RET` gadgets inside that range and the check passes while the methods do nothing. Daniel's bypass stops the scan before ProcessMonitor runs, so this only matters if scan order changed. Forensically clean (no patches, no hooks, no injection; just tweak shared memory and exit). Only affects ProcessMonitor; the other modules don't use this mapping.

---

### C. Module Delivery Interception

VAC modules are DLLs streamed from Valve's servers to the client. `steamservice.dll` receives them over the network, decrypts them, and loads them into the game process. What if they never arrive?

```mermaid
flowchart LR
    subgraph SERVER["Valve Servers"]
        VS["VAC Module<br/>Repository"]
    end

    subgraph NETWORK["Network Layer"]
        NET["Encrypted module<br/>in transit"]
    end

    subgraph CLIENT["Client"]
        SS["steamservice.dll"]
        GAME["Game Process"]
    end

    VS --> NET --> SS --> GAME

    subgraph INTERCEPT["Interception Points"]
        direction TB
        I1["Point 1: Winsock Hook<br/>Hook recv / WSARecv<br/>Drop packets containing<br/>VAC module signatures"]
        I2["Point 2: WinINet Hook<br/>Hook InternetReadFile<br/>Return empty buffer<br/>for VAC download URLs"]
        I3["Point 3: DNS Redirect<br/>Redirect VAC module<br/>server hostnames to<br/>localhost via hosts file"]
        I4["Point 4: Firewall Rule<br/>Block outbound connections<br/>to VAC module servers<br/>on specific ports"]
    end

    NET -.-> INTERCEPT

    style SERVER fill:#1a1a2e,stroke:#e94560,color:#fff
    style NETWORK fill:#16213e,stroke:#e94560,color:#fff
    style CLIENT fill:#1a1a2e,stroke:#533483,color:#fff
    style INTERCEPT fill:#1a1a2e,stroke:#ff0000,color:#fff
    style I1 fill:#e94560,stroke:#1a1a2e,color:#fff
    style I2 fill:#e94560,stroke:#1a1a2e,color:#fff
    style I3 fill:#0f3460,stroke:#1a1a2e,color:#fff
    style I4 fill:#0f3460,stroke:#1a1a2e,color:#fff
```

**Point 1 (Winsock Hook)** is the most practical user-mode approach. By hooking `recv` or `WSARecv` in `steamservice.dll`, incoming data can be inspected for VAC module signatures. If a packet looks like a module download, return 0 bytes or an error code. `steamservice.dll` sees a network failure and the module never loads.

**Point 3 (DNS Redirect)** is the simplest but most detectable. Editing the `hosts` file to redirect VAC server hostnames to `127.0.0.1` prevents module downloads without any code injection. However, Valve could detect the hosts file modification, and Steam may validate DNS responses.

**Point 4 (Firewall Rule)** operates outside the process entirely. A Windows Firewall rule blocking outbound connections to VAC module server IPs would prevent downloads. This requires knowing the server IPs, which could change, but operates at the OS level with no code injection.

Same issue as Daniel's: no module load means no report. A network failure is more plausible than an odd page size, but missing reports can still be flagged.

---

### D. Report Layer Poisoning

Let VAC run to completion, then rewrite the report before it leaves the machine.

VAC encrypts scan results through two layers:
1. **XOR encryption** - DWORD-by-DWORD with a server-provided key (e.g., `0x1D4855D3`)
2. **ICE cipher** - 16-round Feistel network, 8-byte blocks, 4 S-boxes with 1024 entries each

The encrypted report is then transmitted back to Valve.

```mermaid
flowchart TD
    SCAN["VAC scan completes<br/>with real findings"] --> SERIALIZE["Serialize scan data<br/>into 2048-byte buffer"]
    SERIALIZE --> XOR["XOR encrypt<br/>(server key)"]
    XOR --> ICE["ICE cipher encrypt<br/>(16 rounds)"]
    ICE --> SEND["Transmit to<br/>Valve servers"]

    subgraph POISONING["Report Poisoning Approach"]
        direction TB
        P1["Option 1: Pre-encryption<br/>Hook the serialization<br/>Modify buffer before encryption<br/>Replace findings with clean data"]
        P2["Option 2: Post-encryption<br/>Decrypt the report<br/>Modify the payload<br/>Re-encrypt and send"]
        P3["Option 3: Full replacement<br/>Drop the real report<br/>Generate a fabricated<br/>clean report from scratch"]
    end

    SERIALIZE -.-> P1
    ICE -.-> P2
    SEND -.-> P3

    style SCAN fill:#e94560,stroke:#1a1a2e,color:#fff
    style SERIALIZE fill:#533483,stroke:#1a1a2e,color:#fff
    style XOR fill:#0f3460,stroke:#1a1a2e,color:#fff
    style ICE fill:#0f3460,stroke:#1a1a2e,color:#fff
    style SEND fill:#1a1a2e,stroke:#e94560,color:#fff
    style POISONING fill:#1a1a2e,stroke:#ff0000,color:#fff
    style P1 fill:#e94560,stroke:#1a1a2e,color:#fff
    style P2 fill:#e94560,stroke:#1a1a2e,color:#fff
    style P3 fill:#e94560,stroke:#1a1a2e,color:#fff
```

Option 1 (pre-encryption) is the practical path: hook the code that fills the 2048-byte buffer, zero or replace findings, then let encryption run. Valve gets a valid encrypted report that decrypts to "nothing found." Option 2 (post-encryption) needs the XOR key (capturable from the session) and the ICE key (e.g. from `Ice_set()`); then decrypt, modify, re-encrypt.

From a telemetry perspective this produces the fewest obvious anomalies, assuming the report format has not drifted and no extra server-side checks fire. The cost is high: exact report layout, byte-to-finding mapping, and any server-side integrity (checksums, HMACs, nonces) must be understood and preserved.

---

### E. Thread Suspension Timing Attack

VAC modules are loaded via `LoadLibraryExW`, which creates a new module in the process. Between the moment the module is loaded and the moment its scan thread begins execution, there is a timing window.

```mermaid
sequenceDiagram
    participant SS as steamservice.dll
    participant LLE as LoadLibraryExW
    participant MOD as VAC Module
    participant BYPASS as Bypass (monitoring)

    SS->>LLE: LoadLibraryExW("vac_module.dll")
    LLE->>MOD: Map DLL into memory
    LLE->>MOD: Call DllMain(DLL_PROCESS_ATTACH)
    MOD-->>LLE: DllMain returns

    Note over BYPASS: Timing window opens here

    BYPASS->>MOD: Enumerate new threads
    BYPASS->>MOD: SuspendThread on scan thread
    BYPASS->>MOD: Locate scan function via pattern scan
    BYPASS->>MOD: Patch: MOV EAX, 0 / RET<br/>(overwrite first bytes)
    BYPASS->>MOD: ResumeThread

    MOD->>MOD: Scan function called
    MOD->>MOD: Immediately returns 0
    MOD-->>SS: Report: no findings
```

**How it works:**
1. Hook `LoadLibraryExW` (same as Daniel's approach) to detect when a VAC module loads
2. After the module is mapped, enumerate newly created threads via `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)`
3. Suspend the scan thread with `SuspendThread`
4. Pattern scan the module's `.text` section for the scan initialization function
5. Overwrite the first bytes with `XOR EAX, EAX / RET` (return 0)
6. Resume the thread

**Advantage over Daniel's approach:** No persistent API hooks. The hooks are only needed briefly during module load. After patching, the hooks can be removed entirely, leaving no hookable trace for later integrity checks.

**Risk:** The timing window between module load and thread execution is narrow. If the scan thread starts before suspension, the patch arrives too late. This can be mitigated by hooking `CreateThread` to catch the scan thread at creation time and suspend it before it runs.

---

### F. Full Data Fabrication

The inverse of Daniel's approach. Instead of preventing the scan, **complete it successfully with entirely fabricated data**.

```mermaid
flowchart TD
    subgraph DANIELS["Daniel's Philosophy"]
        D["Prevent scan from running<br/>No data collected<br/>No report sent"]
    end

    subgraph FABRICATION["Fabrication Philosophy"]
        F["Let scan run on a<br/>fabricated environment<br/>Real report sent<br/>with clean data"]
    end

    FABRICATION --> HOOKS["Hook every data-gathering API"]

    HOOKS --> H1["GetSystemInfo<br/>Return real page size 4096<br/>Scan proceeds normally"]
    HOOKS --> H2["NtQuerySystemInformation<br/>Filter handles, hide debuggers<br/>Report clean code integrity"]
    HOOKS --> H3["FindFirstVolumeW<br/>Return spoofed volume data<br/>Fake serial numbers and GUIDs"]
    HOOKS --> H4["EnumServicesStatusW<br/>Remove cheat drivers<br/>from service list"]
    HOOKS --> H5["ReadProcessMemory<br/>Return clean memory pages<br/>Hide injected DLLs"]
    HOOKS --> H6["GetFileInformationByHandle<br/>Spoof file metadata<br/>for modified binaries"]

    H1 --> RESULT["VAC scan completes<br/>All checks pass<br/>Encrypted report says 'clean'<br/>Valve sees normal system"]
    H2 --> RESULT
    H3 --> RESULT
    H4 --> RESULT
    H5 --> RESULT
    H6 --> RESULT

    style DANIELS fill:#1a1a2e,stroke:#533483,color:#fff
    style FABRICATION fill:#1a1a2e,stroke:#e94560,color:#fff
    style D fill:#533483,stroke:#1a1a2e,color:#fff
    style F fill:#e94560,stroke:#1a1a2e,color:#fff
    style HOOKS fill:#0f3460,stroke:#1a1a2e,color:#fff
    style RESULT fill:#533483,stroke:#1a1a2e,color:#fff
    style H1 fill:#0f3460,stroke:#1a1a2e,color:#fff
    style H2 fill:#0f3460,stroke:#1a1a2e,color:#fff
    style H3 fill:#0f3460,stroke:#1a1a2e,color:#fff
    style H4 fill:#0f3460,stroke:#1a1a2e,color:#fff
    style H5 fill:#0f3460,stroke:#1a1a2e,color:#fff
    style H6 fill:#0f3460,stroke:#1a1a2e,color:#fff
```

Return the real page size (4096) so the scan proceeds, and hook every data-gathering API to present a clean system:

| API | Fabricated Response |
|-----|-------------------|
| `GetSystemInfo` | Real data (page size 4096, real CPU info) |
| `NtQuerySystemInformation(SystemHandleInformation)` | Real handles minus any with suspicious access rights to the game |
| `NtQuerySystemInformation(SystemKernelDebuggerInformation)` | No debugger attached |
| `NtQuerySystemInformation(SystemCodeIntegrityInformation)` | Code integrity intact |
| `EnumServicesStatusW` | Real services minus cheat drivers |
| `FindFirstVolumeW` / `FindNextVolumeW` | Spoofed serial numbers if evading hardware ban |
| `ReadProcessMemory` | Clean memory pages at checked offsets |
| `GetFileInformationByHandle` | Original file indices for modified binaries |

Assuming consistency across all spoofed data (e.g. fake volume serials match everywhere they're queried), the result looks like a clean host. The cost is hooking 20+ APIs and knowing each return format; one inconsistency can be detected server-side. Daniel's 8-hook approach achieves the same practical outcome with far less work and maintenance.

---

## Intercepting VAC's Encrypted Communications

An entirely different attack surface: the data flowing between VAC's servers and the client. VAC modules are delivered encrypted, and scan reports are transmitted encrypted. Could this channel be inspected, decrypted, or manipulated?

### The Encryption Stack

VAC uses a layered encryption approach for both module delivery and scan reporting:

```mermaid
flowchart TD
    subgraph INBOUND["Inbound: Module Delivery"]
        direction TB
        I1["Valve servers send<br/>compiled VAC DLLs"] --> I2["Encrypted in transit<br/>Steam TLS and custom"]
        I2 --> I3["steamservice.dll receives<br/>and decrypts"] --> I4["Module loaded into<br/>game process"]
    end

    subgraph OUTBOUND["Outbound: Scan Reports"]
        direction TB
        O1["Scan data collected<br/>2048-byte buffer"] --> O2["XOR encryption<br/>DWORD-by-DWORD<br/>Server-provided key"]
        O2 --> O3["ICE cipher<br/>16-round Feistel<br/>8-byte blocks"]
        O3 --> O4["Transmitted to<br/>Valve servers"]
    end

    subgraph INTERCEPT["Interception Analysis"]
        direction TB
        T1["TLS Layer<br/>Steam uses standard TLS<br/>for transport security.<br/>MITM possible with custom<br/>root CA on local machine"]
        T2["XOR Layer<br/>Key is server-provided<br/>per session. Can be captured<br/>in memory when received.<br/>XOR is trivially reversible<br/>once key is known"]
        T3["ICE Layer<br/>Key schedule derived from<br/>input key string. If key<br/>captured during Ice_set,<br/>full decrypt is possible.<br/>16-round Feistel is symmetric,<br/>same key encrypts and decrypts"]
    end

    I2 -.-> T1
    O2 -.-> T2
    O3 -.-> T3

    style INBOUND fill:#1a1a2e,stroke:#533483,color:#fff
    style OUTBOUND fill:#1a1a2e,stroke:#e94560,color:#fff
    style INTERCEPT fill:#1a1a2e,stroke:#ff0000,color:#fff
    style T1 fill:#0f3460,stroke:#1a1a2e,color:#fff
    style T2 fill:#e94560,stroke:#1a1a2e,color:#fff
    style T3 fill:#e94560,stroke:#1a1a2e,color:#fff
```

### Can the XOR Layer Be Broken?

Yes, trivially. The XOR key is provided by the server at the start of each session. It arrives in plaintext (within the TLS stream) and is stored in memory. Two approaches:

1. **Memory capture:** Hook the function that receives the XOR key from the server, or scan memory for the key after it arrives. XOR keys like `0x1D4855D3` are 4 bytes and used for the entire 2048-byte buffer. Once known, the XOR layer can be applied or removed at will.

2. **Known-plaintext attack:** If any portion of the scan report is predictable (e.g., fixed header bytes, known structure offsets), XORing the known plaintext against the ciphertext reveals the key directly.

### Can the ICE Cipher Be Broken?

Not through cryptanalysis - the ICE cipher is a 16-round Feistel network and is cryptographically sound for its intended purpose. However, it doesn't need to be broken:

- **Key capture:** The ICE key is set via `Ice_set()`, which takes a key string and builds the key schedule. Hooking this function captures the key at initialization. Since ICE is symmetric, the same key decrypts.
- **Pre-encryption interception:** Hook the buffer before it enters encryption. The plaintext scan data is available in memory as a 2048-byte buffer before `Ice_encrypt()` is called.
- **S-box reconstruction:** The 4 S-boxes (1024 entries each) are initialized at runtime via `Ice_InitSboxes()`. Capturing them after initialization allows offline decryption of any report encrypted with the same configuration.

### Can Module Delivery Be Decrypted?

Module delivery uses Steam's own transport encryption (TLS). On the local machine, this can be intercepted by:

1. **Installing a custom root CA** and performing a local MITM on Steam's TLS connections
2. **Hooking the decryption output** in `steamservice.dll` - capturing the module bytes after decryption but before loading
3. **Dumping from memory** after the module is loaded into the game process, since the decrypted DLL exists as a mapped image

Daniel's VAC repository itself is proof that module delivery can be decrypted and analyzed - his entire reverse engineering project is based on disassembling the decrypted module binaries.

### Practical Implications

The encryption stack protects against **passive network observers** (ISPs, public Wi-Fi sniffers) but provides no protection against **the machine owner**. Since the encryption keys exist in memory on the client and the decrypted data is processed in user-mode, anyone with admin access to the machine can inspect everything.

You cannot protect secrets from the owner of the machine. Encryption helps against passive observers; keys and plaintext exist on the client, so the primary threat (the user) is not mitigated.

---

## Beyond User-Mode: Threats VAC Cannot Address

Daniel's work operates entirely within Ring 3 (user-mode). But the most impactful cheat architectures for CS:GO operated at layers VAC could never reach. These are not bypass techniques - they are architectures that make VAC irrelevant regardless of how it is implemented.

### DMA Cheats

Direct Memory Access cheats use a hardware device (typically a PCIe card, commonly referred to as a "DMA card") to read game memory through the PCIe bus without involving the CPU at all.

```mermaid
flowchart LR
    subgraph GAMING_PC["Gaming PC"]
        CPU["CPU<br/>Running CS:GO + VAC"]
        RAM["System RAM<br/>Game state in memory"]
        PCIE["PCIe Bus"]
        DMA_CARD["DMA Card<br/>(e.g. Screamer, AcquirePCIe)"]
    end

    subgraph SECOND_PC["Second PC"]
        SOFTWARE["Cheat Software<br/>ESP overlay / aimbot<br/>reads game memory"]
    end

    RAM <-->|"Normal memory access<br/>(monitored by VAC)"| CPU
    RAM <-->|"DMA read<br/>(invisible to CPU)"| DMA_CARD
    DMA_CARD <-->|"Thunderbolt / PCIe<br/>cable"| PCIE
    DMA_CARD <-->|"USB or network<br/>to second PC"| SOFTWARE

    style GAMING_PC fill:#1a1a2e,stroke:#e94560,color:#fff
    style SECOND_PC fill:#1a1a2e,stroke:#ff0000,color:#fff
    style CPU fill:#533483,stroke:#1a1a2e,color:#fff
    style RAM fill:#0f3460,stroke:#1a1a2e,color:#fff
    style DMA_CARD fill:#ff0000,stroke:#1a1a2e,color:#fff
    style SOFTWARE fill:#ff0000,stroke:#1a1a2e,color:#fff
```

**Why VAC is completely blind to this:**

- The DMA card reads physical memory addresses directly via the PCIe bus. This does not trigger any software interrupt, syscall, or API call. The CPU is not involved.
- No process is created on the gaming PC. `NtQuerySystemInformation(SystemHandleInformation)` sees nothing.
- No driver is loaded on the gaming PC. `EnumServicesStatusW` sees nothing.
- No handle is opened to the game process. Handle enumeration finds nothing.
- The cheat software runs on a completely separate machine. Even a kernel-mode anti-cheat on the gaming PC cannot detect software running on a different computer.

**The DMA card itself** is typically a modified FPGA device that presents itself as a legitimate PCIe peripheral (e.g., a network card). The gaming PC's OS sees a normal device in Device Manager.

**What can DMA cheats do?**
- Read all player positions, health, weapon data from game memory
- Feed this to a second monitor showing a radar or ESP overlay
- With write access (bidirectional DMA), modify game memory to implement aimbot, speed hacks, or teleportation - though writing is riskier as it can cause game crashes if the wrong addresses are modified

**What could theoretically detect this:**
- IOMMU (Input/Output Memory Management Unit) configuration that restricts which physical memory regions DMA devices can access. However, most gaming PCs have IOMMU disabled for performance, and cheat DMA firmware can often work around basic IOMMU configurations.
- Kernel-mode anti-cheat that monitors PCIe device enumeration (e.g., checking for FPGA-based devices), but this is a cat-and-mouse game as DMA firmware evolves to impersonate legitimate devices.

---

### Network-Level Cheats

Rather than reading memory locally, network cheats intercept game packets in transit and extract game state from the network data itself.

```mermaid
flowchart TD
    subgraph GAME_CLIENT["CS:GO Client"]
        CSGO["Game Engine"] --> NET_STACK["Network Stack<br/>UDP packets"]
    end

    subgraph NETWORK["Network Path"]
        ROUTER["Router / Switch"]
    end

    subgraph VALVE_SVRS["Valve Game Servers"]
        GS["Game Server<br/>Sends world state<br/>to all players"]
    end

    subgraph PASSIVE["Passive Network Cheat"]
        direction TB
        MIRROR["Network tap or<br/>port mirroring"] --> PARSER["Packet parser<br/>Extracts player positions<br/>from UDP stream"]
        PARSER --> RADAR["Second monitor<br/>showing radar overlay<br/>with all player positions"]
    end

    subgraph ACTIVE["Active Network Cheat"]
        direction TB
        PROXY["Local proxy<br/>(WinDivert / nfqueue)"] --> MODIFY["Inspect + modify<br/>game packets"]
        MODIFY --> INJECT["Inject fabricated<br/>packets or delay<br/>specific updates"]
    end

    GS --> ROUTER --> NET_STACK
    ROUTER -.-> MIRROR
    NET_STACK -.-> PROXY

    style GAME_CLIENT fill:#1a1a2e,stroke:#533483,color:#fff
    style VALVE_SVRS fill:#1a1a2e,stroke:#533483,color:#fff
    style NETWORK fill:#16213e,stroke:#e94560,color:#fff
    style PASSIVE fill:#1a1a2e,stroke:#ff0000,color:#fff
    style ACTIVE fill:#1a1a2e,stroke:#ff0000,color:#fff
    style MIRROR fill:#e94560,stroke:#1a1a2e,color:#fff
    style RADAR fill:#ff0000,stroke:#1a1a2e,color:#fff
    style PROXY fill:#e94560,stroke:#1a1a2e,color:#fff
```

**Passive network cheats** tap the network without modifying anything:

- **Packet sniffing:** Use a network tap, port mirroring on a managed switch, or a promiscuous-mode capture on the local NIC. Extract UDP game packets and parse them for player position data.
- **Radar overlay:** Send parsed positions to a second PC or second monitor displaying a real-time radar showing all player locations. No software runs on the gaming PC beyond the normal game client.
- **Why VAC can't detect this:** The sniffing happens at the network layer, outside the game process, outside the OS, often on separate hardware entirely. There is no process, no handle, no driver, no file to detect.

**Active network cheats** use a local packet filter to modify game traffic:

- **WinDivert / Npcap:** Kernel-mode packet filter drivers that can intercept, inspect, and modify network packets before they reach the game client or after they leave it.
- **Selective packet delay:** Delay position update packets for specific players to gain a reaction-time advantage.
- **Packet injection:** Fabricate packets that the game client interprets as legitimate server updates.

**CS:GO's specific vulnerability:** Source Engine games historically sent more world-state data to clients than strictly necessary. While Valve implemented "trusted mode" and server-side visibility checks to limit what data clients receive, earlier versions sent enough information for a network parser to reconstruct a full radar of all player positions - even players behind walls.

**The encryption challenge:** Modern game protocols use encryption on the UDP stream, making passive sniffing harder. However, since the game client must decrypt the packets to process them, the decryption keys exist in memory on the gaming PC. A DMA card or local memory read can extract the session keys, enabling real-time decryption of the network stream on a second machine.

---

### Kernel Cheats via Custom Driver

A cheat running as a signed kernel driver has complete control over the system and is invisible to any user-mode anti-cheat.

```mermaid
flowchart TB
    subgraph RING0["Ring 0: Kernel Mode"]
        CHEAT_DRV["Cheat Driver<br/>(signed .sys)"]
        NTOSKRNL["ntoskrnl.exe"]
        HAL["Hardware<br/>Abstraction Layer"]
    end

    subgraph RING3["Ring 3: User Mode"]
        VAC["VAC Modules"]
        CSGO["CS:GO"]
        CHEAT_CLIENT["Cheat User-Mode<br/>Client (optional)"]
    end

    CHEAT_DRV -->|"Read/write<br/>game memory directly"| CSGO
    CHEAT_DRV -->|"Hide from enumeration<br/>via DKOM"| NTOSKRNL
    CHEAT_DRV -->|"Filter syscall results<br/>via SSDT hook"| VAC
    CHEAT_DRV -.->|"Communicate via<br/>IOCTL / shared memory"| CHEAT_CLIENT

    VAC -->|"NtQuerySystemInformation<br/>(filtered by driver)"| NTOSKRNL

    style RING0 fill:#1a1a2e,stroke:#ff0000,color:#fff
    style RING3 fill:#16213e,stroke:#533483,color:#fff
    style CHEAT_DRV fill:#ff0000,stroke:#1a1a2e,color:#fff
    style VAC fill:#0f3460,stroke:#1a1a2e,color:#fff
    style CSGO fill:#533483,stroke:#1a1a2e,color:#fff
    style CHEAT_CLIENT fill:#e94560,stroke:#1a1a2e,color:#fff
```

**Getting a driver signed** is the primary barrier. Windows requires kernel drivers to be signed with an Extended Validation (EV) code signing certificate. There are two paths:

**Path 1: Legitimate EV certificate**
- Purchase an EV code signing certificate from a Certificate Authority (~$300-500/year)
- Requires a registered business entity with verification
- Sign the driver through Microsoft's Hardware Developer Center (attestation signing for Windows 10+)
- The driver loads normally via `sc create` + `sc start`
- **Detection risk:** Valve can report the driver's certificate thumbprint. Once identified, the certificate can be revoked by the CA and the driver signature blacklisted by Microsoft. This is a one-time-use approach unless multiple certificates are rotated.

**Path 2: Self-signed with test signing enabled**
- Generate a self-signed certificate and sign the driver locally
- Enable test signing mode: `bcdedit /set testsigning on`
- The driver loads, but Windows displays a "Test Mode" watermark on the desktop
- **Detection risk:** VAC queries `SystemCodeIntegrityInformation` which reveals test signing is enabled. Trivially detectable.

**What a kernel driver can do that VAC cannot see:**
- **DKOM (Direct Kernel Object Manipulation):** Unlink the cheat's `EPROCESS` entry from the kernel's process list. The process continues running but is invisible to `NtQuerySystemInformation`, Task Manager, and every user-mode enumeration API.
- **SSDT hooking:** Modify the System Service Descriptor Table to intercept any syscall. When VAC calls `NtQuerySystemInformation`, the hooked syscall handler filters the results before they reach user-mode.
- **Page table manipulation:** Map game memory into the driver's address space without opening a handle. No handle means handle enumeration sees nothing.
- **Physical memory read/write:** Access physical RAM addresses directly, bypassing all access checks.

---

### BYOVD - Bring Your Own Vulnerable Driver

Rather than obtaining a signing certificate, exploit a vulnerability in a **legitimately signed driver** to gain kernel code execution.

```mermaid
flowchart TD
    subgraph ATTACK_CHAIN["BYOVD Attack Chain"]
        FIND["1. Find a legitimately signed<br/>driver with a vulnerability<br/>(e.g. CVE in a hardware<br/>vendor's driver)"]
        LOAD["2. Load the vulnerable driver<br/>normally via Service Control<br/>Manager (it's properly signed)"]
        EXPLOIT["3. Send crafted IOCTL to<br/>the vulnerable driver<br/>triggering arbitrary<br/>kernel code execution"]
        MAP["4. Use the exploit to<br/>manually map an unsigned<br/>cheat driver into<br/>kernel memory"]
        HIDE["5. Cheat driver runs in<br/>kernel with full privileges<br/>No signature required<br/>Not in service list"]
    end

    FIND --> LOAD --> EXPLOIT --> MAP --> HIDE

    subgraph EXAMPLES["Known Vulnerable Drivers Used"]
        direction TB
        E1["Capcom.sys<br/>Intentional backdoor<br/>Disables SMEP, runs<br/>user-supplied code in Ring 0"]
        E2["Intel NAL driver<br/>Arbitrary physical memory<br/>read/write via IOCTL"]
        E3["Various GPU vendor drivers<br/>Buffer overflows in IOCTL<br/>handlers leading to<br/>kernel code execution"]
        E4["AsIO.sys ASUS<br/>Arbitrary port I/O<br/>and MSR access"]
    end

    HIDE -.-> EXAMPLES

    style ATTACK_CHAIN fill:#1a1a2e,stroke:#ff0000,color:#fff
    style FIND fill:#e94560,stroke:#1a1a2e,color:#fff
    style LOAD fill:#e94560,stroke:#1a1a2e,color:#fff
    style EXPLOIT fill:#ff0000,stroke:#1a1a2e,color:#fff
    style MAP fill:#ff0000,stroke:#1a1a2e,color:#fff
    style HIDE fill:#ff0000,stroke:#1a1a2e,color:#fff
    style EXAMPLES fill:#1a1a2e,stroke:#e94560,color:#fff
    style E1 fill:#533483,stroke:#1a1a2e,color:#fff
    style E2 fill:#533483,stroke:#1a1a2e,color:#fff
    style E3 fill:#533483,stroke:#1a1a2e,color:#fff
    style E4 fill:#533483,stroke:#1a1a2e,color:#fff
```

The vulnerable driver is legitimately signed and loads normally. VAC might see it in the service list but it's a real vendor driver; flagging it would false-positive on many machines. The exploit gives kernel execution via the driver's IOCTL; the cheat driver is then manually mapped (e.g. `ExAllocatePool`, copy, call entry point) and never appears in the loaded module list or service enumeration.

**The cat-and-mouse game:** Microsoft maintains a vulnerable driver blocklist (`Microsoft Vulnerable Driver Blocklist`) that prevents known-exploitable drivers from loading. However, new vulnerabilities are discovered faster than the blocklist is updated, and legacy systems may not have the latest blocklist.

**Even kernel-mode anti-cheat struggles here.** EAC, BattlEye, and Vanguard all attempt to detect BYOVD by:
- Maintaining their own driver blocklists
- Monitoring for suspicious IOCTL patterns
- Checking for manually mapped kernel memory regions (pool allocations with executable permissions)
- Scanning for known exploit signatures

But this is fundamentally a reactive defense. Each new vulnerable driver requires a new blocklist entry. The attacker only needs one driver that hasn't been blocklisted yet.

---

## Conclusion

At the same privilege level, the scanner never gets the last word. That is the limitation Daniel's work exposes: ~200 lines of C turn off VAC because it runs in the same process with the same rights. User-mode cannot verify that kernel responses are honest; kernel cannot verify the hypervisor; software cannot see DMA. The industry moved to kernel-level anti-cheat (EAC, BattlEye, Vanguard) to get a privilege advantage; the arms race then moved to hypervisors and hardware. Operating above the adversary's layer is what actually changes the game.

---

## Credits

[Daniel Krupinski](https://github.com/danielkrupinski): [VAC](https://github.com/danielkrupinski/VAC), [VAC-Bypass](https://github.com/danielkrupinski/VAC-Bypass). License: MIT.
