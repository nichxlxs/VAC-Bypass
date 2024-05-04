# VAC: A User-Mode Anti-Cheat Case Study

An educational project analyzing Valve Anti-Cheat (VAC) as it operated in CS:GO - how it worked, how it was bypassed, and why the industry moved to kernel-level anti-cheat. Based on the reverse engineering work by [Daniel Krupinski](https://github.com/danielkrupinski).

> **Disclaimer:** This project is strictly educational.

**Note:** The original bypass (and the Rust reimplementation in this repo) was coded for **32-bit Steam**. Current Steam is 64-bit, so this project likely does not work anymore unless it is upgraded to 64-bit.

---

## Documents

### [VAC Analysis](VAC-Analysis.md)
How VAC works internally - module architecture, detection mechanisms (IAT hook detection, VMT validation, handle enumeration, driver scanning), encryption protocols (ICE cipher, XOR, MD5, CRC32), and the inherent limitations of user-mode anti-cheat against kernel-level threats.

### [VAC Bypass Analysis](VAC-Bypass-Analysis.md)
How ~200 lines of C completely disable VAC - the page size vulnerability, IAT hook chain, `GetProcAddress` interception, failsafe mechanisms, and defensive takeaways explaining why modern anti-cheat moved to Ring 0.

### [Rust implementation](vac-bypass-rs/)
Rust reimplementation of the original bypass (32-bit only): [`vac-bypass-rs/`](vac-bypass-rs/) with entrypoint [`vac-bypass-rs/src/lib.rs`](vac-bypass-rs/src/lib.rs). Build and test instructions in [vac-bypass-rs/README.md](vac-bypass-rs/README.md).

### [Alternative Approaches](Alternative-Approaches.md)
Other user-mode bypass strategies (syscall poisoning, file mapping manipulation, report layer poisoning, etc.), whether VAC's encrypted comms can be intercepted, and threats VAC cannot address (DMA, network cheats, kernel drivers, BYOVD).

### [Reverse Engineering Process](Reverse-Engineering-Process.md)
How Daniel likely reverse engineered the VAC modules from compiled 32-bit DLLs into readable C source - module capture techniques, defeating XOR string obfuscation, reconstructing the API resolution layer, function-by-function disassembly using byte-pattern signatures, mapping data structures from buffer offsets, reversing the ICE cipher, and what properties of VAC made it a feasible target.

---

## Credits

- [Daniel Krupinski](https://github.com/danielkrupinski): reverse engineering and original implementations
- [VAC](https://github.com/danielkrupinski/VAC): reconstructed VAC module source code
- [VAC-Bypass](https://github.com/danielkrupinski/VAC-Bypass): VAC bypass implementation  
- License: MIT

