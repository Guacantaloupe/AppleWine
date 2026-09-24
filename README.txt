AppleWine Stage 2
=================

Purpose
-------
Run the first real ARM64 instructions of an unsigned/test iOS IPA on x64 Windows
through a small C++17 interpreter.

How to build with CMake
-----------------------
Open this folder in Visual Studio 2022 or VS Code as a CMake project.
Select an x64 configuration and build the `AppleWine` target. The produced
Windows application opens a file dialog for the IPA, so no runtime command
line arguments are required.

The legacy `AppleWine.sln` and `AppleWine.vcxproj` are retained for direct
Visual Studio compatibility, but `CMakeLists.txt` is the canonical project.

Implemented ARM64 subset
------------------------
- B, BL, BR, BLR, RET
- B.cond, CBZ/CBNZ, TBZ/TBNZ
- ADR, ADRP
- ADD/SUB immediate and shifted-register; flag-setting CMP/CMN forms
- MOVN/MOVZ/MOVK
- AND/ORR/EOR/ANDS shifted-register, including MOV alias
- LDR literal
- LDR/STR unsigned-immediate for byte/half/word/xword and LDRSW
- LDUR/STUR W/X
- LDP/STP W/X with offset/pre-index/post-index
- HINT/NOP/PAC/BTI treated as no-op for this compatibility experiment

Execution model
---------------
- LC_MAIN is used as the initial guest PC.
- 4 MiB synthetic ARM64 stack.
- Minimal argc/argv/envp/apple context.
- X30 starts at a synthetic return sentinel.
- Up to 2000 instructions are interpreted.
- First 600 trace lines are displayed.
- An indirect branch outside mapped executable code stops cleanly and is reported.

Stage 2.5 now implemented
--------------------------
- LC_DYLD_CHAINED_FIXUPS header, import table, page starts and pointer chains
- DYLD_CHAINED_PTR_64 / _64_OFFSET and common ARM64e userland formats
- Rebase application at the original guest VM addresses
- Synthetic guest addresses for imported symbols, with symbol/dylib reporting
- Small probe shims for malloc/calloc/free, memcpy/memmove/memset, strlen/strcmp,
  selected Objective-C runtime calls, pthread-style calls, dyld queries and logging
- Synthetic 16 MiB guest heap for the above probe shims

Not implemented yet
-------------------
- Loading the actual iOS dyld shared cache and its framework dylibs
- Complete Darwin/libSystem compatibility
- Objective-C / Swift runtime compatibility
- UIKit / Metal / WebKit compatibility
- NEON/SIMD and the full AArch64 ISA

The current report should stop at a named imported symbol or framework boundary,
instead of showing a raw chained-fixup value such as 0x8010000000000025.
