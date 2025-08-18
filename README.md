# GhostTEB | GS:[0x30] read emulator (user-mode)
GhostTEB spoofs TEB reads at a specific call site by inlining a UD2 trap & handling it with a Vectored Exception Handler(VEH) in user mode.
When the trapped instruction is hit, GhostTEB returns a fake TEB base, writes it to the register, skips the original instruction, and resumes execution.

### **Features**
- Inline emulation of mov r64, gs:[0x30] at chosen call sites
- Instruction skipping (Rip += len) after writing spoofed value
- Stub resolution: handles endbr64, hotpatch nops, and common JMP thunks

> Tested on: Windows 10/11 x64, MSVC toolset (latest). Requires x64 (uses __readgsqword).

###  Output
```python
GhostTEB | TEB/VEH Base Emulation (user-mode)

[VALID] gs:[0x30] before: 00000076A6F2F000
Hooked @ 00007FF6889B14F0 (len=9, dst=0)

[verify] 9B before patch:
65 48 8B 04 25 30 00 00 00
[verify] 9B after  patch:
0F 0B 8B 04 25 30 00 00 00
[verify] head = UD2 OK

[check]   VEH disable test
[success] STATUS_ILLEGAL_INSTRUCTION
[success] VEH restored

[run] VEH Enabled:
  00 -> 0000024F7DF10000 (SPOOF)
  01 -> 0000024F7DF10000 (SPOOF)
  02 -> 0000024F7DF10000 (SPOOF)

[Finished] returned gs:[0x30] -> 00000076A6F2F000 (og: 00000076A6F2F000)
```
