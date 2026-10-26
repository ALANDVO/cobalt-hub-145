# Product development plan

Each round completes one feature or repair. Future items are planned, not implemented claims.

## Current round

fastapi-react-skeleton

## Roadmap

### fastapi-react-skeleton — FastAPI/React skeleton with binary upload and decompile endpoint

Status: done

Acceptance:
- FastAPI backend starts on port 8000
- React frontend starts on port 3000
- POST /api/decompile accepts binary upload and returns decompilation result
- Frontend shows upload form and displays decompilation output

### vtable-analysis — Vtable function call resolution in decompiler (issue #516)

Status: planned

Acceptance:
- Decompiler recognizes vtable pointer in struct/class
- Indirect calls through vtable show resolved function names
- UI allows marking struct field as vtable

### switch-recovery — Switch statement recognition (issue #2628)

Status: planned

Acceptance:
- Decompiler recognizes jump table patterns
- Produces switch/case constructs in output

### jmp-call-recovery — JMP with PUSH return address recognition (issue #5747)

Status: planned

Acceptance:
- Decompiler recognizes PUSH+JMP as CALL with return
- Control flow continues after call instead of returning

### m68k-linea-linef — M68000 lineA/lineF opcode support (issue #487)

Status: planned

Acceptance:
- Disassembler handles 0xAxxx and 0xFxxx opcodes
- Vectors at 0x0A/0x0B recognized

### cross-segment-strings — Cross-segment string display in decompiler (issue #4865)

Status: planned

Acceptance:
- String references resolved across memory segments
- Decompiler shows string literals instead of addresses

### batch-decompilation-perf — Batch decompilation performance (issue #2791)

Status: planned

Acceptance:
- Decompilation scales beyond 10 threads
- I/O bottleneck identified and mitigated

