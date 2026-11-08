# Changelog

## 1.3.0 — work-in-progress checkpoint

Partial code published for continued development. Known issues: STATUS.md.

## 1.2.0 — work-in-progress checkpoint

Partial code published for continued development. Known issues: STATUS.md.

## [1.1.0] - 2026-11-07

### Added
- Vtable analysis feature (issue #516)
  - REST API for vtable management: GET/POST/DELETE /api/vtables
  - Vtable call resolution in decompiler for:
    - Direct memory calls: `call [0x3000]`
    - Register+offset calls (32-bit): `call [eax+8]`
    - Register+offset calls (64-bit): `call [rax+0x10]`
  - Frontend UI for registering vtables with multiple entries
  - Vtable entries display in a table with index, address, and name

### Fixed
- Backend test file syntax error

## [1.0.0] - 2026-11-07

### Added
- FastAPI/React skeleton with binary upload and decompile endpoint
- POST /api/decompile accepts binary upload and returns disassembly
- Frontend upload form with architecture/mode selection
- Support for x86 (16/32/64-bit), ARM, MIPS architectures

---

Alan Vo · [alanvo.net](https://alanvo.net) · [X: @alanvoasi](https://x.com/alanvoasi)
