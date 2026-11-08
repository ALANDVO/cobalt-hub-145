from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict
import subprocess
import tempfile
import os
import re

app = FastAPI(title="cobalt-hub-145 Decompiler API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class DecompileRequest(BaseModel):
    architecture: str = "x86"
    mode: str = "32"

class DecompileResponse(BaseModel):
    success: bool
    output: str
    error: Optional[str] = None

# Vtable models
class VtableEntry(BaseModel):
    index: int
    address: int
    name: Optional[str] = None

class Vtable(BaseModel):
    address: int
    name: Optional[str] = None
    entries: List[VtableEntry] = []

class VtableRegisterRequest(BaseModel):
    address: int
    name: Optional[str] = None
    entries: List[Dict] = []  # [{"index": 0, "address": 0x1234, "name": "func1"}, ...]

# In-memory vtable registry
vtables: Dict[int, Vtable] = {}

# Global to track current architecture for vtable resolution
_current_ptr_size = 4

def decompile_binary(binary_data: bytes, arch: str, mode: str) -> str:
    """Decompile binary using capstone disassembler as a baseline."""
    global _current_ptr_size
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_ARCH_ARM, CS_MODE_ARM, CS_ARCH_MIPS, CS_MODE_MIPS32
        
        arch_map = {
            "x86": CS_ARCH_X86,
            "arm": CS_ARCH_ARM,
            "mips": CS_ARCH_MIPS,
        }
        mode_map = {
            "16": CS_MODE_32,  # fallback
            "32": CS_MODE_32,
            "64": CS_MODE_64,
            "arm": CS_MODE_ARM,
            "mips32": CS_MODE_MIPS32,
        }
        
        cs_arch = arch_map.get(arch.lower(), CS_ARCH_X86)
        cs_mode = mode_map.get(mode.lower(), CS_MODE_32)
        
        # Set pointer size based on mode
        if mode == "64":
            _current_ptr_size = 8
        else:
            _current_ptr_size = 4
        
        md = Cs(cs_arch, cs_mode)
        md.detail = True
        
        instructions = list(md.disasm(binary_data, 0x1000))
        
        # Detect potential vtables (arrays of pointers to code)
        detect_vtables(instructions, binary_data)
        
        output_lines = []
        for insn in instructions:
            line = f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}"
            # Check for indirect calls that might use vtables
            if insn.mnemonic in ("call", "jmp") and "[" in insn.op_str:
                vtable_info = resolve_vtable_call(insn)
                if vtable_info:
                    line += f"  ; {vtable_info}"
            output_lines.append(line)
        
        if not output_lines:
            return "No instructions decoded."
        
        return "\n".join(output_lines)
    except Exception as e:
        return f"Decompilation error: {str(e)}"

def detect_vtables(instructions, binary_data: bytes):
    """Detect potential vtables in the binary data."""
    # Simple heuristic: look for arrays of pointers that point to code addresses
    global _current_ptr_size
    data_start = 0x1000
    data_len = len(binary_data)
    ptr_size = _current_ptr_size
    
    # Scan for pointer arrays (potential vtables)
    for offset in range(0, data_len - ptr_size * 2, ptr_size):
        if offset + ptr_size * 2 > data_len:
            break
        # Read two consecutive pointers
        ptr1 = int.from_bytes(binary_data[offset:offset+ptr_size], 'little')
        ptr2 = int.from_bytes(binary_data[offset+ptr_size:offset+ptr_size*2], 'little')
        
        # Heuristic: both pointers point within the code section
        if (0x1000 <= ptr1 < 0x1000 + data_len and 
            0x1000 <= ptr2 < 0x1000 + data_len):
            vtable_addr = data_start + offset
            if vtable_addr not in vtables:
                vt = Vtable(address=vtable_addr, name=f"vtable_{vtable_addr:x}")
                # Add first few entries
                for i in range(0, min(20, (data_len - offset) // ptr_size), ptr_size):
                    if offset + i + ptr_size <= data_len:
                        ptr = int.from_bytes(binary_data[offset+i:offset+i+ptr_size], 'little')
                        if 0x1000 <= ptr < 0x1000 + data_len:
                            vt.entries.append(VtableEntry(index=len(vt.entries), address=ptr))
                if vt.entries:
                    vtables[vtable_addr] = vt

def resolve_vtable_call(insn) -> Optional[str]:
    """Try to resolve an indirect call through a vtable."""
    global _current_ptr_size
    op_str = insn.op_str
    
    # Pattern 1: call [absolute_address] - direct memory call
    # e.g., call dword ptr [0x3000]
    match = re.search(r'(?:qword|dword|word|byte)?\s*ptr\s*\[\s*0x([0-9a-f]+)\s*\]', op_str, re.IGNORECASE)
    if match:
        addr = int(match.group(1), 16)
        # Check if this address is a known vtable
        if addr in vtables:
            vt = vtables[addr]
            if vt.entries:
                entry = vt.entries[0]
                name = entry.name or f"sub_{entry.address:x}"
                return f"vtable call -> {vt.name}[0] = {name} (0x{entry.address:x})"
        # Check if address points to a vtable entry
        for vt_addr, vt in vtables.items():
            for entry in vt.entries:
                if entry.address == addr:
                    name = entry.name or f"sub_{entry.address:x}"
                    return f"vtable call -> {vt.name}[{entry.index}] = {name} (0x{entry.address:x})"
    
    # Pattern 2: call [reg+offset] - register+offset (common for vtable calls)
    # e.g., call dword ptr [eax+0x18], call [rbx+8], call qword ptr [rax+0x20]
    # Capture offset with optional 0x prefix
    match = re.search(r'(?:qword|dword|word|byte)?\s*ptr\s*\[\s*(\w+)\s*\+\s*(0x[0-9a-f]+|[0-9a-f]+)\s*\]', op_str, re.IGNORECASE)
    if match:
        reg = match.group(1).lower()
        offset_str = match.group(2)
        # Parse offset - hex if 0x prefix, else decimal
        try:
            if offset_str.startswith(('0x', '0X')):
                offset = int(offset_str, 16)
            else:
                offset = int(offset_str)
        except ValueError:
            offset = 0
        
        # Check vtable entries - prefer current pointer size
        best_match = None
        for vt_addr, vt in vtables.items():
            for entry in vt.entries:
                if entry.index * _current_ptr_size == offset:
                    best_match = (vt, entry)
                    break
                elif entry.index * (8 if _current_ptr_size == 4 else 4) == offset and best_match is None:
                    best_match = (vt, entry)
            if best_match:
                break
        
        if best_match:
            vt, entry = best_match
            name = entry.name or f"sub_{entry.address:x}"
            return f"possible vtable call: {vt.name}[{entry.index}] = {name} @ offset 0x{offset:x}"
        return f"possible vtable call (reg={reg}, offset=0x{offset:x})"
    
    # Pattern 3: call [reg] - register indirect
    match = re.search(r'(?:qword|dword|word|byte)?\s*ptr\s*\[\s*(\w+)\s*\]', op_str, re.IGNORECASE)
    if match:
        reg = match.group(1).lower()
        return f"indirect call via {reg} (possible vtable)"
    
    return None

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.post("/api/decompile", response_model=DecompileResponse)
async def decompile(
    file: UploadFile = File(...),
    architecture: str = "x86",
    mode: str = "32"
):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    
    binary_data = await file.read()
    if len(binary_data) == 0:
        raise HTTPException(status_code=400, detail="Empty file")
    
    if len(binary_data) > 10 * 1024 * 1024:  # 10MB limit
        raise HTTPException(status_code=400, detail="File too large (max 10MB)")
    
    output = decompile_binary(binary_data, architecture, mode)
    
    return DecompileResponse(success=True, output=output)

# Vtable API endpoints
@app.get("/api/vtables")
async def list_vtables():
    """List all registered vtables."""
    return {"vtables": [vt.model_dump() for vt in vtables.values()]}

@app.post("/api/vtables")
async def register_vtable(request: VtableRegisterRequest):
    """Register a vtable manually."""
    vt = Vtable(address=request.address, name=request.name)
    for entry in request.entries:
        vt.entries.append(VtableEntry(**entry))
    vtables[request.address] = vt
    return {"success": True, "vtable": vt.model_dump()}

@app.delete("/api/vtables/{address}")
async def unregister_vtable(address: int):
    """Unregister a vtable."""
    if address not in vtables:
        raise HTTPException(status_code=404, detail="Vtable not found")
    del vtables[address]
    return {"success": True}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
