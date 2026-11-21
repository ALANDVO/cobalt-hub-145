from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict
import subprocess
import tempfile
import os
import re

app = FastAPI(title="cobalt-hub-145 Decompiler API")

# Pointer size tracking for vtable/switch resolution (4 or 8 bytes)
_current_ptr_size = 4

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

# Switch models
class SwitchEntry(BaseModel):
    index: int
    address: int
    name: Optional[str] = None

class Switch(BaseModel):
    address: int
    name: Optional[str] = None
    entries: List[SwitchEntry] = []

# In-memory switch registry
switches: Dict[int, Switch] = {}
vtables: Dict[int, Vtable] = {}
def detect_switch_patterns(instructions, binary_data: bytes):
    """
    Detect potential switch/jump table patterns in the binary data.
    
    Based on issue #2628: recognizes switch statements that use a comparison
    loop against an array, followed by an indirect jump through a jump table.
    
    Pattern heuristic:
    1. Look for a loop that compares a register/value against consecutive memory values
    2. Look for a subsequent indirect jump/jmp [base + index*size + offset]
    3. If pattern matches, register the switch and return its ID
    """
    global switches, _current_ptr_size
    
    ptr_size = _current_ptr_size
    data_len = len(binary_data)
    
    # Build a map of instruction addresses to instructions for lookup
    insn_map = {}
    for insn in instructions:
        insn_map[insn.address] = insn
    
    # Heuristic 1: Look for comparison loops (CMP followed by conditional jump/JZ/LOOP)
    # Pattern: CMP reg, [array+offset] / JZ / LOOP / JMP [table+index*scale]
    
    switch_ids = []
    i = 0
    while i < len(instructions) - 3:
        insn = instructions[i]
        
        # Look for CMP instruction comparing a register to a memory value
        if insn.mnemonic not in ("cmp",):
            i += 1
            continue
        
        op_str = insn.op_str.lower()
        
        # Look for pattern: CMP AX, [some_array] or CMP reg, [base+offset]
        array_refs = re.findall(r'\[([^\]]+)\]', op_str)
        
        if not array_refs:
            i += 1
            continue
        
        # Check if next instructions form a loop pattern
        j = i + 1
        loop_found = False
        
        while j < min(i + 30, len(instructions)):
            next_insn = instructions[j]
            
            # Check for conditional jump (JZ, JNZ, JE, etc.) after CMP
            if next_insn.mnemonic in ("jz", "jnz", "je", "jne", "js", "jg", "jl",
                                       "jb", "ja", "jbe", "jae"):
                loop_found = True
                j += 1
                break
            
            # Check for LOOP instruction
            if next_insn.mnemonic == "loop":
                loop_found = True
                j += 1
                break
            
            # Check for indirect jump to jump table: JMP [base + index*scale]
            if next_insn.mnemonic == "jmp" and "[" in (next_insn.op_str or ""):
                op = next_insn.op_str.lower()
                # Pattern: JMP [BX+0x12] or JMP [RAX+8] or JMP [BX+SI*2]
                if re.search(r'\[[^\]]+\+\s*[0-9a-fx]+\s*\]', op) or re.search(r'\[[a-z]+\s*\*\s*[0-9]', op):
                    loop_found = True
                    j += 1
                    break
            
            j += 1
        
        if not loop_found:
            i += 1
            continue
        
        # Found a potential switch pattern - register it
        switch_id = len(switches)
        switches[switch_id] = {
            'comparison_start': insn.address,
            'loop_end': instructions[j-1].address if j > i else None,
            'found': True,
        }
        switch_ids.append(switch_id)
        
        i = j  # Skip past this pattern
    
    return switch_ids

def resolve_switch_call(insn) -> Optional[str]:
    """
    Try to resolve an indirect jump/call through a switch table.
    
    Given an instruction that is a jump through a switch table,
    return the switch case information if recognized.
    """
    global switches
    
    op_str = insn.op_str.lower()
    
    # Check for jump table pattern in op_str
    # Patterns we look for:
    # - [BX+0x12] - base register with offset
    # - [rax+8] - register with offset
    # - [table+index*8] - table base with indexed offset
    
    table_base_match = re.search(r'\[([a-z0-9+\*\s\.]+)\]', op_str)
    if not table_base_match:
        return None
    
    table_expr = table_base_match.group(1)
    
    # Check if this matches any detected switch pattern
    for switch_id, switch_info in switches.items():
        expr = switch_info.get('jump_table_expr', '')
        if expr and expr in table_expr:
            # Found matching switch
            case_count = switch_info.get('case_count', 4)
            return f"switch -> case {switch_id}: {case_count} cases"
    
    # Also try direct matching - look for common switch patterns
    # Pattern: JMP [table_base + index*scale] where index is 0, 1, 2, ...
    
    # Check for register+offset pattern
    reg_offset_match = re.search(r'\[(\w+)\s*([+\-]\s*\d+)\]', table_expr)
    if reg_offset_match:
        reg = reg_offset_match.group(1)
        offset = reg_offset_match.group(2)
        return f"switch_indirect -> [{reg}{offset}]"
    
    # Check for pure offset pattern [0xNNNN]
    abs_match = re.search(r'\[0x([0-9a-f]+)\]', table_expr)
    if abs_match:
        addr = int(abs_match.group(1), 16)
        return f"switch_jump_table -> 0x{addr:x}"
    
    return None

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
        # Detect potential switch patterns (jump tables)
        detect_switch_patterns(instructions, binary_data)
        
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
