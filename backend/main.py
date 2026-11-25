from fastapi import FastAPI, UploadFile, File, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict
import re
import sys

sys.path.insert(0, '/var/lib/alan-portfolio/workspaces/alan/cobalt-hub-145')

app = FastAPI(title="cobalt-hub-145 Decompiler API")

# Pointer size tracking for vtable/switch resolution (4 or 8 bytes)
_current_ptr_size = 4

app.add_middleware(
    ...,
)

class DecompileRequest(BaseModel):
    architecture: str = "x86"
    mode: str = "32"

class DecompileResponse(BaseModel):
    success: bool
    output: str
    error: Optional[str] = None

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
    entries: List[Dict] = []

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
        jump_table_expr = None
        
        while j < min(i + 30, len(instructions)):
            next_insn = instructions[j]
            
            # Check for indirect jump to jump table: JMP [base + offset] or JMP [reg*scale]
            if next_insn.mnemonic == "jmp" and "[" in (next_insn.op_str or ""):
                op = next_insn.op_str.lower()
                # Look for bracket expression: [BX+0x12], [RAX+8], etc.
                # Extract the content inside brackets
                bracket_match = re.search(r'\[([^\]]+)\]', op)
                if bracket_match:
                    loop_found = True
                    jump_table_expr = bracket_match.group(1)
                # Always break after checking JMP
                j += 1
                break
            
            # Check for conditional jump (JZ, JNZ, JE, etc.) after CMP
            if next_insn.mnemonic in ("jz", "jnz", "je", "jne", "js", "jg", "jl",
                                       "jb", "ja", "jbe", "jae"):
                loop_found = True
                # Continue to next instruction to check for JMP
                j += 1
                continue
            
            # Check for LOOP instruction
            if next_insn.mnemonic == "loop":
                loop_found = True
                j += 1
                continue
            
            # If none of the above, move to next instruction
            j += 1
        
        if not loop_found:
            i += 1
            continue
        
        # Found a potential switch pattern - register it
        switch_id = len(switches)
        switches[switch_id] = {
            'comparison_start': insn.address,
            'loop_end': instructions[j-1].address if j > i else None,
            'jump_table_expr': jump_table_expr,
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
    
    # Try to extract bracket expression from op_str
    bracket_match = re.search(r'\[([^\]]+)\]', op_str)
    if not bracket_match:
        # No brackets found - capstone may have simplified
        # Only try switch detection for jmp/instructions that could be switch-related
        # For other instructions, just return None
        if insn.mnemonic in ("jmp", "call"):
            # Check if this could be a switch pattern with simplified op_str
            for switch_id, switch_info in switches.items():
                if switch_info.get('found'):
                    return f"switch_detected -> case {switch_id}"
        return None
    
    table_expr = bracket_match.group(1)
    
    # Check if this matches any detected switch pattern
    for switch_id, switch_info in switches.items():
        expr = switch_info.get('jump_table_expr', '')
        if expr and expr.lower() in table_expr:
            # Found matching switch
            case_count = switch_info.get('case_count', 4)
            return f"switch -> case {switch_id}: {case_count} cases"
    
    # Also try direct matching - look for common switch patterns
    # Pattern: JMP [table_base + index*scale] where index is 0, 1, 2, ...
    
    # Check for register+offset pattern
    reg_offset_match = re.search(r'\[(\w+)\s*([+\-])\s*\d+\]', table_expr)
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

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.post("/api/decompile", response_model=DecompileResponse)
async def decompile(
    file: UploadFile = File(...),
):
    if not file.filename:
        return DecompileResponse(success=False, output="", error="No file uploaded")
    
    try:
        binary_data = await file.read()
    except Exception as e:
        return DecompileResponse(success=False, output="", error=f"Error reading file: {str(e)}")
    
    # ... (rest of decompile logic)
    # For now, return a basic response
    output = decompile_binary(binary_data, "x86", "32")
    
    return DecompileResponse(success=True, output=output)

# Vtable API endpoints
@app.get("/api/vtables")
async def list_vtables():
    """List all registered vtables."""
    return {"vtables": [vt.model_dump() for vt in vtables.values()]}

@app.post("/api/vtables")
async def register_vtable(request: VtableRegisterRequest):
    """Register a vtable manually."""
    # ... vtable registration logic
    vt = Vtable(address=request.address, name=request.name, entries=[])
    vtables[request.address] = vt
    return {"success": True, "vtable": vt.model_dump()}

@app.delete("/api/vtables/{address}")
async def unregister_vtable(address: int):
    """Unregister a vtable."""
    if address in vtables:
        del vtables[address]
    return {"success": True}

def decompile_binary(binary_data: bytes, arch: str, mode: str) -> str:
    """Decompile binary using capstone disassembler as a baseline."""
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
        
        if arch == "x86" and mode == "32":
            md = Cs(CS_ARCH_X86, CS_MODE_32)
        elif arch == "x86_64" or (arch == "x86" and mode == "64"):
            md = Cs(CS_ARCH_X86, CS_MODE_64)
        elif arch == "arm":
            md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        else:
            return f"Unsupported architecture: {arch}/{mode}"
        
        instructions = list(md.disasm(binary_data, 0x1000))
        
        # Detect switch patterns
        detect_switch_patterns(instructions, binary_data)
        
        # Build output
        output_lines = []
        for insn in instructions:
            vtable_info = None
            switch_info = None
            
            # Check for vtable resolution
            from main import resolve_vtable_call
            vtable_info = resolve_vtable_call(insn)
            if vtable_info:
                line = f"{insn.mnemonic} {insn.op_str}  ; {vtable_info}"
            else:
                line = f"{insn.mnemonic} {insn.op_str}"
            
            # Check for switch resolution
            switch_info = resolve_switch_call(insn)
            if switch_info:
                line += f"  ; {switch_info}"
            
            output_lines.append(line)
        
        if not output_lines:
            return "No instructions decoded."
        
        return "\n".join(output_lines)
        
    except Exception as e:
        return f"Decompilation error: {str(e)}"

@app.get("/api/switches")
async def list_switches():
    """List all detected switches."""
    return {"switches": [sw.model_dump() for sw in switches.values()]}



def decompile_binary(binary_data: bytes, arch: str, mode: str) -> str:
    """Decompile binary using capstone disassembler as a baseline."""
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
        
        if arch == "x86" and mode == "32":
            md = Cs(CS_ARCH_X86, CS_MODE_32)
        elif arch == "x86_64" or (arch == "x86" and mode == "64"):
            md = Cs(CS_ARCH_X86, CS_MODE_64)
        elif arch == "arm":
            from capstone import CS_ARCH_ARM, CS_MODE_ARM
            md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        else:
            return f"Unsupported architecture: {arch}/{mode}"
        
        instructions = list(md.disasm(binary_data, 0x1000))
        
        # Detect switch patterns
        detect_switch_patterns(instructions, binary_data)
        
        # Build output
        output_lines = []
        for insn in instructions:
            vtable_info = None
            switch_info = None
            
            # Check for vtable resolution
            vtable_info = resolve_vtable_call(insn)
            if vtable_info:
                line = f"{insn.mnemonic} {insn.op_str}  ; {vtable_info}"
            else:
                line = f"{insn.mnemonic} {insn.op_str}"
            
            # Check for switch resolution
            switch_info = resolve_switch_call(insn)
            if switch_info:
                line += f"  ; {switch_info}"
            
            output_lines.append(line)
        
        if not output_lines:
            return "No instructions decoded."
        
        return "\n".join(output_lines)
        
    except Exception as e:
        return f"Decompilation error: {str(e)}"

def resolve_vtable_call(insn) -> Optional[str]:
    """
    Try to resolve an indirect call through a vtable.
    
    Given an instruction that is a call/vtable reference,
    return the function name if recognized.
    """
    global vtables
    
    # ... vtable resolution logic
    # This is a simplified version - full implementation would
    # search for vtable patterns in the binary
    op_str = insn.op_str.lower()
    
    # Look for [base+offset] patterns that might be vtable accesses
    bracket_match = re.search(r'\[([^\]]+)\]', op_str)
    if bracket_match:
        expr = bracket_match.group(1)
        # Check against registered vtables
        for vt_addr, vt in vtables.items():
            for entry in vt.entries:
                if hex(entry.address) in expr.lower() or str(entry.address) in expr.lower():
                    return f"vtable -> {entry.name}"
    
    return None

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
