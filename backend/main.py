
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import subprocess
import tempfile
import os

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

def decompile_binary(binary_data: bytes, arch: str, mode: str) -> str:
    """Decompile binary using capstone disassembler as a baseline."""
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
        
        md = Cs(cs_arch, cs_mode)
        md.detail = True
        
        output_lines = []
        for insn in md.disasm(binary_data, 0x1000):
            output_lines.append(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")
        
        if not output_lines:
            return "No instructions decoded."
        
        return "\n".join(output_lines)
    except Exception as e:
        return f"Decompilation error: {str(e)}"

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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
