import sys
sys.path.insert(0, "/var/lib/alan-portfolio/workspaces/alan/cobalt-hub-145/backend")

from main import decompile_binary, vtables, Vtable, VtableEntry

# Create a test binary with a vtable-like pattern
# Code section starts at 0x1000
# We'll create: function1 (0x1000), function2 (0x1010), vtable at 0x2000 pointing to both

# Simple x86_64 functions: push rbp; mov rbp, rsp; pop rbp; ret
func1 = b"\x55\x48\x89\xe5\x5d\xc3"  # at 0x1000
func2 = b"\x55\x48\x89\xe5\x5d\xc3"  # at 0x1010 (just reuse same bytes)

# Vtable: two 64-bit pointers to func1 and func2
# Addresses are relative to base 0x1000
vtable_data = b"\x00\x10\x00\x00\x00\x00\x00\x00"  # 0x1000 (func1)
vtable_data += b"\x10\x10\x00\x00\x00\x00\x00\x00"  # 0x1010 (func2)

# Full binary: code + vtable
binary = func1 + func2 + b"\x00" * 4 + vtable_data  # pad to 0x2000 offset

print(f"Binary length: {len(binary)} bytes")
print(f"Func1 at offset 0 (0x1000)")
print(f"Func2 at offset 6 (0x1006)")  
print(f"Vtable at offset 16 (0x1010)")

result = decompile_binary(binary, "x86", "64")
print("\n=== Decompilation Result ===")
print(result)

print("\n=== Detected Vtables ===")
for addr, vt in vtables.items():
    print(f"Vtable at 0x{addr:x} ({vt.name}):")
    for entry in vt.entries:
        print(f"  [{entry.index}] -> 0x{entry.address:x}")

# Now test manual vtable registration and call resolution
print("\n=== Testing Call Resolution ===")

# Register a vtable manually
from main import register_vtable, VtableRegisterRequest
import asyncio

# Test the resolve_vtable_call function directly
from main import resolve_vtable_call
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# Test instruction: call qword ptr [rax+0x10] - should match vtable[2] (index 2 * 8 = 16)
# But our vtable only has 2 entries (indices 0, 1)
# Let's create a test instruction
test_insn = type('obj', (object,), {
    'mnemonic': 'call',
    'op_str': 'qword ptr [rax+0x10]',
    'address': 0x3000
})()

# Register a vtable with 3 entries for testing
vt = Vtable(address=0x2000, name="test_vtable")
vt.entries = [
    VtableEntry(index=0, address=0x1000, name="func1"),
    VtableEntry(index=1, address=0x1010, name="func2"),
    VtableEntry(index=2, address=0x1020, name="func3"),
]
vtables[0x2000] = vt

# Test with offset 0x10 (index 2 * 8 = 16)
result = resolve_vtable_call(test_insn)
print(f"call [rax+0x10] -> {result}")

# Test with offset 0x8 (index 1 * 8 = 8)
test_insn.op_str = 'qword ptr [rax+0x8]'
result = resolve_vtable_call(test_insn)
print(f"call [rax+0x8] -> {result}")

# Test with offset 0x0 (index 0)
test_insn.op_str = 'qword ptr [rax]'
result = resolve_vtable_call(test_insn)
print(f"call [rax] -> {result}")

# Test absolute address call
test_insn2 = type('obj', (object,), {
    'mnemonic': 'call',
    'op_str': 'qword ptr [0x1010]',
    'address': 0x3010
})()
result = resolve_vtable_call(test_insn2)
print(f"call [0x1010] -> {result}")

