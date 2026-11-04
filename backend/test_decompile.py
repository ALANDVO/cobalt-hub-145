import sys
sys.path.insert(0, "/var/lib/alan-portfolio/workspaces/alan/cobalt-hub-145/backend")

from main import decompile_binary

# Test with x86 32-bit: push ebp; mov ebp, esp; pop ebp; ret
test_bytes = b"\x55\x89\xe5\x5d\xc3"
result = decompile_binary(test_bytes, "x86", "32")
print("Test 1 - x86 32-bit:")
print(result)
print()

# Test with x86_64: push rbp; mov rbp, rsp; pop rbp; ret
test_bytes_64 = b"\x55\x48\x89\xe5\x5d\xc3"
result_64 = decompile_binary(test_bytes_64, "x86", "64")
print("Test 2 - x86 64-bit:")
print(result_64)
print()

# Test ARM
test_bytes_arm = b"\x00\x00\x50\xe3"  # mov r0, #0
result_arm = decompile_binary(test_bytes_arm, "arm", "arm")
print("Test 3 - ARM:")
print(result_arm)
</arg_key>
<arg_key=i>
Write test script
