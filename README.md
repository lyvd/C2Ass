# C2Ass

1. This tool is for learning assembly code. Using this one we can
- Understand what is going on when we execute an instruction such as: register changes, status flag changes

This tool uses Keystone engine to assemble an assembly code and Unicorn engine for code simulation
2. How to use this tool
Let's run a python script called main.py with an option called -c following by a instruction(s) you want to examine 

python main.py -c "mov eax, 1; cmp eax, 1"

mov eax, 1 = [184, 1, 0, 0, 0] number of statements: 1)
Emulation done. Below is the CPU context
EAX = 0x0001
 EBX = 0x0000
 ECX = 0x0000
 EDX = 0x0000
 ESP = 0x0000
 EBP = 0x0000
 EIP = 0x1000005
 EFlags = 0xffff
 Carry Flag: 1
 Parity Flag: 1
 Auxiliary Carry Flag: 1
 Zero Flag: 1
 Sign Flag: 1
 Trap Flag: 1
 Interrupt Enable Flag: 1
 Direction Flag: 1
 Overflow Flag: 1
 Nested Task Flag: 1
 cmp eax, 1 = [131, 248, 1](number of statements: 1)
 Emulation done. Below is the CPU context
 EAX = 0x0000
 EBX = 0x0000
 ECX = 0x0000
 EDX = 0x0000
 ESP = 0x0000
 EBP = 0x0000
 EIP = 0x1000003
 EFlags = 0xf7bf
 Carry Flag: 1
 Parity Flag: 1
 Auxiliary Carry Flag: 1
 Zero Flag: 0
 Sign Flag: 1
 Trap Flag: 1
 Interrupt Enable Flag: 1
 Direction Flag: 1
 Overflow Flag: 0
 Nested Task Flag: 1
