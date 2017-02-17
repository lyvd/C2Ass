# C2Ass

1. This tool is for learning assembly code. Using this one we can
- Understand what is going on when we execute an instruction such as: register changes, status flag changes

This tool uses Keystone engine to assemble an assembly code and Unicorn engine for code simulation
2. How to use this tool
Let's run a python script called main.py with an option called -c following by a instruction(s) you want to examine 


Instruction: mov ax, 0083h = [102, 184, 131, 0] (number of statements: 1)
>>> Before instruction at 0x1000000, instruction size = 4
Registers
- EAX = 0x00000000 (0)
- EBX = 0x00000000 (0)
- ECX = 0x00000000 (0)
- EDX = 0x00000000 (0)
- ESI = 0x00000000 (0)
- EDI = 0x00000000 (0)
- ESP = 0x01002000 (16785408)
- EBP= 0x00000000 (0)
- EFLAGS = 0x00000000 (0)
- EIP = 0x01000000 (16777216)
Flags
- Carry Flag: 0
- Parity Flag: 0
- Auxiliary Carry Flag: 0
- Zero Flag: 0
- Sign Flag: 0
- Overflow Flag: 0
>>> After executing the instrution
- EAX = 0x00000083 (131)
- EBX = 0x00000000 (0)
- ECX = 0x00000000 (0)
- EDX = 0x00000000 (0)
- ESP = 0x01002000 (16785408)
- EBP = 0x00000000 (0)
- EIP = 0x01000004 (16777220)
- ESI = 0x00000000 (0)
- EDI = 0x00000000 (0)
- EFLAGS = 0x00000000 (0)
Flags
- Carry Flag: 0
- Parity Flag: 0
- Auxiliary Carry Flag: 0
- Zero Flag: 0
- Sign Flag: 0
- Overflow Flag: 0
Instruction:  mov bl, 2 = [179, 2] (number of statements: 1)
>>> Before instruction at 0x1000000, instruction size = 2
Registers
- EAX = 0x00000083 (131)
- EBX = 0x00000000 (0)
- ECX = 0x00000000 (0)
- EDX = 0x00000000 (0)
- ESI = 0x00000000 (0)
- EDI = 0x00000000 (0)
- ESP = 0x01002000 (16785408)
- EBP= 0x00000000 (0)
- EFLAGS = 0x00000000 (0)
- EIP = 0x01000000 (16777216)
Flags
- Carry Flag: 0
- Parity Flag: 0
- Auxiliary Carry Flag: 0
- Zero Flag: 0
- Sign Flag: 0
- Overflow Flag: 0
>>> After executing the instrution
- EAX = 0x00000083 (131)
- EBX = 0x00000002 (2)
- ECX = 0x00000000 (0)
- EDX = 0x00000000 (0)
- ESP = 0x01002000 (16785408)
- EBP = 0x00000000 (0)
- EIP = 0x01000002 (16777218)
- ESI = 0x00000000 (0)
- EDI = 0x00000000 (0)
- EFLAGS = 0x00000000 (0)
Flags
- Carry Flag: 0
- Parity Flag: 0
- Auxiliary Carry Flag: 0
- Zero Flag: 0
- Sign Flag: 0
- Overflow Flag: 0
Instruction:  div bl = [246, 243] (number of statements: 1)
>>> Before instruction at 0x1000000, instruction size = 2
Registers
- EAX = 0x00000083 (131)
- EBX = 0x00000002 (2)
- ECX = 0x00000000 (0)
- EDX = 0x00000000 (0)
- ESI = 0x00000000 (0)
- EDI = 0x00000000 (0)
- ESP = 0x01002000 (16785408)
- EBP= 0x00000000 (0)
- EFLAGS = 0x00000000 (0)
- EIP = 0x01000000 (16777216)
Flags
- Carry Flag: 0
- Parity Flag: 0
- Auxiliary Carry Flag: 0
- Zero Flag: 0
- Sign Flag: 0
- Overflow Flag: 0
>>> After executing the instrution
- EAX = 0x00000141 (321)
- EBX = 0x00000002 (2)
- ECX = 0x00000000 (0)
- EDX = 0x00000000 (0)
- ESP = 0x01002000 (16785408)
- EBP = 0x00000000 (0)
- EIP = 0x01000002 (16777218)
- ESI = 0x00000000 (0)
- EDI = 0x00000000 (0)
- EFLAGS = 0x00000000 (0)
Flags
- Carry Flag: 0
- Parity Flag: 0
- Auxiliary Carry Flag: 0
- Zero Flag: 0
- Sign Flag: 0
- Overflow Flag: 0
