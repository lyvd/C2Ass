from __future__ import print_function
from unicorn import *
from x86_const import *
import binascii
from keystone import * 
from capstone import *

# memory address where emulation starts
ADDRESS = 0x1000000

CODE = b"mov eax, 0Ah; and eax, 80000003h; dec eax; or eax, 0FFFFFFFCh; inc eax"

try:
	ks = Ks(KS_ARCH_X86, KS_MODE_32)
	encoding, count = ks.asm(CODE)
	print("%s = %s (number of statements: %u)" % (CODE, encoding, count))
except KsError as e:
	print("ERROR: %s" %e)


sample =  binascii.hexlify(bytearray(encoding))
sample = binascii.a2b_hex(sample)

md = Cs(CS_ARCH_X86, CS_MODE_32)
print("Disassemble")
for i in md.disasm(sample, 0x1000):
	print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

mu = Uc(UC_ARCH_X86, UC_MODE_32)

# map 2MB memory for this emulation
mu.mem_map(ADDRESS, 2 * 1024 * 1024)

# write machine code to be emulated to memory
mu.mem_write(ADDRESS, sample)

# initialize machine registers
mu.reg_write(UC_X86_REG_EAX, 0x1234)
mu.reg_write(UC_X86_REG_EFLAGS, 0x0000)


# intercept invalid memory events

try:
    # emulate machine code in infinite time
    mu.emu_start(ADDRESS, ADDRESS + len(sample))
except UcError as e:
    print("ERROR: %s" % e)

# now print out some registers
print(">>> Emulation done. Below is the CPU context")

r_eax = mu.reg_read(UC_X86_REG_EAX)
r_eflags = mu.reg_read(UC_X86_REG_EFLAGS)
print(">>> EAX = 0x%04x" %r_eax)
print(">>> EFlags = 0x04%x" %r_eflags)

