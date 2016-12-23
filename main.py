from __future__ import print_function
from unicorn import *
from x86_const import *
import binascii
from keystone import * 
from capstone import *

# print status flags
def print_flags(mu):
	r_eflags = mu.reg_read(UC_X86_REG_EFLAGS)
	string_flags = ('{0:08b}'.format(r_eflags))
	string_flags = string_flags[::-1]
	# print(string_flags)
	print(">>> Carry Flag: {}".format(string_flags[UC_X86_INS_CF]))
	print(">>> Parity Flag: {}".format(string_flags[UC_X86_INS_PF]))
	print(">>> Auxiliary Carry Flag: {}".format(string_flags[UC_X86_INS_AF]))
	print(">>> Zero Flag: {}".format(string_flags[UC_X86_INS_ZF]))
	print(">>> Sign Flag: {}".format(string_flags[UC_X86_INS_SF]))
	print(">>> Trap Flag: {}".format(string_flags[UC_X86_INS_TF]))
	print(">>> Interrupt Enable Flag: {}".format(string_flags[UC_X86_INS_IF]))
	print(">>> Direction Flag: {}".format(string_flags[UC_X86_INS_DF]))
	print(">>> Overflow Flag: {}".format(string_flags[UC_X86_INS_OF]))
	print(">>> Nested Task Flag: {}".format(string_flags[UC_X86_INS_NT]))
	# print(">>> Resume Flag: {}".format(string_flags[UC_X86_INS_RF]))
	# print(">>> Virtual 8086 Mode flag {}".format(string_flags[UC_X86_INS_VM]))
# define a hook for accessing value of register
def hook_code(uc, address, size, user_data):
	print(">>> Tracing instruction at 0x%x, instruction size = %u" %(address, size))
	# get register's content
	# eax
	eax = uc.reg_read(UC_X86_REG_EAX)
	print(">>> EAX = 0x%04x" %(eax))
	# edx
	edx = uc.reg_read(UC_X86_REG_EDX)
	
	print(">>> EDX = 0x%04x" %(edx))
	# eflags
	eflags = uc.reg_read(UC_X86_REG_EFLAGS)

	print(">>> EFLAGS = 0x%04x" %(eflags))

	print_flags(eflags)

def assemble(CODE):
	try:
		ks = Ks(KS_ARCH_X86, KS_MODE_32)
		encoding, count = ks.asm(CODE)
		print("%s = %s (number of statements: %u)" % (CODE, encoding, count))
		return encoding
	except KsError as e:
		print("ERROR: %s" %e)

def binarize(code_string):
	encoding = assemble(code_string)
	sample =  binascii.hexlify(bytearray(encoding))
	# print("Sample:", sample)
	sample = binascii.a2b_hex(sample)
	return sample

def populate_registers(mu):
	# initialize machine registers
	mu.reg_write(UC_X86_REG_EAX, 0x00000000)
	mu.reg_write(UC_X86_REG_EBX, 0x00000000)
	mu.reg_write(UC_X86_REG_ECX, 0x00000000)
	mu.reg_write(UC_X86_REG_EDX, 0x00000000)
	mu.reg_write(UC_X86_REG_EFLAGS, 0xFFFF)

def emulate(sample):
	md = Cs(CS_ARCH_X86, CS_MODE_32)

	mu = Uc(UC_ARCH_X86, UC_MODE_32)

	# map 2MB memory for this emulation
	mu.mem_map(ADDRESS, 2 * 1024 * 1024)
	# code_32 = b"\x0c\x01"
	# write machine code to be emulated to memory
	mu.mem_write(ADDRESS, sample)

	populate_registers(mu)

	try:
    # emulate machine code in infinite time
	    mu.emu_start(ADDRESS, ADDRESS + len(sample))
	except UcError as e:
	    #print("ERROR: %s" % e)
	    pass
	return mu    

def print_registers(mu):
	print(">>> Emulation done. Below is the CPU context")

	r_eax = mu.reg_read(UC_X86_REG_EAX)
	print(">>> EAX = 0x%04x" %r_eax)
	r_ebx = mu.reg_read(UC_X86_REG_EBX)
	print(">>> EBX = 0x%04x" %r_ebx)
	r_ecx = mu.reg_read(UC_X86_REG_ECX)
	print(">>> ECX = 0x%04x" %r_ecx)
	r_edx = mu.reg_read(UC_X86_REG_EDX)
	print(">>> EDX = 0x%04x" %r_edx)
	r_esp = mu.reg_read(UC_X86_REG_ESP)
	print(">>> ESP = 0x%04x" %r_esp)
	r_ebp = mu.reg_read(UC_X86_REG_EBP)
	print(">>> EBP = 0x%04x" %r_ebp)
	r_eip = mu.reg_read(UC_X86_REG_EIP)
	print(">>> EIP = 0x%04x" %r_eip)	
	r_eflags = mu.reg_read(UC_X86_REG_EFLAGS)
	print(">>> EFlags = 0x%04x" %r_eflags)

# memory address where emulation starts
ADDRESS = 0x1000000

CODE = b"mov ax, 3; mov cx, 3; cmp cx, ax"
code_string = CODE.split(';')

for cs in code_string:

	sample = binarize(cs)

	mu = emulate(sample)

	print_registers(mu)

	print_flags(mu)