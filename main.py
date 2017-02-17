
from __future__ import print_function
from unicorn import *
from x86_const import *
import binascii
from keystone import * 
from capstone import *
import argparse


# Create  a global list of mu 

mu_dict = {
"UC_X86_REG_EAX": 0x00000000,
 "UC_X86_REG_EBX": 0x00000000,
 "UC_X86_REG_ECX": 0x00000000,
 "UC_X86_REG_EDX": 0x00000000, 
 "UC_X86_REG_ESI": 0x00000000, 
 "UC_X86_REG_EDI": 0x00000000, 
 "UC_X86_REG_ESP" : 0x00000000,
  "UC_X86_REG_EBP": 0x00000000,
  "UC_X86_REG_EIP": 0x00000000,
  "UC_X86_REG_EFLAGS": 0x00000000}

ks_syntax = ""
# print status flags
# print status flags
def print_flags(r_eflags):
	#r_eflags = mu.reg_read(UC_X86_REG_EFLAGS)
	string_flags = ('{0:016b}'.format(r_eflags))
	string_flags = string_flags[::-1]
	# print(string_flags)
	print("Flags")
	print("- Carry Flag: {}".format(string_flags[UC_X86_INS_CF]))
	print("- Parity Flag: {}".format(string_flags[UC_X86_INS_PF]))
	print("- Auxiliary Carry Flag: {}".format(string_flags[UC_X86_INS_AF]))
	print("- Zero Flag: {}".format(string_flags[UC_X86_INS_ZF]))
	print("- Sign Flag: {}".format(string_flags[UC_X86_INS_SF]))
	#print(">>> Overflow Flag: {}".format(string_flags[UC_X86_INS_OF]))
	# print(">>> Trap Flag: {}".format(string_flags[UC_X86_INS_TF]))
	# print(">>> Interrupt Enable Flag: {}".format(string_flags[UC_X86_INS_IF]))
	# print(">>> Direction Flag: {}".format(string_flags[UC_X86_INS_DF]))
	print(">>> Overflow Flag: {}".format(string_flags[UC_X86_INS_OF]))
	# print(">>> Nested Task Flag: {}".format(string_flags[UC_X86_INS_NT]))
	# print(">>> Resume Flag: {}".format(string_flags[UC_X86_INS_RF]))
	# print(">>> Virtual 8086 Mode flag {}".format(string_flags[UC_X86_INS_VM]))


def hook_code(uc, address, size, user_data):
	global mu_dict

	#print("Before executing the instruction")
	print(">>> Before instruction at 0x%x, instruction size = %u" %(address, size))
	# get register's content
	# eax
	print("Registers")
	eax = uc.reg_read(UC_X86_REG_EAX)
	print("- EAX = 0x%08x (%d)" %(eax, int(eax)))

	ebx = uc.reg_read(UC_X86_REG_EBX)
	print("- EBX = 0x%08x (%d)" %(ebx, int(ebx)))

	ecx = uc.reg_read(UC_X86_REG_ECX)
	print("- ECX = 0x%08x (%d)" %(ecx, int(ecx)))

	# edx
	edx = uc.reg_read(UC_X86_REG_EDX)
	print("- EDX = 0x%08x (%d)" %(edx, int(edx)))

	# esi
	esi = uc.reg_read(UC_X86_REG_ESI)
	print("- ESI = 0x%08x (%d)" %(esi, int(esi)))

	# edi
	edi = uc.reg_read(UC_X86_REG_EDI)
	print("- EDI = 0x%08x (%d)" %(edi, int(edi)))

	# esp
	esp = uc.reg_read(UC_X86_REG_ESP)
	print("- ESP = 0x%08x (%d)" %(esp, int(esp)))

	# ebp
	ebp = uc.reg_read(UC_X86_REG_EBP)
	print("- EBP= 0x%08x (%d)" %(ebp, int(ebp)))

	# eflags
	eflags = uc.reg_read(UC_X86_REG_EFLAGS)
	print("- EFLAGS = 0x%08x (%d)" %(eflags, int(eflags)))

	# eflags
	eip = uc.reg_read(UC_X86_REG_EIP)

	print("- EIP = 0x%08x (%d)" %(eip, int(eip)))

	print_flags(mu_dict["UC_X86_REG_EFLAGS"])
	#print_flags(uc)

def assemble(CODE):
	global ks_syntax
	try:
		ks = Ks(KS_ARCH_X86, KS_MODE_32)
		if(ks_syntax == "KS_OPT_SYNTAX_ATT"):
			ks.syntax = KS_OPT_SYNTAX_ATT
		encoding, count = ks.asm(CODE)
		print("Instruction: %s = %s (number of statements: %u)" % (CODE, encoding, count))
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

def update_registers(mu):
	global mu_dict

 	mu_dict["UC_X86_REG_EAX"] = mu.reg_read(UC_X86_REG_EAX)
 	mu_dict["UC_X86_REG_EBX"] = mu.reg_read(UC_X86_REG_EBX)
 	mu_dict["UC_X86_REG_ECX"] = mu.reg_read(UC_X86_REG_ECX)
 	mu_dict["UC_X86_REG_EDX"] = mu.reg_read(UC_X86_REG_EDX)
 	mu_dict["UC_X86_REG_ESI"] = mu.reg_read(UC_X86_REG_ESI)
 	mu_dict["UC_X86_REG_EDI"] = mu.reg_read(UC_X86_REG_EDI)
 	mu_dict["UC_X86_REG_ESP"] = mu.reg_read(UC_X86_REG_ESP)
 	mu_dict["UC_X86_REG_EBP"] = mu.reg_read(UC_X86_REG_EBP)
 	mu_dict["UC_X86_REG_EIP"] = mu.reg_read(UC_X86_REG_EIP)
 	mu_dict["UC_X86_REG_EFLAGS"] = mu.reg_read(UC_X86_REG_EFLAGS)


def emulate(sample):

	# memory address where emulation starts
	ADDRESS = 0x1000000

	md = Cs(CS_ARCH_X86, CS_MODE_32)

	mu = Uc(UC_ARCH_X86, UC_MODE_32)

	# map 2MB memory for this emulation
	mu.mem_map(ADDRESS, 2 * 1024 * 1024)
	# code_32 = b"\x0c\x01"
	# write machine code to be emulated to memory
	mu.mem_write(ADDRESS, sample)

	#populate_registers(mu)
	mu.reg_write(UC_X86_REG_EAX, mu_dict["UC_X86_REG_EAX"])
	mu.reg_write(UC_X86_REG_EBX, mu_dict["UC_X86_REG_EBX"])
	mu.reg_write(UC_X86_REG_ECX, mu_dict["UC_X86_REG_ECX"])
	mu.reg_write(UC_X86_REG_EDX, mu_dict["UC_X86_REG_EDX"])
	mu.reg_write(UC_X86_REG_ESI, mu_dict["UC_X86_REG_ESI"])
	mu.reg_write(UC_X86_REG_EDI, mu_dict["UC_X86_REG_EDI"])
	mu.reg_write(UC_X86_REG_ESP, mu_dict["UC_X86_REG_ESP"])
	mu.reg_write(UC_X86_REG_EBP, mu_dict["UC_X86_REG_EBP"])
	mu.reg_write(UC_X86_REG_EIP, mu_dict["UC_X86_REG_EIP"])
	mu.reg_write(UC_X86_REG_EFLAGS, mu_dict["UC_X86_REG_EFLAGS"])
	mu.hook_add(UC_HOOK_CODE, hook_code)

	# setup stack
	mu.reg_write(UC_X86_REG_ESP, ADDRESS + 0x2000)
	try:
    # emulate machine code in infinite time
	    mu.emu_start(ADDRESS, ADDRESS + len(sample))
	except UcError as e:
	    #print("ERROR: %s" % e)
	    pass
	return mu    

def print_registers(mu):
	global mu_dict
	print(">>> After executing the instrution")
	eax = mu_dict["UC_X86_REG_EAX"]
	print("- EAX = 0x%08x (%d)" %(eax,int(eax)))
	ebx = mu_dict["UC_X86_REG_EBX"]
	print("- EBX = 0x%08x (%d)" %(ebx, int(ebx)))
	ecx = mu_dict["UC_X86_REG_ECX"]
	print("- ECX = 0x%08x (%d)" % (ecx, int(ecx)))
	edx = mu_dict["UC_X86_REG_EDX"]
	print("- EDX = 0x%08x (%d)" %(edx, int(edx)))
	esp = mu_dict["UC_X86_REG_ESP"]
	print("- ESP = 0x%08x (%d)" % (esp, int(esp)))
	ebp = mu_dict["UC_X86_REG_EBP"]
	print("- EBP = 0x%08x (%d)" % (ebp, int(ebp)))
	eip = mu_dict["UC_X86_REG_EIP"]
	print("- EIP = 0x%08x (%d)" % (eip, int(eip)))
	esi = mu_dict["UC_X86_REG_ESI"]
	print("- ESI = 0x%08x (%d)" % (esi, int(esi)))
	edi = mu_dict["UC_X86_REG_EDI"]
	print("- EDI = 0x%08x (%d)" % (edi, int(edi)))
	eflags = mu_dict["UC_X86_REG_EFLAGS"]
	print("- EFLAGS = 0x%08x (%d)" % (eflags, int(eflags)))
	print_flags(eflags)



def parse_arguments():
    parser = argparse.ArgumentParser(description='A tool for learning assembly code.')
    parser.add_argument('-c', action="store", dest='code_string', default='',
                        help='Supply code to emulate')
    parser.add_argument('-syntax', action="store", dest='syntax', default='',
                        help='Set syntax')
    return parser.parse_args()

def main():

	global ks_syntax
	arguments = parse_arguments()
	#CODE = b"mov ax, 3; mov cx, 3; cmp cx, ax"
	code = arguments.code_string
	code_string = code.split(';')

	syntax = arguments.syntax
	if(syntax == "att"):
		ks_syntax = "KS_OPT_SYNTAX_ATT"
		print("AT&T Syntax")

	for cs in code_string:
		sample = binarize(cs)
		# print_registers(mu)
		mu = emulate(sample)

		#print_registers(mu)
		# print_flags(mu)
		update_registers(mu)
		print_registers(mu)
		#print_stack(mu)
	
if __name__ == '__main__':
    main()


