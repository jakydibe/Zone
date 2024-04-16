from capstone import *
from keystone import *
import sys
import pefile
import time
import os
from capstone import x86_const



def get_base_address(pe):
    return pe.OPTIONAL_HEADER.BaseOfCode

def get_entry_point(pe):
    return pe.OPTIONAL_HEADER.AddressOfEntryPoint

def get_size_of_image(pe):
    return pe.OPTIONAL_HEADER.SizeOfImage

def get_text_section(pe, address):
    #return pe.O
    for section in pe.sections:
        if section.contains_rva(address):
            print(section.Name, hex(section.VirtualAddress),hex(section.Misc_VirtualSize), section.SizeOfRawData )
            return section
          
def get_section_size(section):
    return section.Misc_VirtualSize



class Instruction:
    def __init__(self,old_instr,new_instr):
        self.old_instr = old_instr
        self.new_instr = new_instr


    # def update_address(self, num_bytes):
    #     self.new_instr.address = self.new_instr.address + num_bytes



class lables:
    def __init__(self, instr, label_address, jump_call):
        self.instr = instr
        self.label_address = label_address
        #true is jump, false is call
        self.jump_call = jump_call


class Zone:
    #def __init__(self, file):
    def __init__(self):
        #self.file = file
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True
        self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
        self.pe = pefile.PE("C:\\Users\\jakyd\\Desktop\\tesi\\tesi\\hello_world.exe") #eventualmente passare il file come parametro

        self.label_table = []


        self.new_instructions = []
        self.original_entry_point = self.pe_handler.getEntryPointAddress()

        self.base_address = get_base_address(self.pe)
        self.code_section = get_text_section(self.pe, self.base_address)
        self.code_section_size = get_section_size(self.code_section)
        self.raw_bytes = self.code_section.get_data(self.base_address,self.code_section_size)

        print("Base address: 0x%x" %self.base_address)
        print(self.code_section.Name, hex(self.code_section.VirtualAddress),hex(self.code_section.Misc_VirtualSize), self.code_section.SizeOfRawData )



        
        for i in self.cs.disasm(self.raw_bytes, self.base_address):
            #scrivimi tutti i campi di i (address, mnemonic, op_str)
            #time.sleep(1000)

            new_instr = Instruction(i,i)
            self.new_instructions.append(new_instr)

        self.create_label_table()




    def print_instructions(self):
        for instr in self.new_instructions:
            if instr.new_instr.address <= 0x1060:
                print("{}:\t{} \t{}\t{}".format(hex(instr.new_instr.address),bytearray(instr.new_instr.bytes), instr.new_instr.mnemonic, instr.new_instr.op_str))
            else:
                break



#relocate_image()
    def write_pe_text_section(self):

        new_bytes = b""
        for instr in self.new_instructions:
            new_bytes += instr.new_instr.bytes

        #new_bytes = bytearray(new_bytes)
        with open("C:\\Users\\jakyd\\Desktop\\tesi\\tesi\\hello_world_patched.exe", "r+b") as f:

            original_file = f.read()

            modified_file = original_file[:0x400] + new_bytes + original_file[0x400+len(new_bytes):]
            f.seek(0, os.SEEK_SET)

            f.write(modified_file)

        # self.pe.set_bytes_at_offset(self.code_section,new_bytes)
        # self.pe.write("C:\\Users\\jakyd\\Desktop\\tesi\\tesi\\hello_world_patched.exe")

                
    def create_label_table(self):
        tmp_table = []
        for instr in self.new_instructions:
            if (x86_const.X86_GRP_JUMP in instr.new_instr.groups or x86_const.X86_GRP_CALL in instr.new_instr.groups): 
                if (instr.new_instr.operands[0].type == x86_const.X86_OP_IMM):
                    jump_call = False
                    if x86_const.X86_GRP_JUMP in instr.new_instr.groups:
                        label.jump_call = True
                    label = lables(instr, instr.new_instr.operands[0].imm, jump_call)

                    tmp_table.append(label)
                elif (instr.new_instr.operands[0].type == x86_const.X86_OP_MEM):
                    jump_call = False
                    if x86_const.X86_GRP_JUMP in instr.new_instr.groups:
                        jump_call = True
                    label = lables(instr, instr.new_instr.operands[0].mem.disp, jump_call)
                    tmp_table.append(label)

        self.label_table = tmp_table
        #print(self.label_table)


#CAMBIARE::: incrementare solo le istruzioni dopo
    def increase_addresses(self,starting_addr,num_bytes):
        for instr in self.new_instructions:
            if instr.new_instr.address > starting_addr:
                #PROBABILMENTE QUESTE TOCCA TOGLIERE IL COMMENTO
                string_instruction = instr.new_instr.mnemonic + " " + instr.new_instr.op_str
                asm, _ = self.ks.asm(string_instruction, (instr.new_instr.address+ num_bytes))
                new_bytes = bytearray(asm)


                self.update_old_instructions(instr)


                for i in self.cs.disasm(new_bytes, (instr.new_instr.address+ num_bytes)):
                    instr.new_instr = i
            #sommo num_bytes alle istruzioni dei jump



    def update_jumps(self):
        for label in self.label_table:
            for instr in self.new_instructions:
                if instr.old_instr.address == label.label_address:
                    label.label_address = instr.new_instr.address

                    addr = hex(label.label_address)
                    str_instr = ""

                    if label.jump_call:
                        str_instr = f"jmp {addr}"
                    else:
                        str_instr = f"call {addr}"
                    
                    asm, _ = self.ks.asm(str_instr, label.instr.new_instr.address)
                    new_bytes = bytearray(asm)

                    for i in self.new_instructions:
                        if i.new_instr.address == label.instr.new_instr.address:
                            for n in self.cs.disasm(new_bytes, i.new_instr.address):
                                i.new_instr = n              
                            break


    def update_old_instructions(self,instr):
        #for instr in self.new_instructions:
        instr.old_instr = instr.new_instr


    # xor eax,eax --> mov eax,0
    def equal_instructions(self):
        for instr in self.new_instructions:

            if(instr.old_instr.id == x86_const.X86_INS_XOR and instr.old_instr.operands[0].type == x86_const.X86_OP_REG and instr.old_instr.operands[1].type == x86_const.X86_OP_REG):

                print("ADDRESS DEL PRIMO XOR EAX,EAX: ", hex(instr.old_instr.address))
                str_instr = f"mov {instr.old_instr.reg_name(instr.old_instr.operands[0].reg)},0x0"
                asm, _ = self.ks.asm(str_instr, instr.old_instr.address)

                bytes_arr = bytearray(asm)


                for i in self.cs.disasm(bytes_arr,instr.new_instr.address):
                    instr.new_instr = i
                    #instr.update_address(num_bytes)                  

                num_bytes = len(bytes_arr) - instr.old_instr.size

                self.increase_addresses(instr.new_instr.address,num_bytes)
                self.update_jumps()

                break

#0x1010

# 0x1010: bytearray(b'3\xc0')     xor     eax, eax
# 0x1012: bytearray(b'H\x83\xc4(')        add     rsp, 0x28
# 0x1016: bytearray(b'\xc3')      ret

if __name__ == '__main__':
     #try:
     #exe_path = str(sys.argv[1])

    zone = Zone()
    zone.print_instructions()
    zone.equal_instructions()
    zone.print_instructions()
    zone.write_pe_text_section()

