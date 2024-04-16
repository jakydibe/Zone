from capstone import *
from keystone import *
import sys
import pefile
import time
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




#sezione: .text
#section.Name == '.text'
#section.VirtualAddress 
#section.Misc_VirtualSize   grandezza della sezione quando verra' caricata in memoria
#section.SizeOfRawData      grandezza effettiva sul disco della sezione 



#problema: indirizzi gia' sfanculati ---> devo gia' metterli a posto
#soluzione: 
#    1) tupla con: (indirizzo_originale,indirizzo_nuovo, bytes )
#    2) itero istruzioni
#    3) quando rilevo un' istruzione jmp  aggiorno con indirizzo_nuovo
#         3.1) short jmp, solo 2 byte (quindi rilevo 7 NOP), potrei trasformare in far jmp
#         3.2) altimenti far jmp, modifico indirizzo 


class Instruction:
    def __init__(self,old_instr,new_instr):
        self.old_instr = old_instr
        self.new_instr = new_instr


    def update_address(self, num_bytes):
        self.new_instr.address = self.new_instr.address + num_bytes



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



    

    
    





#primo xor eax,eax trovato a 0x1010, grosso 2 byte

#Provo a sostituirlo con mov eax,0x0

    # for instr in istruzioni_nuove:
    #     try:
    #         from capstone import x86_const
    #         if instr.old_instr.id == x86_const.X86_INS_XOR:
    #             print("{}:\t{} \t{}\t{}".format(hex(instr.old_instr.address),bytearray(instr.old_instr.bytes), instr.old_instr.mnemonic, instr.old_instr.op_str))
    #             print("lunghezza istruzione: ", instr.old_instr.size)
                
    #             new_inst_str = "mov eax,0x0"
    #             asm, _ = ks.asm(new_inst_str, instr.old_instr.address)
    #             instr.new_bytes = bytearray(asm)
    #             print(asm)

    #             for i in cs.disasm(instr.new_bytes, instr.old_instr.address):
    #                 instr.old_instr = i
    #                 instr.new_mnemonic = i.mnemonic
    #                 instr.new_length = i.size

    #             #Per rimettere tutto a posto dovro assemblare tutto il codice a + 

    #             print("{}:\t{} \t{}\t{}".format(hex(instr.old_instr.address),bytearray(instr.old_instr.bytes), instr.old_instr.mnemonic,instr.old_instr.op_str))
    #             print("lunghezza istruzione: ", i.size)
    #             break
    #     except Exception as e:
    #         print(e)
    #         break

    # for i in cs.disasm(raw_bytes, base_address):
    #     print("{}:\t{} \t{}\t{}".format(hex(i.address),bytearray(i.bytes), i.mnemonic, i.op_str))
            
    #     #   #print(len(i.bytes))
    #     #   adjusted_array.append(i.bytes)
    #     #   for n in range(instr_max_size - len(i.bytes)):
    #     #        adjusted_array[x] += b'\x90'


