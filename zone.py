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
    def __init__(self,old_instr, old_address, new_address, old_mnemonic, new_mnemonic, old_length, new_length, old_bytes, new_bytes):
        self.old_instr = old_instr
        self.old_address = old_address
        self.new_address = new_address
        self.old_mnemonic = old_mnemonic
        self.new_mnemonic = new_mnemonic
        self.old_length = old_length
        self.new_length = new_length
        self.old_bytes = old_bytes
        self.new_bytes = new_bytes

    def update_address(self, new_address):
        self.new_address = new_address

    def update_mnemonic(self, new_mnemonic):
        self.new_mnemonic = new_mnemonic
    
    def update_length(self, new_length):
        self.new_length = new_length


class lables:
    def __init__(self, instr_address, label_address):
        self.instr_address = instr_address
        self.label_address = label_address


class Zone:
    #def __init__(self, file):
    def __init__(self):
        #self.file = file
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True
        self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
        self.pe = pefile.PE("C:\\Users\\jak\\Desktop\\pymetamorph-master\\hello_world.exe") #eventualmente passare il file come parametro

        self.label_table = []

        self.old_instructions = []

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


            self.old_instructions.append(i)
            new_instr = Instruction(i,i.address, i.address, i.mnemonic, i.mnemonic, i.size, i.size, i.bytes, i.bytes)
            self.new_instructions.append(new_instr)



        for instr in self.old_instructions:

            if (x86_const.X86_GRP_JUMP in instr.groups or x86_const.X86_GRP_CALL in instr.groups): 
                if (instr.operands[0].type == x86_const.X86_OP_IMM):
                    label = lables(instr.address, instr.operands[0].imm)
                    self.label_table.append(label)
                elif (instr.operands[0].type == x86_const.X86_OP_MEM):
                    label = lables(instr.address, instr.operands[0].mem.disp)
                    self.label_table.append(label)

                

        print(self.label_table)

    def increase_addresses(self,num_bytes):
        for instr in self.new_instructions:
            #PROBABILMENTE QUESTE TOCCA TOGLIERE IL COMMENTO
            #string_instruction = instr.mnemonic + " " + instr.op_str
            #asm, _ = self.ks.asm(string_instruction, (instr.address+ num_bytes))
            #instr.new_bytes = bytearray(asm)
            instr.new_address = instr.address + num_bytes
            

    def equal_instructions(self):
        for instr in self.new_instructions:
            if(instr.old_instr.id == x86_const.X86_INS_XOR and instr.old_instr.opernads[0].type == x86_const.X86_OP_REG and instr.old_instr.operands[1].type == x86_const.X86_OP_REG):

                str_instr = f"mov {instr.original_inst.reg_name(instr.original_inst.operands[0].reg)},0x0"
                asm, _ = self.ks.asm(str_instr, instr.old_instr.address)

                instr.new_bytes = bytearray(asm)
                instr.new_mnemonic = "mov"
                instr.new_length = len(asm)








if __name__ == '__main__':
     #try:
     #exe_path = str(sys.argv[1])

    zone = Zone()


    

    
    





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


