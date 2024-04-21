from capstone import *   #e' un disassembler
from keystone import *   #e' un assembler
import sys
import pefile
import lief
import time
import os
import re
from capstone import x86_const

#da guardare: 0x1949

def align(x, al):
    """ return <x> aligned to <al> """
    if x % al == 0:
        return x
    else:
        return x - (x % al) + al

def pad_data(data, al):
    """ return <data> padded with 0 to a size aligned with <al> """
    return data + ([0] * (align(len(data), al) - len(data)))



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

def estrai_valore(stringa):
    # Usa un'espressione regolare per trovare il valore tra "rip +" e "]"
    match = re.search(r"rip \+ (.*?)\]", stringa)
    
    # Se non c'è corrispondenza, restituisci un messaggio di errore
    if match is None:
        return "La stringa non contiene 'rip +'"
    
    # Altrimenti, restituisci il valore trovato
    return int(match.group(1), 16)


#classe che tiene conto per ogni istruzione di quella originale, della precedente e dell' attuale
#in piu' ogni istruzione e' un oggetto come molti campi come indirizzo, opcode etc.etc.
class Instruction:
    def __init__(self,original_instr,old_instr,new_instr,previous_instr,next_instr):
        self.original_instr = original_instr
        self.old_instr = old_instr
        self.new_instr = new_instr
        self.previous_instr = previous_instr
        self.next_instr = next_instr


    # def update_address(self, num_bytes):
    #     self.new_instr.address = self.new_instr.address + num_bytes

#classe principale
class Zone:
    #def __init__(self, file):
    def __init__(self):
        #self.file = file
        self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
        self.cs.detail = True
        self.ks = Ks(KS_ARCH_X86, KS_MODE_32)
        
        self.pe = pefile.PE("hello_world.exe")


        self.label_table = []

        self.far_lable_table = []

        self.new_instructions = []

        #con lief
        self.original_entry_point = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint


        #print(self.pe.OPTIONAL_HEADER)
            

        self.base_address = self.pe.OPTIONAL_HEADER.BaseOfCode
        self.code_section = get_text_section(self.pe, self.base_address)
        self.code_section_size = get_section_size(self.code_section)

        self.base_rdata = self.base_address + self.code_section_size
        #

        print("Base data address: 0x%x" %self.base_rdata)
        # i bytes della .text
        self.raw_bytes = self.code_section.get_data(self.base_address,self.code_section_size)
        self.original_bytes_len = len(self.raw_bytes)


        print("Base address: 0x%x" %self.base_address)
        print(self.code_section.Name, hex(self.code_section.VirtualAddress),hex(self.code_section.Misc_VirtualSize), hex(self.code_section.SizeOfRawData))



        with open("dumped_instructions.txt_orig", 'w') as f:
        #disassemblo tutte le istruzioni e creo un oggetto Instruction per ognuna
            for i in self.cs.disasm(self.raw_bytes, self.base_address):
                #scrivimi tutti i campi di i (address, mnemonic, op_str)
                #time.sleep(1000)
                f.write(f"{hex(i.address)}:\t {i.size}\t {i.mnemonic} {i.op_str}\t {i.bytes}\n")

                if i.address != self.base_address:
                    new_instr = Instruction(i,i,i,self.new_instructions[-1],None)
                    self.new_instructions[-1].next_instr = new_instr
                    self.new_instructions.append(new_instr)

                else:
                    new_instr = Instruction(i,i,i,None,None)
                    self.new_instructions.append(new_instr)



#indirizzo da guardare: 0x10dd
    def print_instructions(self):
        with open("dumped_instructions.txt", 'w') as f:
            
            for instr in self.new_instructions:

                string = "{}:\t{} \t{}\t{} \t{}\n".format(hex(instr.new_instr.address),instr.new_instr.size, instr.new_instr.mnemonic, instr.new_instr.op_str, instr.new_instr.bytes)
                #print("{}:\t{} \t{}\t{}".format(hex(instr.new_instr.address),bytearray(instr.new_instr.bytes), instr.new_instr.mnemonic, instr.new_instr.op_str))
                f.write(string)

        for x,i in enumerate(self.new_instructions):
            print(i.new_instr.mnemonic, i.new_instr.op_str, i.new_instr.bytes)
            if x == 15:
                break


    def locate_by_address(self, address):
        for instr in self.new_instructions:
            if instr.original_instr.address == address:
                return instr
        return None

    def generate_binary_code(self):
        code = b''
        for instruction in self.new_instructions:
            code += instruction.new_instr.bytes
        return code
    

    def write_pe_text_section(self):
        """ TODO load next sections from original file, rewrite them with the appropriate offset on the new file
         and modify file headers to allocate sections with new ofsets"""
        new_code = self.generate_binary_code()

        print("############################################")
        for x,i in enumerate(self.cs.disasm(new_code, self.base_address)):
            print(f"{hex(i.address)}: {i.mnemonic} {i.op_str}")
            if x > 20:
                break

        new_entry_point = self.locate_by_address(
            self.original_entry_point).new_instr.address
        self.pe.NT_HEADERS.OPTIONAL_HEADER.AddressOfEntryPoint = new_entry_point
        self.code_section.Misc_VirtualSize = len(new_code)
        self.code_section.Misc_PhysicalAddress = len(new_code)
        self.code_section.Misc = len(new_code)

        gap = self.pe.OPTIONAL_HEADER.SectionAlignment - (len(new_code) % self.pe.OPTIONAL_HEADER.SectionAlignment)
        gap_bytes = bytearray([0 for _ in range(gap)])
        new_code += gap_bytes
        self.code_section.SizeOfRawData = len(new_code)
        #self.pe_handler.writeBytes(self.base_of_code, new_code):


        grandezza_originale = self.code_section.SizeOfRawData
        print("!!!!!OFFSET: ", hex(self.base_address))
        print("LEN NEW CODE: ", hex(len(new_code)))

        with open("hello_world.exe", "r+b") as f:
            original_file = bytearray(f.read())

            new_code = bytearray(new_code)

            #addr = 0x1000
            original_file[0x400 : 0x400 + len(new_code)] = new_code
            original_file[0x120: 0x124] = (new_entry_point).to_bytes(4, byteorder='little')
            f.seek(0)
            f.write(original_file)


    #crea la lable table
    def print_jump_instr(self):
        i = 0
        for instr in self.new_instructions:
            if (x86_const.X86_GRP_JUMP in instr.new_instr.groups or x86_const.X86_GRP_CALL in instr.new_instr.groups):
                print(instr.new_instr.mnemonic, instr.new_instr.op_str)
                if i == 25:
                    break
                i += 1
    def create_label_table(self):
        jmp_table = dict()
        #itera tutte le istruzioni in cerca di JMP/CALL (di tutti i tipi perche' x86_GRP)
        for instr in self.new_instructions:
            if (x86_const.X86_GRP_JUMP in instr.new_instr.groups or x86_const.X86_GRP_CALL in instr.new_instr.groups): 
                #se l' operando e' un IMM salva l'imm
                if (instr.new_instr.operands[0].type == x86_const.X86_OP_IMM):

                    addr = instr.new_instr.operands[0].imm

                    jmp_table[addr] = None

        self.label_table = jmp_table
        #print(self.label_table)

    def get_instructions_from_labels(self):
        for instr in self.new_instructions:
            if instr.new_instr.address in self.label_table:
                self.label_table[instr.new_instr.address] = instr


#questa funzione assembla tutte le istruzioni successive ad una in seguito ad una modifica
#semplicemente incrementa gli indirizzi delle istruzioni di + num_bytes
    def update_instr(self):
        for instr in self.new_instructions:

            bytes_arr = bytearray(instr.new_instr.bytes)

            addr = instr.new_instr.address
            if instr.previous_instr:
                addr = instr.previous_instr.new_instr.address + instr.previous_instr.new_instr.size
            
            for i in self.cs.disasm(bytes_arr, addr):
                instr.new_instr = i
                #instr.update_address(num_bytes)
                break
                        

    def add_new_section(self):
        pe = lief.parse("hello_world.exe")

        new_section = lief.PE.Section(".newsec")

        new_section.content = [0x41]*0x1000  # Questo riempirà la sezione con "A"
        pe.add_section(new_section, lief.PE.SECTION_TYPES.TEXT)

        # Scrivi il PE modificato in un nuovo file
        pe.write("hello_world.exe")

    #aggiorna i vari indirizzi di jump grazie alla lable table
    #POSSIBILE ERRORE::: EVENTUALMENTE CHECKARE SE IL JUMP E' ALLA SEZIONE .TEXT, magari se jumpa ad altra roba non devo aumentare l'indirizzo
    def update_jumps(self):
        for instr in self.new_instructions:
            if (x86_const.X86_GRP_JUMP in instr.new_instr.groups or x86_const.X86_GRP_CALL in instr.new_instr.groups):
                if (instr.new_instr.operands[0].type == x86_const.X86_OP_IMM):
                    original_addr = instr.original_instr.operands[0].imm
                    if original_addr in self.label_table and self.label_table[original_addr]:
                        new_str = f"{instr.new_instr.mnemonic} {hex(self.label_table[original_addr].new_instr.address)}"
                        asm, _ = self.ks.asm(new_str, instr.new_instr.address)
                        bytes_arr = bytearray(asm)

                        for i in self.cs.disasm(bytes_arr, instr.new_instr.address):
                            instr.new_instr = i
                    else:
                        new_str = f"{instr.original_instr.mnemonic} {instr.original_instr.op_str}"

                # elif(instr.new_instr.operands[0].type == x86_const.X86_OP_MEM):
                #     original_addr = instr.original_instr.operands[0].mem.disp

                #     if original_addr in self.label_table and self.label_table[original_addr]:
                #         new_str = f"{instr.new_instr.mnemonic} {hex(self.label_table[original_addr].new_instr.address)}"
                #         asm, _ = self.ks.asm(new_str, instr.new_instr.address)
                #         bytes_arr = bytearray(asm)
                #         for i in self.cs.disasm(bytes_arr, instr.new_instr.address):
                #             instr.new_instr = i
                else:
                    new_str = f"{instr.original_instr.mnemonic} {instr.original_instr.op_str}"
                    asm, _ = self.ks.asm(new_str, instr.new_instr.address)
                    bytes_arr = bytearray(asm)
                    for i in self.cs.disasm(bytes_arr, instr.new_instr.address):
                        instr.new_instr = i
                
    def update_old_instructions(self,instr):
        #for instr in self.new_instructions:
        instr.old_instr = instr.new_instr

    #semplice prova di modifica delle istruzioni
    # xor eax,eax --> mov eax,0
    def equal_instructions(self):
        for instr in self.new_instructions:

            if(instr.old_instr.id == x86_const.X86_INS_XOR and instr.old_instr.operands[0].type == x86_const.X86_OP_REG and instr.old_instr.operands[1].type == x86_const.X86_OP_REG):

                print("ADDRESS DEL PRIMO XOR EAX,EAX: ", hex(instr.old_instr.address))
                str_instr = f"mov {instr.old_instr.reg_name(instr.old_instr.operands[0].reg)},0x0"
                asm, _ = self.ks.asm(str_instr, instr.old_instr.address)

                bytes_arr = bytearray(asm)


                for i in self.cs.disasm(bytes_arr,instr.new_instr.address):
                    print("vecchia istruzione: ", instr.old_instr.mnemonic, instr.old_instr.op_str)
                    print("nuova istruzione: ", i.mnemonic, i.op_str)
                    instr.new_instr = i
                    #instr.update_address(num_bytes)    
                self.update_old_instructions(instr)              

                break



if __name__ == '__main__':
     #try:
     #exe_path = str(sys.argv[1])

    zone = Zone()
    zone.create_label_table()
    zone.get_instructions_from_labels()

    zone.equal_instructions()
    print("MODIFICHE EFFETTUATE              [1/4]")

    

    
    #zone.print_jump_instr()
    zone.print_instructions()
    zone.update_instr()

    
    #zone.update_instr()
    print("Istruzioni aggiornate             [2/4]")
    #zone.print_jump_instr()
    #zone.print_instructions()


    zone.update_jumps()
    print("Jump aggiornati                   [3/4]")
    print("Istruzioni aggiornate.2           [4/4]")
    zone.print_instructions()

    zone.write_pe_text_section()

