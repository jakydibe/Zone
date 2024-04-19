from capstone import *   #e' un disassembler
from keystone import *   #e' un assembler
import sys
import pefile
import time
import os
import re
from capstone import x86_const

#da guardare: 0x1949


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



#Lables, servono ad aggiustare gli indirizzi delle jump dopo che ho modificato le istruzioni
class lables:
    def __init__(self, instr, label_address, jump_call):
        self.instr = instr #istruzione jump/ call
        self.label_address = label_address  #indirizzo a cui jumpa
        #true is jump, false is call
        self.jump_call = jump_call


#classe principale
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

        self.original_entry_point = self.pe.NT_HEADERS.OPTIONAL_HEADER.AddressOfEntryPoint


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
                    previous_instr = self.new_instructions[-1]
                    new_instr = Instruction(i,i,i,previous_instr,None)
                    previous_instr.next_instr = new_instr
                    self.new_instructions.append(new_instr)

                else:
                    new_instr = Instruction(i,i,i,None,None)
                    self.new_instructions.append(new_instr)

        # for instr in self.new_instructions:
        #     if instr.previous_instr == None:
        #         continue
        #     string_instruction = instr.new_instr.mnemonic + " " + instr.new_instr.op_str

        #     asm, _ = self.ks.asm(string_instruction, (instr.previous_instr.new_instr.address + instr.previous_instr.new_instr.size))
        #     new_bytes = bytearray(asm)

        #     for i in self.cs.disasm(new_bytes, (instr.previous_instr.new_instr.address + instr.previous_instr.new_instr.size)):
        #         instr.previous_instr.new_instr = i
        #         with open("dumped_instructions.txt_orig_aggiustato", 'a') as f:
        #             f.write(f"{hex(i.address)}:\t {i.mnemonic} {i.op_str}\t {i.bytes}\n")



        
                

        self.create_label_table()



#indirizzo da guardare: 0x10dd
    def print_instructions(self):
        with open("dumped_instructions.txt", 'w') as f:
            
            for instr in self.new_instructions:

                string = "{}:\t{} \t{}\t{} \t{}\n".format(hex(instr.new_instr.address),instr.new_instr.size, instr.new_instr.mnemonic, instr.new_instr.op_str, instr.new_instr.bytes)
                #print("{}:\t{} \t{}\t{}".format(hex(instr.new_instr.address),bytearray(instr.new_instr.bytes), instr.new_instr.mnemonic, instr.new_instr.op_str))
                f.write(string)


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
    

        # new_entry = self.locate_by_address(self.original_entry_point).new_instr.address
        # self.pe.NT_HEADERS.OPTIONAL_HEADER.AddressOfEntryPoint = self.original_entry_point
        # print("New entry point: 0x%x" %new_entry)

        # self.code_section.Misc_VirtualSize = len(new_bytes)
        # self.code_section.Misc_PhysicalAddress = len(new_bytes)
        # self.code_section.Misc = len(new_bytes)

        # gap = self.pe.OPTIONAL_HEADER.SectionAlignment - (len(new_bytes) % self.pe.OPTIONAL_HEADER.SectionAlignment)

        # new_bytes += b'\x90' * gap
        # self.pe.set_bytes_at_offset(self.pe.OPTIONAL_HEADER.BaseOfCode, new_bytes)

        # self.pe.write("C:\\Users\\jakyd\\Desktop\\tesi\\tesi\\hello_world_patched.exe")
#relocate_image()
    def write_pe_text_section(self):

        #new_bytes = self.generate_binary_code()
        new_bytes = b''
        for instr in self.new_instructions:
            new_bytes += instr.new_instr.bytes

        with open("dumped_instructions2.txt", 'w') as f:
            for i in self.cs.disasm(new_bytes, self.base_address):
                #print(f"{i.address}: {i.mnemonic} {i.op_str}")
                f.write(f"{hex(i.address)}:\t {i.size}\t {i.mnemonic} {i.op_str}\t {i.bytes}\n")

        new_entry_point = self.locate_by_address(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)

        print(f"LUNGHEZZA NEW_BYTES: {hex(len(new_bytes))}")

        with open("hello_world_patched.exe", "r+b") as f:
            original_file = f.read()
            #f.seek(self.pe.OPTIONAL_HEADER.BaseOfCode)
            modified_file = original_file[:0x400] + new_bytes + original_file[0x400+len(new_bytes):]

            modified_file = modified_file[:0x120] + new_entry_point.new_instr.address.to_bytes(4, byteorder='little') + modified_file[0x124:]
            f.seek(0)

            f.write(modified_file)


    #crea la lable table
    def create_label_table(self):
        tmp_table = []
        #itera tutte le istruzioni in cerca di JMP/CALL (di tutti i tipi perche' x86_GRP)
        for instr in self.new_instructions:
            if (x86_const.X86_GRP_JUMP in instr.new_instr.groups or x86_const.X86_GRP_CALL in instr.new_instr.groups): 
                #se l' operando e' un IMM salva l'imm
                if (instr.new_instr.operands[0].type == x86_const.X86_OP_IMM):
                    jump_call = False
                    if x86_const.X86_GRP_JUMP in instr.new_instr.groups:
                        jump_call = True
                    label = lables(instr, instr.new_instr.operands[0].imm, jump_call)

                    tmp_table.append(label)#altrimenti salva l' indirizzo di mem
                elif (instr.new_instr.operands[0].type == x86_const.X86_OP_MEM):
                    jump_call = False
                    if x86_const.X86_GRP_JUMP in instr.new_instr.groups:
                        jump_call = True
                    label = lables(instr, instr.new_instr.operands[0].mem.disp, jump_call)
                    tmp_table.append(label)

        self.label_table = tmp_table
        #print(self.label_table)


#questa funzione assembla tutte le istruzioni successive ad una in seguito ad una modifica
#semplicemente incrementa gli indirizzi delle istruzioni di + num_bytes
    def increase_addresses(self,starting_addr,num_bytes):
        for instr in self.new_instructions:
            if instr.new_instr.address > starting_addr:
                # if instr.new_instr.address >= self.base_rdata:
                #     break
                #PROBABILMENTE QUESTE TOCCA TOGLIERE IL COMMENTO
                # string_instruction = instr.new_instr.mnemonic + " " + instr.new_instr.op_str
                # asm, _ = self.ks.asm(instr.new_instr.bytes, (instr.new_instr.address + num_bytes))
                # new_bytes = bytearray(asm)

                    
                new_bytes = instr.old_instr.bytes




                for i in self.cs.disasm(new_bytes, (instr.new_instr.address + num_bytes)):

                        #i.size = 1
                    if i.size != instr.new_instr.size:
                        print("ERRORE: ", hex(instr.new_instr.address))
                        print("SIZE OLD: ", instr.new_instr.size)
                        print("SIZE NEW: ", i.size)
                        print("I: ", i.mnemonic)
                        print("I: ", i.op_str)
                        print("I: ", i.bytes)
                        print("I: ", i.size)
                        print("I: ", i.address)
                        exit(1)

                    instr.new_instr = i
                
                if 'rip + ' in instr.new_instr.op_str:
                    offset_new = hex(estrai_valore(instr.new_instr.op_str))
                    new_address = instr.new_instr.address + estrai_valore(instr.new_instr.op_str)
                    old_address = instr.original_instr.address + estrai_valore(instr.original_instr.op_str)

                    if old_address < self.code_section.VirtualAddress + self.code_section.SizeOfRawData:
                        continue
                    if old_address != new_address:
                        offset_aggiustato = hex(old_address - instr.new_instr.address)
                        string = instr.new_instr.mnemonic + ' ' +  instr.new_instr.op_str
                        string = string.replace(f"rip + {offset_new}", f"rip + {offset_aggiustato}")
                        #print(f"offset_new: {offset_new}, offset_aggiustato: {offset_aggiustato}")
                        #print("istruzione: ", instr.new_instr.mnemonic, instr.new_instr.op_str)

                        #print("string: ", string)
                        asm, _ = self.ks.asm(string, instr.new_instr.address)

                        new_bytes = bytearray(asm)
                        for n in self.cs.disasm(new_bytes, instr.new_instr.address):
                            instr.new_instr = n
                        
            #sommo num_bytes alle istruzioni dei jump


    #aggiorna i vari indirizzi di jump grazie alla lable table
    #POSSIBILE ERRORE::: EVENTUALMENTE CHECKARE SE IL JUMP E' ALLA SEZIONE .TEXT, magari se jumpa ad altra roba non devo aumentare l'indirizzo
    def update_jumps(self):
        for label in self.label_table:
            for instr in self.new_instructions:
                #se c'e' un istruzione il cui precedente indirizzo compare nella label_table aggiornala
                if instr.old_instr.address == label.label_address:

                    if label.label_address > (self.code_section.VirtualAddress + self.code_section.SizeOfRawData):
                        continue
                    label.label_address = instr.new_instr.address

                    addr = hex(label.label_address)
                    str_instr = f"{label.instr.new_instr.mnemonic} {addr}"
                    
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
                    instr.new_instr = i
                    #instr.update_address(num_bytes)                  

                num_bytes = len(bytes_arr) - instr.old_instr.size

                self.increase_addresses(instr.new_instr.address,num_bytes)
                self.update_jumps()
                self.update_old_instructions(instr)


                break

#0x1010

# 0x1010: bytearray(b'3\xc0')     xor     eax, eax
# 0x1012: bytearray(b'H\x83\xc4(')        add     rsp, 0x28
# 0x1016: bytearray(b'\xc3')      ret

if __name__ == '__main__':
     #try:
     #exe_path = str(sys.argv[1])

    zone = Zone()
    zone.equal_instructions()
    zone.print_instructions()
    zone.write_pe_text_section()

