#strutture:
#1) classe: Istruzione, e'una lista dinamica che conterra':
#   -istruzione attuale
#   -istruzione vecchia
#   -istruzione originale
#   -precedente e successiva istruzione
#
#
#2)self.instructions: lista di Istruzione   
#
#3)self.labels: lista di label
#

#

#5) aggiornare le varie jump/call:
#   1) verificare se le jmp/call sono fuori dalla .text
#       1.1) se sono fuori dalla .text,(l'indirizzo lo calcolo col valore dopo rip+) --> riassembla l'istruzone con sostituendo il valore dopo 'rip +' con la differenza tra indirizzo_attuale - indirizzo_originale
#       1.2) se sono dentro la .text, --> riassemblo la jump a con il nuovo indirizzo dell'istruzione a cui puntava
#
#   2) verificare se durante l'assemblaggio il numero di byte dell'istruzione e' cambiato(far jump --> short jump)
#       2.1) verificare se la stringa del disassemblaggio e' uguale alla stringa dell'assemblaggio	
#       2.2) se la grandezza nuova e'minore della grandezza vecchia, --> aggiungere NOP fino a raggiungere la grandezza vecchia
#           2.2.1) creare un metodo per inserire istruzioni
#                2.2.2) prev_instr = self.instructions[i], next_instr = self.instructions[i+1]

#
from capstone import *   #e' un disassembler
from keystone import *   #e' un assembler
import sys
import pefile
import time
import lief
import os
from capstone import x86_const

# def estrai_valore(stringa):
#     # Usa un'espressione regolare per trovare il valore tra "rip +" e "]"
#     match = re.search(r"rip \+ (.*?)\]", stringa)
#STRUTTURA COSE DA FARE
#0) inizializzare tutto                                                                         FATTO!                                       
#1) dumpare la .text                                                                            FATTO!
#2) disassemblare la .text e aggiungere le istruzioni alla lista self.instructions              FATTO!
#3) creare le label table                                                                       FATTO!       
#4) modificare un'istruzione (solo per testing)                                                 FATTO!
#5) aggiornare (incrementare) le varie istruzioni                                               FATTO!
#6) aggiornare le varie jump o varie references                                                 FATTO! (forse)
#7) controllare tutte istruzioni con 'rip +' dentro (sono istruzioni che puntano alla .data)    FATTO!
#   7.1) similmente alle jump, calcolare l' indirizzo grazie all'indirizzo originale            FATTO!
#8) scrivere il PE
#
#--> inserire le NOP
    
#     # Se non c'è corrispondenza, restituisci un messaggio di errore
#     if match is None:
#         return "La stringa non contiene 'rip +'"
    
#     # Altrimenti, restituisci il valore trovato
#     return int(match.group(1), 16)

import re

def estrai_valore(instruzione):
    # Usa un'espressione regolare per cercare un numero esadecimale nella stringa
    match = re.search(r'0x[0-9a-fA-F]+', instruzione)
    
    # Se un numero esadecimale è stato trovato, convertilo in un intero e restituiscilo
    if match:
        return int(match.group(), 16)
    else:
        return 0


def find_xref(addr):
    addr_bytes = addr.to_bytes(4, byteorder='little')

    with open("hel.exe", "rb") as f:
        data = f.read()
        xref_list = []
        for i in range(len(data)):
            if data[i:i+4] == addr_bytes:
                #print(addr_bytes,hex(i))
                xref_list.append(i)

    return xref_list


def get_text_section(pe, address):
    #return pe.O
    for section in pe.sections:
        if section.contains_rva(address):
            print(section.Name, hex(section.VirtualAddress),hex(section.Misc_VirtualSize), section.SizeOfRawData )
            return section
        
def get_text_section_lief(pe):
    for section in pe.sections:
        if section.name == '.text':
            return section
    return None

def get_section(pe,name):
    for section in pe.sections:
        if section.Name == name:
            print(section.Name, hex(section.VirtualAddress),hex(section.Misc_VirtualSize), section.SizeOfRawData )
            return section
    return None

class Instruction:
    def __init__(self,new_instruction,old_instruction,original_instruction,prev_instruction,next_instruction):
        self.new_instruction = new_instruction
        self.old_instruction = old_instruction
        self.original_instruction = original_instruction
        self.prev_instruction = prev_instruction
        self.next_instruction = next_instruction




class Zone:
    def __init__(self):
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True

        self.cs.skipdata = True
        self.cs.skipdata_setup = ("uint", None, None)
        self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
        
        self.pe = pefile.PE("hello_world.exe")

        self.pe_lief = lief.parse("hello_world.exe")


        self.label_table = []
        self.instructions = []

        self.jump_table = []

        self.original_entry_point = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.base_address = self.pe.OPTIONAL_HEADER.BaseOfCode
        self.code_section = get_text_section(self.pe, self.base_address)
        self.code_section_size = self.code_section.Misc_VirtualSize

        self.rdata_section = get_section(self.pe, '.rdata\x00\x00')


        self.data_directories = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY

        self.code_raw_start = self.code_section.PointerToRawData
        print(f"Original entry point: {hex(self.original_entry_point)}")
        print(f"Base address: {hex(self.base_address)}")
        print(f"Code section size: {hex(self.code_section_size)}")

        self.raw_code = self.code_section.get_data(self.base_address, self.code_section_size)
        #self.raw_code = get_text_section_lief(self.pe_lief).content


        self.original_code_length = len(self.raw_code)


        with open('instr.txt', 'r+') as f:
            begin = self.base_address
            end = self.base_address + self.code_section_size

            #time.sleep(10000)
            while True:
                last_address = 0
                last_size = 0
                print(f"begin: {hex(begin)}")
                print(f"end: {hex(end)}")
                time.sleep(1)

                print("CICLO\n")
                for i in self.cs.disasm(self.raw_code[begin-self.base_address:end], begin):
                    self.instructions.append(Instruction(i,i,i,None,None))
                    stringa = f"{hex(i.address)} {i.bytes} {i.size}  {i.mnemonic}  {i.op_str}\n"
                    last_address = i.address
                    last_size = i.size
                    f.write(stringa)
                


                begin = max(int(last_address),begin) + last_size + 1
                
                if begin >= end:
                    break
                #self.raw_code = self.code_section.get_data(self.base_address, self.code_section_size)[begin:end]


        print("FINITO DI DISASSEMBLARE")
        time.sleep(10000)


        for x,instr in enumerate(self.instructions):
            if x == 0:
                continue
            instr.prev_instruction = self.instructions[x-1]
            if x == len(self.instructions)-1:
                continue
            instr.next_instruction = self.instructions[x+1]

    def update_instr(self):
        for x,i in enumerate(self.instructions):
            if x == 0:
                continue
            addr = i.prev_instruction.new_instruction.address + len(i.prev_instruction.new_instruction.bytes)


            for n in self.cs.disasm(i.new_instruction.bytes,addr):
                i.new_instruction = n

    def find_section_via_raw(self,raw_address):
        for section in self.pe.sections:
            if raw_address >= section.PointerToRawData and raw_address < section.PointerToRawData + section.SizeOfRawData:
                return section
        return None

    #File Offset = RVA - Section.VirtualAddress + Section.PointerToRawData
    def convert_raw_to_rva(self,raw_address,section):
        return raw_address + section.VirtualAddress - section.PointerToRawData

    def print_instructions(self):
        with open('instr_2.txt', 'r+') as f:

            for x,i in enumerate(self.instructions):
                stringa  = f"{hex(i.new_instruction.address)} {i.new_instruction.bytes} {len(i.new_instruction.bytes)}  {i.new_instruction.mnemonic}  {i.new_instruction.op_str}\n"
                f.write(stringa)

    def print_label_table(self):
        for k,v in self.label_table.items():
            print(hex(k),v.new_instruction.mnemonic, v.new_instruction.op_str)

    
    def create_jmp_table(self):
        for instr in self.instructions:
            if instr.old_instruction.id == x86_const.X86_INS_JMP and instr.old_instruction.operands[0].type == x86_const.X86_OP_REG:
                if instr.prev_instruction.new_instruction.mnemonic == 'add' and instr.prev_instruction.prev_instruction.new_instruction.mnemonic == 'mov':
                    indirizzo_jmp_table = estrai_valore(instr.prev_instruction.prev_instruction.new_instruction.op_str)
                    self.jump_table.append(indirizzo_jmp_table)
    
    def print_jmp_table(self):
        with open('jmp_table.txt', 'r+') as f:
            for i in self.jump_table:
                f.write(hex(i) + '\n')
                    
    def adjust_jmp_table(self):
        for n,i in enumerate(self.jump_table):
            x = 0
            if n != len(self.jump_table) - 1:
                while (i + x*4 < self.jump_table[n+1]):
                    addr = self.pe.get_dword_at_rva(i + x*4)
                    is_an_instruction = False
                    for instr in self.instructions:
                        if instr.original_instruction.address == addr:
                            self.pe.set_dword_at_rva(i + x*4, instr.new_instruction.address)
                            is_an_instruction = True
                            break
                    if is_an_instruction == False:
                        break
                    x += 1

        self.pe.write("hello_world.exe")
                    


    def create_label_table(self):
        lt = dict()

        for instr in self.instructions:
            if (x86_const.X86_GRP_JUMP in instr.new_instruction.groups) or (x86_const.X86_GRP_CALL in instr.new_instruction.groups):
                if(instr.new_instruction.operands[0].type == x86_const.X86_OP_IMM):
                    addr = instr.new_instruction.operands[0].imm
                    lt[addr] = instr

        self.label_table = lt

    def insert_instruction(self,index,instruction):
        self.instructions[index].next_instruction = instruction
        self.instructions[index +1].prev_instruction = instruction

        instruction.previous_instruction = self.instructions[index]
        instruction.next_instruction = self.instructions[index +1]

        self.instructions.insert(index,instruction)


    def update_label_table(self):
        restart = False
        finished = False
        while finished == False:
            restart = False

            for instr in self.instructions:
                if restart == True:
                    break
                if instr.original_instruction.address in self.label_table:
                    
                    for num_instr,instr2 in enumerate(self.instructions):
                        if restart == True:
                            break
                        if instr2.original_instruction.address == self.label_table[instr.original_instruction.address].original_instruction.address:
                            new_addr = instr.new_instruction.address

                            new_str = f"{instr2.original_instruction.mnemonic} {hex(new_addr)}"
                            
                            asm,_ = self.ks.asm(new_str,instr2.new_instruction.address)
                            asm = bytearray(asm)

                            if(len(asm) < instr2.new_instruction.size):
                                restart = True
                                print("Indirizzo: ",hex(instr2.new_instruction.address))
                                print('Istruzione: ',instr2.new_instruction.mnemonic,instr2.new_instruction.op_str)
                                print("lunghezza asm: ",len(asm))
                                print("lunghezza instr2.new_instruction: ",instr2.new_instruction.size)
                                nop_num = instr2.new_instruction.size - len(asm)
                        ###################DA AGGIUSTARE################################
                                for i in range(nop_num):
                                    asm.append(0x90)
                                for x,i in enumerate(self.cs.disasm(asm, instr2.new_instruction.address)):
                                    if x == 0:
                                        instr2.new_instruction = i
                                    else:
                                        insr = Instruction(i,i,i,None,None)
                                        self.insert_instruction(num_instr + x, insr)
                                # for i in self.cs.disasm(asm,instr2.new_instruction.address):
                                #     instr.new_instruction = i
                            elif(len(asm) == instr2.new_instruction.size):
                                for i in self.cs.disasm(asm,instr2.new_instruction.address):
                                    instr2.new_instruction = i
                            else:
                                print("SOSPETTO: len(asm) > instr2.new_instruction.size")
            finished = True




    def adjust_out_text_references(self):
        for num_instr,instr in enumerate(self.instructions):
            if instr is not None:
                if ('rip +' in instr.new_instruction.op_str):
                    #print(hex(instr.original_instruction.address),instr.original_instruction.mnemonic,instr.original_instruction.op_str)
                    valore_originale = estrai_valore(instr.original_instruction.op_str)
                    if valore_originale == 0:
                        continue

                    addr = self.instructions[num_instr + 1].original_instruction.address + valore_originale

                    #checko se l'indirizzo e'all'interno della .text
                    if addr > self.base_address and addr < self.base_address + self.code_section_size:
                        for i in self.instructions:
                            if i.original_instruction.address == addr:
                                addr = i.new_instruction.address
                                print("NUOVO INDIRIZZO JUMP RIP+ : ",hex(addr))
                                break
         
                    offset = addr - self.instructions[num_instr + 1].new_instruction.address

                    #print(f"valore vecchio: {hex(valore_originale)}, addr nuovo: {hex(new_addr)}")
                    old_string = instr.new_instruction.mnemonic + ' ' + instr.new_instruction.op_str

                    new_string = old_string.replace(hex(valore_originale),hex(offset))

                    asm, _ = self.ks.asm(new_string, instr.new_instruction.address)
                    asm = bytearray(asm)

                    if(len(asm) < len(instr.new_instruction.bytes)):
                        if(instr.new_instruction.bytes[0] == 0x48 and (len(instr.new_instruction.bytes) - len(asm) == 1)):
                            print("cosa strana")
                            print("Indirizzo: ",hex(instr.new_instruction.address))

                            asm.insert(0,0x48)
                            for i in self.cs.disasm(asm, instr.new_instruction.address):
                                instr.new_instruction = i
                        else:                     
                            ##########DA IMPLEMENTARE################
                            print("Indirizzo: ",hex(instr.new_instruction.address))
                            print('nuova lunghezza asm: ',len(asm))
                            print('vecchia lunghezza instr.new_instruction: ',instr.new_instruction.size)
                            nop_num = instr.new_instruction.size - len(asm)
                            for i in range(nop_num):
                                asm.append(0x90)
                            for x,i in enumerate(self.cs.disasm(asm, instr.new_instruction.address)):
                                if x == 0:
                                    instr.new_instruction = i
                                else:
                                    insr = Instruction(i,i,i,None,None)
                                    self.insert_instruction(num_instr + x, insr)
                    else:
                        for i in self.cs.disasm(asm, instr.new_instruction.address):
                            instr.new_instruction = i

                elif ('rip -' in instr.new_instruction.op_str):
                    #print(hex(instr.original_instruction.address),instr.original_instruction.mnemonic,instr.original_instruction.op_str)
                    valore_originale = estrai_valore(instr.original_instruction.op_str)
                    print("valore_originale: ",valore_originale)
                    if valore_originale == 0:
                        continue
                    addr = self.instructions[num_instr + 1].original_instruction.address - valore_originale

                    #checko se l'indirizzo e'all'interno della .text
                    if addr > self.base_address and addr < self.base_address + self.code_section_size:
                        for i in self.instructions:
                            if i.original_instruction.address == addr:
                                addr = i.new_instruction.address
                                break

                    offset = self.instructions[num_instr + 1].new_instruction.address - addr

                    #print(f"valore vecchio: {hex(valore_originale)}, addr nuovo: {hex(new_addr)}")
                    old_string = instr.new_instruction.mnemonic + ' ' + instr.new_instruction.op_str

                    new_string = old_string.replace(hex(valore_originale),hex(offset))

                    asm, _ = self.ks.asm(new_string, instr.new_instruction.address)
                    asm = bytearray(asm)

                    if(len(asm) < len(instr.new_instruction.bytes)):
                        #checka il problema del bytes 0x48 che ks non lo assembla molto spesso
                        if(instr.new_instruction.bytes[0] == 0x48 and (len(instr.new_instruction.bytes) - len(asm) == 1)):
                            # print("cosa strana")
                            # print("Indirizzo: ",hex(instr.new_instruction.address))

                            asm.insert(0,0x48)
                            for i in self.cs.disasm(asm, instr.new_instruction.address):
                                instr.new_instruction = i
                        else:                     
                            ##########DA IMPLEMENTARE################
                            # print("Indirizzo: ",hex(instr.new_instruction.address))
                            # print('nuova lunghezza asm: ',len(asm))
                            # print('vecchia lunghezza instr.new_instruction: ',instr.new_instruction.size)
                            nop_num = instr.new_instruction.size - len(asm)
                            for i in range(nop_num):
                                asm.append(0x90)
                            for x,i in enumerate(self.cs.disasm(asm, instr.new_instruction.address)):
                                if x == 0:
                                    instr.new_instruction = i
                                else:
                                    insr = Instruction(i,i,i,None,None)
                                    self.insert_instruction(num_instr + x, insr)
                    else:
                        for i in self.cs.disasm(asm, instr.new_instruction.address):
                            instr.new_instruction = i
            else:
                print("dentro adjust_out_text_references(), instr e' None")



    def update_old_instructions(self,instr):
        instr.old_instruction = instr.new_instruction

    def equal_instructions(self):
        for instr in self.instructions:

            if(instr.old_instruction.id == x86_const.X86_INS_XOR and instr.old_instruction.operands[0].type == x86_const.X86_OP_REG and instr.old_instruction.operands[1].type == x86_const.X86_OP_REG):

                print("ADDRESS DEL PRIMO XOR EAX,EAX: ", hex(instr.old_instruction.address))
                str_instr = f"mov {instr.old_instruction.reg_name(instr.old_instruction.operands[0].reg)},0x0"
                #str_instr = f"sub eax,eax"

                asm, _ = self.ks.asm(str_instr, instr.old_instruction.address)

                bytes_arr = bytearray(asm)


                for i in self.cs.disasm(bytes_arr,instr.new_instruction.address):
                    print("vecchia istruzione: ", instr.old_instruction.mnemonic, instr.old_instruction.op_str)
                    print("nuova istruzione: ", i.mnemonic, i.op_str)
                    instr.new_instruction = i
                    #instr.update_address(num_bytes)    
                self.update_old_instructions(instr)              

                break

    def adjust_reloc_table(self):
        for entries in self.pe.DIRECTORY_ENTRY_BASERELOC:
            for reloc in entries.entries:
                data = self.pe.get_qword_at_rva(reloc.rva)
                data = data - self.pe.OPTIONAL_HEADER.ImageBase
                #print(hex(reloc.rva), reloc.type,hex(data))#, reloc.value)
                for instr in self.instructions:
                    if instr.original_instruction.address == data:
                        # print("Trovato un reloc che punta ad un'istruzione")
                        # print(hex(reloc.rva), reloc.type,hex(data))
                        print("nella reloc: ",hex(data))
                        print("nella istruzione: ",hex(instr.new_instruction.address))
                        self.pe.set_qword_at_rva(reloc.rva, instr.new_instruction.address + self.pe.OPTIONAL_HEADER.ImageBase)
                        break
        self.pe.write("hello_world.exe")


                        
    def locate_by_address(self, address):
        for instr in self.instructions:
            if instr.original_instruction.address == address:
                return instr
        return None
    def write_pe_file(self):
        new_bytes = b''
        for i in self.instructions:
            new_bytes += i.new_instruction.bytes
        
        # gap = self.pe.OPTIONAL_HEADER.SectionAlignment - (len(new_bytes) % self.pe.OPTIONAL_HEADER.SectionAlignment)

        # gap_bytes = (bytearray([0 for _ in range(gap)]))
        # new_bytes += gap_bytes
        new_entry_point = self.locate_by_address(self.original_entry_point).new_instruction.address

        #indirizzo dove viene salvato l'entry point
        entry_point_addr = self.pe.DOS_HEADER.e_lfanew + 0x28
        with open("hello_world.exe", "r+b") as f:

            original_file = bytearray(f.read())
            print(f"LEN ORIGINAL_FILE: {len(original_file)}")
            new_bytes = bytearray(new_bytes)

            #riscrivo la .text
            original_file[self.code_raw_start : self.code_raw_start + len(new_bytes)] = new_bytes
            #scrivo l' entry point
            original_file[entry_point_addr: entry_point_addr + 4] = new_entry_point.to_bytes(4, byteorder='little')
            print(f"LEN NUOVO_FILE: {len(original_file)}")

            f.seek(0)
            f.write(original_file)        



if __name__ == '__main__':
    zone = Zone()

    zone.print_instructions()

    # zone.create_label_table()
    
    # zone.create_jmp_table()
    # zone.print_jmp_table()

    # zone.equal_instructions()
    # zone.update_instr()
    # zone.update_label_table()

    # #zone.print_instructions()

    # zone.adjust_out_text_references()

    # #zone.print_instructions()


    # zone.adjust_reloc_table()
    # zone.adjust_jmp_table()

    # zone.write_pe_file()
 

#1f4e
