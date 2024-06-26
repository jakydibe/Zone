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
import random
from capstone import x86_const
import increase_text

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

#strutturare un dizionario per essere piu' performante
#dizionario del tipo [indirizzo_originale: istruzione]---> per patchare le jump
#un altro dizionario del tipo: []





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
    def __init__(self, file):
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True
        self.cs.skipdata = True

        self.file = file

        self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
        
        
        self.pe = pefile.PE(file)

        self.pe_lief = lief.parse(file)

        self.push_mov = False

        self.label_table = []
        self.instructions = []

        self.jump_table = []
        self.start_end_table = []

        self.instr_dict = {}

        self.increase_size = 0x2000

        self.original_entry_point = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.base_address = self.pe.OPTIONAL_HEADER.BaseOfCode
        self.code_section = get_text_section(self.pe, self.base_address)
        self.code_section_size = self.code_section.Misc_VirtualSize

        self.rdata_section = get_section(self.pe, '.rdata\x00\x00')

        self.reg_list = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']

        self.data_directories = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY

        self.code_raw_start = self.code_section.PointerToRawData
        print(f"Original entry point: {hex(self.original_entry_point)}")
        print(f"Base address: {hex(self.base_address)}")
        print(f"Code section size: {hex(self.code_section_size)}")

        self.raw_code = self.code_section.get_data(self.base_address, self.code_section_size)
        #self.raw_code = get_text_section_lief(self.pe_lief).content


        self.original_code_length = len(self.raw_code)

        self.bytes_to_add = []


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

                    instruction = Instruction(i,i,i,None,None) 
                    self.instructions.append(instruction)


                    self.instr_dict[i.address] = instruction

                    stringa = f"{hex(i.address)} {i.bytes} {i.size}  {i.mnemonic}  {i.op_str}\n"
                    last_address = i.address
                    last_size = i.size
                    f.write(stringa)
                

                
                if begin >= end:
                    break


                begin = max(int(last_address),begin) + last_size
                # byte_rotto = hex(self.raw_code[begin-self.base_address -1])
                #print(f"byte rotto: {byte_rotto}")


                #self.raw_code = self.code_section.get_data(self.base_address, self.code_section_size)[begin:end]


        print("FINITO DI DISASSEMBLARE")
        #self.cs.skipdata = False

        for x,instr in enumerate(self.instructions):
            instr.new_bytes = instr.new_instruction.bytes

            if x == 0:
                continue
            instr.prev_instruction = self.instructions[x-1]
            if x == len(self.instructions)-1:
                continue
            instr.next_instruction = self.instructions[x+1]

    def update_address(self):
        starting_address = self.base_address
        addr = starting_address

        for x,instr in enumerate(self.instructions):
            try:
                if x != 0:
                    addr = addr + len(self.instructions[x-1].new_instruction.bytes)
                    
                for n in self.cs.disasm(instr.new_instruction.bytes,addr):
                    instr.old_instruction = instr.new_instruction
                    instr.new_instruction = n
            except Exception as e:
                print("Errore in update_address(): ",e)
                continue
            
            


    def update_instr(self):
        for x,i in enumerate(self.instructions):
            try:
                if x == 0:
                    continue
                addr = i.prev_instruction.new_instruction.address + len(i.prev_instruction.new_instruction.bytes)


                for n in self.cs.disasm(i.new_instruction.bytes,addr):
                    i.old_instruction = i.new_instruction
                    i.new_instruction = n
            except Exception as e:
                print("Errore in update_instr(): ",e)
                print('Indirizzo: ',hex(i.new_instruction.address))
                continue

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
        for v in self.label_table:
            print(hex(v))

    
    def create_jmp_table(self):
        for instr in self.instructions:
            if instr.old_instruction.id == x86_const.X86_INS_JMP and instr.old_instruction.operands[0].type == x86_const.X86_OP_REG:
                if instr.prev_instruction.new_instruction.mnemonic == 'add' and instr.prev_instruction.prev_instruction.new_instruction.mnemonic == 'mov':
                    indirizzo_jmp_table = estrai_valore(instr.prev_instruction.prev_instruction.new_instruction.op_str)
                    self.jump_table.append(indirizzo_jmp_table)

        self.jump_table.sort()

        for n,i in enumerate(self.jump_table):
            start = i
            end = 0
            x = 0
            if n != len(self.jump_table) - 1:
                while (i + x*4 < self.jump_table[n+1]):
                    addr = self.pe.get_dword_at_rva(i + x*4)
                    is_an_instruction = False
                    for instr in self.instructions:
                        if instr.original_instruction.address == addr:
                            is_an_instruction = True
                            break
                    if is_an_instruction == False:
                        break
                    x += 1           
                end = i + x*4 
            self.start_end_table.append((start,end))


    
    def print_jmp_table(self):
        with open('jmp_table.txt', 'r+') as f:
            for i in self.jump_table:
                f.write(hex(i) + '\n')
            f.write('\n\n\n####################\n\n\n')
            for i in self.start_end_table:
                f.write(hex(i[0]) + ' ' + hex(i[1]) + '\n')
                    
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

        self.pe.write(file)
                    
    def check_if_inside_jmp_table(self,address):
        inside_jmp_table = False
        for jmp in self.start_end_table:
            if address >= jmp[0] and address <= jmp[1]:
                inside_jmp_table = True

        return inside_jmp_table

    def create_label_table(self):
        lt = []
        for instr in self.instructions:
            inside_jmp_table = self.check_if_inside_jmp_table(instr.original_instruction.address)
            if inside_jmp_table == True:
                continue
            
            if instr.new_instruction.mnemonic == '.byte':
                continue

            if (x86_const.X86_GRP_JUMP in instr.new_instruction.groups) or (x86_const.X86_GRP_CALL in instr.new_instruction.groups):
                if 'ptr' not in instr.new_instruction.op_str:
                    addr = estrai_valore(instr.new_instruction.op_str)
                    if addr not in lt:
                       lt.append(addr)
        lt.sort()
        with open('label_table.txt', 'r+') as f:
            for i in lt:
                f.write(hex(i) + '\n')
        self.label_table = lt


    def insert_instruction(self,index,instruction):
        self.instructions[index - 1].next_instruction = instruction
        self.instructions[index].prev_instruction = instruction

        instruction.prev_instruction = self.instructions[index - 1]
        instruction.next_instruction = self.instructions[index]

        self.instructions.insert(index,instruction)


# tutte le jumps piu' piccole di 7 byte vengono portate a 7 byte
    def pad_jumps(self):

        bytes_needed = 0
        for num_instr,instr in enumerate(self.instructions):
            try:
                if instr.new_instruction.mnemonic == '.byte':
                    continue
                if (x86_const.X86_GRP_JUMP in  instr.new_instruction.groups) or (x86_const.X86_GRP_CALL in instr.new_instruction.groups):
                    max_length = 7
                    if len(instr.new_instruction.bytes) < max_length:
                        nop_num = max_length - len(instr.new_instruction.bytes)
                        bytes_needed += nop_num

                        asm = bytearray(instr.new_instruction.bytes)
                        for i in range(nop_num):
                            asm.append(0x90)
                        for x,i in enumerate(self.cs.disasm(asm, instr.new_instruction.address)):
                            if x == 0:
                                instr.new_instruction = i
                            else:
                                insr = Instruction(i,i,i,None,None)
                                self.insert_instruction(num_instr + x, insr)
            except Exception as e:
                print("Errore: ",e)
                continue
        print("#########################################")
        print("BYTES ADDEDD for JUMPS Padding: ",hex(bytes_needed))
        print("#########################################")
#per aggiustare le istruzioni:
#1)iterare in cerca di jump: e estrarre il valore 
#2)controllare se nel mio dizionario esiste qualcosa con chiave il valore estratto
#3)in tal caso ri assemblare l' istruzione cambiando il valore a dict[valore].new_instruction.address


    def update_label_table(self):

        re_iterate = True
        while re_iterate == True:
            self.update_instr()
            re_iterate = False
            for num_instr,instr in enumerate(self.instructions):
                if instr.new_instruction.mnemonic == '.byte':
                    continue

                if (x86_const.X86_GRP_JUMP in  instr.new_instruction.groups) or (x86_const.X86_GRP_CALL in instr.new_instruction.groups):

                    if 'ptr' in instr.new_instruction.op_str:
                        continue
                    addr = estrai_valore(instr.original_instruction.op_str)
                    if addr in self.label_table:
                    #     for instr2 in self.instructions:
                        try:
                            if self.instr_dict[addr] is not None:
                                instr2 = self.instr_dict[addr]
                                if instr2.original_instruction.address == addr:
                                    new_str = f"{instr.new_instruction.mnemonic} {hex(instr2.new_instruction.address)}"
                                    asm,_ = self.ks.asm(new_str,instr.new_instruction.address)
                                    asm = bytearray(asm)
                                    if(len(asm) < instr.new_instruction.size):
                                        print("Indirizzo: ",hex(instr.new_instruction.address))
                                        print('Istruzione: ',instr.new_instruction.mnemonic,instr.new_instruction.op_str)
                                        print("lunghezza asm: ",len(asm))
                                        nop_num = instr.new_instruction.size - len(asm)
                                        for i in range(nop_num):
                                            asm.append(0x90)
                                        for x,i in enumerate(self.cs.disasm(asm, instr.new_instruction.address)):
                                            if x == 0:
                                                instr.new_instruction = i
                                            else:
                                                insr = Instruction(i,i,i,None,None)
                                                self.insert_instruction(num_instr + x, insr)
                                    elif(len(asm) == instr.new_instruction.size):
                                        for i in self.cs.disasm(asm,instr.new_instruction.address):
                                            instr.new_instruction = i
                                    else:
                                        re_iterate = True
                                        print(f" {hex(instr.new_instruction.address)} SOSPETTO: len(asm) > instr2.new_instruction.size")

                                        for i in self.cs.disasm(asm,instr.new_instruction.address):
                                            instr.new_instruction = i
                                        original_length = len(instr.new_instruction.bytes)

                                        instr2 = self.instr_dict[addr]
                                        new_str = f"{instr.new_instruction.mnemonic} {hex(instr2.new_instruction.address)}"
                                        asm,_ = self.ks.asm(new_str,instr.new_instruction.address)
                                        asm = bytearray(asm)

                                        for i in self.cs.disasm(asm,instr.new_instruction.address):
                                            instr.new_instruction = i

                                        if len(asm) != original_length:
                                            print('e che cazzo pero')
                        except Exception as e:
                            print("Errore in update_label_table(): ",e)
                            continue



    def adjust_out_text_references(self):
        re_iterate = True
        while re_iterate == True:
            re_iterate = False
            self.update_instr()
            for num_instr,instr in enumerate(self.instructions):
                inside_jmp_table = self.check_if_inside_jmp_table(instr.original_instruction.address)
                if inside_jmp_table == True:
                    continue

                if instr is not None:
                    if ('rip +' in instr.new_instruction.op_str):
                        #print(hex(instr.original_instruction.address),instr.original_instruction.mnemonic,instr.original_instruction.op_str)
                        valore_originale = estrai_valore(instr.original_instruction.op_str)
                        if valore_originale == 0:
                            continue
                        if num_instr == len(self.instructions) - 1:
                            continue
                        addr = self.instructions[num_instr + 1].original_instruction.address + valore_originale

                        # print("valore_originale: ",valore_originale)
                        # print("nuovo indirizzo: ",hex(addr))
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



                        try:
                            asm, _ = self.ks.asm(new_string, instr.new_instruction.address)
                            asm = bytearray(asm)
                        except:
                            nuovi_bytes = offset.to_bytes(4, byteorder='little')
                            bytes_vecchi = valore_originale.to_bytes(4, byteorder='little')
                            asm = bytearray(instr.new_instruction.bytes.replace(bytes_vecchi,nuovi_bytes))
                            print('vecchi bytes: ',instr.new_instruction.bytes)
                            print('nuovi bytes: ',asm)



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
                        elif len(asm) == len(instr.new_instruction.bytes):
                            for i in self.cs.disasm(asm, instr.new_instruction.address):
                                instr.new_instruction = i
                        else:
                            print(f"{hex(instr.new_instruction.address)} SOSPETTO: len(asm) > instr2.new_instruction.size in out_refs rip+")
                            re_iterate = True

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
                        elif len(asm) == len(instr.new_instruction.bytes):
                            for i in self.cs.disasm(asm, instr.new_instruction.address):
                                instr.new_instruction = i
                        else:
                            print(f"{hex(instr.new_instruction.address)} SOSPETTO: len(asm) > instr2.new_instruction.size in out_refs rip-")
                            re_iterate = True
                else:
                    print("dentro adjust_out_text_references(), instr e' None")


    def insert_random_nop(self):
        for num_instr,instr in enumerate(self.instructions):
            if instr.new_instruction.mnemonic == '.byte':
                continue
            #checko che non sia dentro una jmp table della .text
            if self.check_if_inside_jmp_table(instr.original_instruction.address) == True:
                continue
            
            probability = random.randint(0,100)
            if probability < 10:
                nop_num = random.randint(1,3)
                for n in range(nop_num):
                    asm, _ = self.ks.asm("nop",(instr.new_instruction.address + instr.new_instruction.size) + n)
                    asm = bytearray(asm)
                    for x,i in enumerate(self.cs.disasm(asm, instr.new_instruction.address + instr.new_instruction.size + n)):
                        insr = Instruction(i,i,i,None,None)
                        self.insert_instruction(num_instr + 1 + n, insr)

    def update_old_instructions(self,instr):
        instr.old_instruction = instr.new_instruction


    #faccio il bogus control flow,
    #1) divido il codice in blocchi di (3-15) istruzioni e aggiungo alla fine di ogni blocco un jmp al blocco successivo
    #2) shufflo i blocchi

    def ultra_bogus_cf(self):
        for num_instr,instr in enumerate(self.instructions):
            try:
                if instr.new_instruction.mnemonic == '.byte':
                    continue
                #checko che non sia dentro una jmp table della .text
                if self.check_if_inside_jmp_table(instr.original_instruction.address) == True:
                    continue
                if 'ret' in self.instructions[num_instr+1].new_instruction.mnemonic:
                    continue

                probability = random.randint(0,100)
                if probability < 15:
                    #asm = bytearray([0xeb,0x00])
                    #asm, _ = self.ks.asm("",(instr.new_instruction.address + instr.new_instruction.size))
                    asm = bytearray([0xEB,0x00])
                    for x,i in enumerate(self.cs.disasm(asm, instr.new_instruction.address + instr.new_instruction.size )):
                        insr = Instruction(i,i,i,None,None)
                        self.insert_instruction(num_instr + 1 , insr)

            except Exception as e:
                print("Errore in ultra_bogus_cf(): ",e)
                continue


    #for testing purposes on other file (bcuz it still doesn't work)
    def one_equal_instruction(self):
        for num_instr,instr in enumerate(self.instructions):
            #substitue xor reg,rex with mov reg,0x0
            if(instr.old_instruction.id == x86_const.X86_INS_XOR and instr.old_instruction.operands[0].type == x86_const.X86_OP_REG and instr.old_instruction.operands[1].type == x86_const.X86_OP_REG):
                if instr.old_instruction.operands[0].reg == instr.old_instruction.operands[1].reg:
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
                    #self.update_old_instructions(instr)             
                    bytes_added += (len(bytes_arr) - len(instr.old_instruction.bytes)) 
                    change_num += 1
                    if change_num == 2:
                        break

    def equal_instructions(self):
        change_num = 0
        bytes_added = 0
        for num_instr,instr in enumerate(self.instructions):
            #substitue xor reg,rex with mov reg,0x0
            if(instr.old_instruction.id == x86_const.X86_INS_XOR and instr.old_instruction.operands[0].type == x86_const.X86_OP_REG and instr.old_instruction.operands[1].type == x86_const.X86_OP_REG):
                if instr.old_instruction.operands[0].reg == instr.old_instruction.operands[1].reg:
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
                    #self.update_old_instructions(instr)             
                    bytes_added += (len(bytes_arr) - len(instr.old_instruction.bytes)) 
                    change_num += 1
                    if change_num == 2:
                        #break
                        continue
            #substitute add reg, x  with sub reg, -x
            elif (instr.old_instruction.id == x86_const.X86_INS_ADD and instr.old_instruction.operands[0].type == x86_const.X86_OP_REG and instr.old_instruction.operands[1].type == x86_const.X86_OP_IMM):
                print("ADDRESS DEL PRIMO ADD: ", hex(instr.old_instruction.address))
                str_instr = f"sub {instr.old_instruction.reg_name(instr.old_instruction.operands[0].reg)},{-instr.old_instruction.operands[1].imm}"
                asm, _ = self.ks.asm(str_instr, instr.old_instruction.address)
                bytes_arr = bytearray(asm)
                for i in self.cs.disasm(bytes_arr,instr.new_instruction.address):
                    print("vecchia istruzione: ", instr.old_instruction.mnemonic, instr.old_instruction.op_str)
                    print("nuova istruzione: ", i.mnemonic, i.op_str)
                    instr.new_instruction = i
                bytes_added += (len(bytes_arr) - len(instr.old_instruction.bytes))
                change_num += 1
                if change_num == 2:
                    #break
                    continue
            #substitute sub reg, x with add reg, -x
            elif (instr.old_instruction.id == x86_const.X86_INS_SUB and instr.old_instruction.operands[0].type == x86_const.X86_OP_REG and instr.old_instruction.operands[1].type == x86_const.X86_OP_IMM):
                print("ADDRESS DEL PRIMO SUB: ", hex(instr.old_instruction.address))
                str_instr = f"add {instr.old_instruction.reg_name(instr.old_instruction.operands[0].reg)},{-instr.old_instruction.operands[1].imm}"
                asm, _ = self.ks.asm(str_instr, instr.old_instruction.address)
                bytes_arr = bytearray(asm)
                for i in self.cs.disasm(bytes_arr,instr.new_instruction.address):
                    print("vecchia istruzione: ", instr.old_instruction.mnemonic, instr.old_instruction.op_str)
                    print("nuova istruzione: ", i.mnemonic, i.op_str)
                    instr.new_instruction = i
                bytes_added += (len(bytes_arr) - len(instr.old_instruction.bytes))
                change_num += 1
                if change_num == 2:
                    #break
                    continue
            #transform push r/m8/32 in (mov rax, r/m8/32; push rax)
            elif (self.push_mov == True and instr.old_instruction.id == x86_const.X86_INS_PUSH):
                if (instr.old_instruction.operands[0].type == x86_const.X86_OP_REG):
                    print("ADDRESS DEL PRIMO PUSH: ", hex(instr.old_instruction.address))
                    str_instr = f"mov rax,{instr.old_instruction.op_str}"
                    asm, _ = self.ks.asm(str_instr, instr.old_instruction.address)
                    bytes_arr = bytearray(asm)
                    for i in self.cs.disasm(bytes_arr,instr.new_instruction.address):
                        print("vecchia istruzione: ", instr.old_instruction.mnemonic, instr.old_instruction.op_str)
                        print("nuova istruzione: ", i.mnemonic, i.op_str)
                        instr.new_instruction = i
                    str_instr2 = f"push {instr.old_instruction.op_str}"
                    addr = instr.old_instruction.address + len(bytes_arr)
                    asm, _ = self.ks.asm(str_instr2, addr)
                    bytes_arr = bytearray(asm)
                    for i in self.cs.disasm(bytes_arr,addr):
                        insr = Instruction(i,i,i,None,None)
                        self.insert_instruction(num_instr + 1, insr)

                    bytes_added += (len(bytes_arr) - len(instr.old_instruction.bytes))
                    change_num += 1
                    if change_num == 2:
                        #break
                        continue

        print("##########################################")
        print("BYTES ADDED: ",hex(bytes_added))
        print("##########################################")


    def adjust_reloc_table(self):
        for entries in self.pe.DIRECTORY_ENTRY_BASERELOC:
            for reloc in entries.entries:
                data = self.pe.get_qword_at_rva(reloc.rva)
                data = data - self.pe.OPTIONAL_HEADER.ImageBase
                #print(hex(reloc.rva), reloc.type,hex(data))#, reloc.value)

                # for instr in self.instructions:
                #     if instr.original_instruction.address == data:
                try:
                    if self.instr_dict[data] is not None:
                        instr = self.instr_dict[data]
                        # print("Trovato un reloc che punta ad un'istruzione")
                        # print(hex(reloc.rva), reloc.type,hex(data))
                        #rint("nella reloc: ",hex(data))
                        #print("nella istruzione: ",hex(instr.new_instruction.address))
                        self.pe.set_qword_at_rva(reloc.rva, instr.new_instruction.address + self.pe.OPTIONAL_HEADER.ImageBase)
                except Exception as e:
                    continue
        self.pe.write(file)


                        
    def locate_by_address(self, address):
        instr = self.instr_dict[address]            
        if instr.original_instruction.address == address:
            return instr
        return None
    

    def write_pe_file(self):
        new_bytes = b''
        for i in self.instructions:
            new_bytes += i.new_instruction.bytes
        
        length = self.original_code_length

        new_bytes = new_bytes[:length]
        # gap = self.pe.OPTIONAL_HEADER.SectionAlignment - (len(new_bytes) % self.pe.OPTIONAL_HEADER.SectionAlignment)

        # gap_bytes = (bytearray([0 for _ in range(gap)]))
        # new_bytes += gap_bytes
        new_entry_point = self.locate_by_address(self.original_entry_point).new_instruction.address
        

        #indirizzo dove viene salvato l'entry point
        entry_point_addr = self.pe.DOS_HEADER.e_lfanew + 0x28
        
        with open(file, "r+b") as f:

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

    file = 'hello_world.exe'
    #file = "C:\\Users\\jak\\Downloads\\PE-bear_0.6.7.3_qt4_x86_win_vs10\\PE-bear - Copia.exe"
    #file = 'C:\\Users\\jak\\Desktop\\reverse.exe'
    increase_text.increase_text_final(0x7000,file)
    zone = Zone(file)

    zone.print_instructions()


    zone.create_jmp_table()
    zone.print_jmp_table()

    #zone.pad_jumps()


    zone.create_label_table()
####################################
    #zone.equal_instructions()
    #
    #zone.insert_random_nop()
    zone.ultra_bogus_cf()
#####################################

    #zone.update_address()
    zone.print_instructions()

    #zone.update_instr()

    zone.update_label_table()


    zone.adjust_out_text_references()



    zone.adjust_reloc_table()
    zone.adjust_jmp_table()

    zone.print_instructions()


    zone.write_pe_file()
 

