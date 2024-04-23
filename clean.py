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
#   2) verificare se durante l'assemblaggio il numero di byte dell'istruzione e' cambiato
#       2.1) verificare se la stringa del disassemblaggio e' uguale alla stringa dell'assemblaggio	
#       2.2) se la grandezza nuova e'minore della grandezza vecchia, --> aggiungere NOP fino a raggiungere la grandezza vecchia
#           2.2.1) creare un metodo per inserire istruzioni
#                2.2.2) prev_instr = self.instructions[i], next_instr = self.instructions[i+1]

#STRUTTURA COSE DA FARE
#0) inizializzare tutto                                                                         FATTO!                                       
#1) dumpare la .text                                                                            FATTO!
#2) disassemblare la .text e aggiungere le istruzioni alla lista self.instructions              FATTO!
#3) creare le label table                                                                       FATTO!       
#4) modificare un'istruzione (solo per testing)                                                 FATTO!
#5) aggiornare (incrementare) le varie istruzioni                                               FATTO!
#6) aggiornare le varie jump o varie references   
#7) controllare tutte istruzioni con 'rip +' dentro (sono istruzioni che puntano alla .data)
#   7.1) similmente alle jump, calcolare l' indirizzo grazie all'indirizzo originale
#8) scrivere il PE
#
#
from capstone import *   #e' un disassembler
from keystone import *   #e' un assembler
import sys
import pefile
import time
import os
import re
from capstone import x86_const

def get_text_section(pe, address):
    #return pe.O
    for section in pe.sections:
        if section.contains_rva(address):
            print(section.Name, hex(section.VirtualAddress),hex(section.Misc_VirtualSize), section.SizeOfRawData )
            return section

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
        self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
        
        self.pe = pefile.PE("hello_world.exe")

        self.label_table = []
        self.instructions = []

        self.original_entry_point = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.base_address = self.pe.OPTIONAL_HEADER.BaseOfCode
        self.code_section = get_text_section(self.pe, self.base_address)
        self.code_section_size = self.code_section.Misc_VirtualSize

        print(f"Original entry point: {hex(self.original_entry_point)}")
        print(f"Base address: {hex(self.base_address)}")
        print(f"Code section size: {hex(self.code_section_size)}")

        self.raw_code = self.code_section.get_data(self.base_address, self.code_section_size)
        self.original_code_length = len(self.raw_code)



        for i in self.cs.disasm(self.raw_code, self.base_address):
            self.instructions.append(Instruction(i,i,i,None,None))


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
            addr = i.prev_instruction.new_instruction.address + i.prev_instruction.new_instruction.size


            for n in self.cs.disasm(i.new_instruction.bytes,addr):
                i.new_instruction = n

    def print_instructions(self):
        for x,i in enumerate(self.instructions):
            print(hex(i.new_instruction.address),i.new_instruction.mnemonic, i.new_instruction.op_str)
            if x > 35:
                break

    def print_label_table(self):
        for k,v in self.label_table.items():
            print(hex(k),v.new_instruction.mnemonic, v.new_instruction.op_str)


    def create_label_table(self):
        lt = dict()

        for instr in self.instructions:
            if (x86_const.X86_GRP_JUMP in instr.new_instruction.groups) or (x86_const.X86_GRP_CALL in instr.new_instruction.groups):
                if(instr.new_instruction.operands[0].type == x86_const.X86_OP_IMM):
                    addr = instr.new_instruction.operands[0].imm
                    lt[addr] = instr

        self.label_table = lt

    def update_label_table(self):
        for x,instr in enumerate(self.instructions):
            if (instr.original_instruction.address in self.label_table):
                new_str = self.label_table[instr.original_instruction.address].new_instruction.mnemonic + ' ' + instr.new_instruction.address

                asm, _ = self.ks.asm(new_str, self.label_table[instr.original_instruction.address].new_instruction.address)
                bytes_arr = bytearray(asm)
                if len(bytes_arr) < instr.new_instruction.size:
                    print("ERRORE DI MERDA")
                    diff = instr.new_instruction.size - len(bytes_arr)
                    #insert_instruction
                for i in self.cs.disasm(bytes_arr, self.label_table[instr.original_instruction.address].new_instruction.address):
                    self.label_table[instr.original_instruction.address].new_instruction = i


    def update_old_instructions(self,instr):
        instr.old_instruction = instr.new_instruction

    def equal_instructions(self):
        for instr in self.instructions:

            if(instr.old_instruction.id == x86_const.X86_INS_XOR and instr.old_instruction.operands[0].type == x86_const.X86_OP_REG and instr.old_instruction.operands[1].type == x86_const.X86_OP_REG):

                print("ADDRESS DEL PRIMO XOR EAX,EAX: ", hex(instr.old_instruction.address))
                str_instr = f"mov {instr.old_instruction.reg_name(instr.old_instruction.operands[0].reg)},0x0"
                asm, _ = self.ks.asm(str_instr, instr.old_instruction.address)

                bytes_arr = bytearray(asm)


                for i in self.cs.disasm(bytes_arr,instr.new_instruction.address):
                    print("vecchia istruzione: ", instr.old_instruction.mnemonic, instr.old_instruction.op_str)
                    print("nuova istruzione: ", i.mnemonic, i.op_str)
                    instr.new_instruction = i
                    #instr.update_address(num_bytes)    
                self.update_old_instructions(instr)              

                break




if __name__ == '__main__':
    zone = Zone()
    zone.print_instructions()
    zone.create_label_table()
    zone.equal_instructions()
    zone.update_instr()
    zone.print_instructions()


