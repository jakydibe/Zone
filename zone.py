# planning del refactoring
# 1) disassemblare 
#   1.1) creare la lista dinamica di istruzioni
#   1.2) creare il dizionario di istruzioni
# 
# 
# 
# 
# 
# 
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
import zone_utils
import increase_text


# una classe che rappresenta un istruzione in tutte le sue forme, attuale, vecchia, originale, precedente e prossima
class Instruction:
    def __init__(self,new_instruction,old_instruction,original_instruction,prev_instruction,next_instruction):
        self.new_instruction = new_instruction
        self.old_instruction = old_instruction
        self.original_instruction = original_instruction
        self.prev_instruction = prev_instruction
        self.next_instruction = next_instruction
        self.address_history = []


class Zone:
    def __init__(self, file):


        # inizializzo il disassembler
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True
        self.cs.skipdata = True #utile per skippare dati inutili nella .text (tipo stringhe o tabelle di jump)

        self.reg_list64 = ['rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp','r8','r9','r10','r11','r12','r13','r14','r15']
        self.reg_list32 = ['eax','ebx','ecx','edx','esi','edi','ebp','esp','r8d','r9d','r10d','r11d','r12d','r13d','r14d','r15d']
        self.reg_list16 = ['ax','bx','cx','dx','si','di','bp','sp','r8w','r9w','r10w','r11w','r12w','r13w','r14w','r15w']
        self.reg_list8 = ['al','bl','cl','dl','sil','dil','bpl','spl','r8b','r9b','r10b','r11b','r12b','r13b','r14b','r15b']
        self.reg_list8h = ['ah','bh','ch','dh']
        self.reg_lists = [self.reg_list64,self.reg_list32,self.reg_list16,self.reg_list8,self.reg_list8h]


        self.no_ops_templates = ['nop','sub','add','mov','lea','push','or','xor','and','inc','sar','shr','shl','rcl','rcr']

        self.file = file

        # inizializzo l'assembler
        self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
        
        self.push_mov = False
        self.pe = pefile.PE(file)


        # lista di tuple (istruzione, indirizzo) per tutte le jmp/call che puntano a indirizzi dentro la .text
        self.short_label_table = []
        self.far_label_table = []

        #lista dinamica globale di istruzioni
        self.instructions = []

        #lista di jump table (causate da switch-cases)
        self.jump_table = []
        
        # lista di tuple (start,end) per le jump table, utile per verificare se un indirizzo e' dentro una jump table
        self.start_end_table = []

        #dizionario di istruzioni, molto utile dal punto di vista delle performance(tempo di accesso costante)
        self.instr_dict = {}
        self.updated_instr_dict = {}


        # alcuni valori utili per la modifica del file presi dagli header del PE
        self.original_entry_point = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.base_address = self.pe.OPTIONAL_HEADER.BaseOfCode
        self.code_section = zone_utils.get_text_section(self.pe, self.base_address)
        self.code_section_size = self.code_section.Misc_VirtualSize

        self.rdata_section = zone_utils.get_section(self.pe, b'.rdata\x00\x00')


        #sono i bytes che posso inserire senza dover incrementare la .text
        self.padding_bytes = self.rdata_section.VirtualAddress - self.code_section.VirtualAddress - self.code_section_size
        self.added_bytes = 0

        print(f"Padding bytes: {self.padding_bytes}")
        self.data_directories = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY

        self.code_raw_start = self.code_section.PointerToRawData
        print(f"Original entry point: {hex(self.original_entry_point)}")
        print(f"Base address: {hex(self.base_address)}")
        print(f"Code section size: {hex(self.code_section_size)}")


        # raw bytes della sezione .text
        self.raw_code = self.code_section.get_data(self.base_address, self.code_section_size)

        # lunghezza del codice originale
        self.original_code_length = len(self.raw_code)

        self.bytes_to_add = []



        #con questo ciclo apro il file instr.txt e ci scrivo le istruzioni disassemblate
        with open('instr.txt', 'r+') as f:
            begin = self.base_address
            end = self.base_address + self.code_section_size


            #con questo ciclo mi assicuro di disassemblare tutto il codice
            while True:
                last_address = 0
                last_size = 0
                print(f"begin: {hex(begin)}")
                print(f"end: {hex(end)}")
                time.sleep(1)

                print("CICLO\n")
                #con questo ciclo itero tutte le istruzioni e le aggiungo a self.instructions e a self.instr_dict
                for i in self.cs.disasm(self.raw_code[begin-self.base_address:end], begin):
                    
                    # creo un oggetto Instruction e lo aggiungo alla lista di istruzioni
                    instruction = Instruction(i,i,i,None,None) 
                    instruction.address_history.append(i.address)
                    self.instructions.append(instruction)


                    #questo dizionario ci potro' accedere con la chiave dell' indirizzo originale
                    self.instr_dict[i.address] = instruction
                    #questo dizionario ci potro' accedere con la chiave dell' precedente, e' molto utile in futuro
                    self.updated_instr_dict[i.address] = instruction

                

                    stringa = f"{hex(i.address)} {i.bytes} {i.size}  {i.mnemonic}  {i.op_str}\n"
                    last_address = i.address
                    last_size = i.size
                    f.write(stringa)

                

                
                if begin >= end:
                    break


                begin = max(int(last_address),begin) + last_size


        print("FINITO DI DISASSEMBLARE")
        #self.cs.skipdata = False

        #assegno i prev_instruction e next_instruction
        for x,instr in enumerate(self.instructions):
            instr.new_bytes = instr.new_instruction.bytes

            if x == 0:
                continue
            instr.prev_instruction = self.instructions[x-1]
            if x == len(self.instructions)-1:
                continue
            instr.next_instruction = self.instructions[x+1]



    def create_label_table(self):
        print("CREO LABEL TABLE")
        for instr in self.instructions:
            try:
                inside_jmp_table = self.check_if_inside_jmp_table(instr.original_instruction.address)
                if inside_jmp_table == True:
                    continue
                
                if instr.new_instruction.mnemonic == '.byte':
                    continue

                if (x86_const.X86_GRP_JUMP in instr.new_instruction.groups) or (x86_const.X86_GRP_CALL in instr.new_instruction.groups):
                    if ('ptr' not in instr.new_instruction.op_str) and instr.new_instruction.operands[0].type != x86_const.X86_OP_REG:
                        addr = zone_utils.estrai_valore(instr.new_instruction.op_str)
                        self.short_label_table.append((instr, self.instr_dict[addr]))
            except Exception as e:
                print("Errore in create_label_table(): ",e)
                continue


        # self.short_label_table.sort()




    def update_instr(self):
        print("UPDATE INSTR")
        
        new_instr_dict = {}
        for x,i in enumerate(self.instructions):
            try:

                if x == 0:
                    continue
                addr = i.prev_instruction.new_instruction.address + len(i.prev_instruction.new_instruction.bytes)

                old_addr = i.old_instruction.address

                for n in self.cs.disasm(i.new_instruction.bytes,addr):
                    i.old_instruction = i.new_instruction

                    new_instr_dict[i.old_instruction.address] = i
                    i.address_history.append(n.address)

                    i.new_instruction = n


            except Exception as e:
                print("Errore in update_instr(): ",e)
                print('Indirizzo: ',hex(i.new_instruction.address))
                continue
        self.updated_instr_dict = new_instr_dict
        with open('dict.txt', 'r+') as f:
            for key in self.updated_instr_dict:
                stringa = f"{hex(key)} {hex(self.updated_instr_dict[key].new_instruction.address)}\n"
                f.write(stringa)
    def print_instructions(self):
        with open('instr_2.txt', 'r+') as f:

            for x,i in enumerate(self.instructions):
                stringa  = f"{hex(i.new_instruction.address)} {i.new_instruction.bytes} {len(i.new_instruction.bytes)}  {i.new_instruction.mnemonic}  {i.new_instruction.op_str}\n"
                f.write(stringa)

    def update_label_table(self):
        print("UPDATE LABEL TABLE")
        re_iterate = True
        num_iterazioni = 0

        inserted_instructions = False
        while re_iterate == True:
            print("ITERANDO: num_iterazioni: ",num_iterazioni)
            self.update_instr()
            re_iterate = False
            num_iterazioni += 1
            # try:

            for entry in self.short_label_table:

                if self.check_if_inside_jmp_table(entry[0].new_instruction.address) == True:
                    continue

                if (x86_const.X86_GRP_JUMP not in entry[0].new_instruction.groups) and (x86_const.X86_GRP_CALL not in entry[0].new_instruction.groups):
                    continue

                if (entry[0].new_instruction.operands[0].type == x86_const.X86_OP_REG):
                    continue
                
                if 'ptr' in entry[0].new_instruction.op_str:
                    continue


                index = self.instructions.index(entry[0])
                old_jump_address = zone_utils.estrai_valore(entry[0].new_instruction.op_str)


                if old_jump_address == 0:
                    print(entry[0].new_instruction.mnemonic, entry[0].new_instruction.op_str)
                


                jmp_addr = zone_utils.estrai_valore(entry[0].new_instruction.op_str)
                jmp_addr_ptr = entry[1].new_instruction.address

                if jmp_addr != jmp_addr_ptr:
                    original_length = len(entry[0].new_instruction.bytes)
                    str_instr = f"{entry[0].new_instruction.mnemonic} {hex(jmp_addr_ptr)}"
                    asm, _ = self.ks.asm(str_instr, entry[0].new_instruction.address)
                    bytes_arr = bytearray(asm)

                    new_length = len(bytes_arr)
                    if original_length != new_length:
                        # if new_length >= 6:
                        #     print("\n\nSTRANISSIMO NEW_LENGTH >= 6!!!!!")
                        #     print("Indirizzo: ",hex(entry[0].new_instruction.address))
                        #     for i in self.cs.disasm(bytes_arr,entry[0].new_instruction.address):
                        #         entry[0].new_instruction = i

                        #     re_iterate = True
                        #     # exit(0)
                        if original_length > new_length:
                            diff = original_length - new_length
                            for _ in range(diff):
                                bytes_arr.append(0x90)
                            
                            for x,i in enumerate(self.cs.disasm(bytes_arr,entry[0].new_instruction.address)):
                                if x == 0:
                                    entry[0].new_instruction = i
                                else:
                                    new_instr = Instruction(i,i,i,None,None)
                                    new_instr.address_history.append(i.address)
                                    self.insert_instruction(index+x,new_instr)
                                    inserted_instructions = True
                        elif new_length > original_length:
                            re_iterate = True
                            diff = new_length - original_length

                            print("NEW_LEN > ORIG_LEN")
                            for i in self.cs.disasm(bytes_arr,entry[0].new_instruction.address):
                                entry[0].new_instruction = i

                            new_str = f"{entry[0].new_instruction.mnemonic} {entry[1].new_instruction.address}"
                            new_asm, _ = self.ks.asm(new_str, entry[0].new_instruction.address)
                            new_bytes = bytearray(new_asm)
                            for x,i in enumerate(self.cs.disasm(new_bytes,entry[0].new_instruction.address)):
                                entry[0].new_instruction = i

                    else:
                        for i in self.cs.disasm(bytes_arr,entry[0].new_instruction.address):
                            entry[0].new_instruction = i




    def adjust_out_text_references(self):
        re_iterate = True
        inserted_instructions = False
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
                        valore_originale = zone_utils.estrai_valore(instr.original_instruction.op_str)
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
                                        insr.address_history.append(i.address)
                                        self.insert_instruction(num_instr + x, insr)
                                        inserted_instructions = True
                        elif len(asm) == len(instr.new_instruction.bytes):
                            for i in self.cs.disasm(asm, instr.new_instruction.address):
                                instr.new_instruction = i
                        else:
                            print(f"{hex(instr.new_instruction.address)} SOSPETTO: len(asm) > instr2.new_instruction.size in out_refs rip+")
                            re_iterate = True

                    elif ('rip -' in instr.new_instruction.op_str):
                        #print(hex(instr.original_instruction.address),instr.original_instruction.mnemonic,instr.original_instruction.op_str)
                        valore_originale = zone_utils.estrai_valore(instr.original_instruction.op_str)
                        # print("valore_originale: ",valore_originale)
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
                                        insr.address_history.append(i.address)
                                        self.insert_instruction(num_instr + x, insr)
                                        inserted_instructions = True
                        elif len(asm) == len(instr.new_instruction.bytes):
                            for i in self.cs.disasm(asm, instr.new_instruction.address):
                                instr.new_instruction = i
                        else:
                            print(f"{hex(instr.new_instruction.address)} SOSPETTO: len(asm) > instr2.new_instruction.size in out_refs rip-")
                            re_iterate = True
                else:
                    print("dentro adjust_out_text_references(), instr e' None")


    def locate_by_address(self, address):
        instr = self.instr_dict[address]            
        if instr.original_instruction.address == address:
            return instr
        return None

    def adjust_reloc_table(self):
        for entries in self.pe.DIRECTORY_ENTRY_BASERELOC:
            for reloc in entries.entries:
                data = self.pe.get_qword_at_rva(reloc.rva)
                # print("data: ",hex(data))

                data = data - self.pe.OPTIONAL_HEADER.ImageBase
                # print(hex(reloc.rva), reloc.type,hex(data))#, reloc.value)

                # for instr in self.instructions:
                #     if instr.original_instruction.address == data:
                # try:

                if data not in self.instr_dict:
                    continue

                if self.instr_dict[data] is not None:
                    # print("RELOC: ",hex(reloc.rva))
                    instr = self.instr_dict[data]

                    self.pe.set_qword_at_rva(reloc.rva, instr.new_instruction.address + self.pe.OPTIONAL_HEADER.ImageBase)
                # except Exception as e:
                #     print("Errore in adjust_reloc_table(): ",e)
                #     continue
        self.pe.write(self.file)

    def insert_instruction(self,index,instruction):
        self.instructions[index - 1].next_instruction = instruction
        self.instructions[index].prev_instruction = instruction

        instruction.prev_instruction = self.instructions[index - 1]
        instruction.next_instruction = self.instructions[index]

        self.instructions.insert(index,instruction)
                

    def  insert_random_nop(self):

        inserted_nops = 0
        for num_instr,instr in enumerate(self.instructions):
            try:

                new_entry_point = self.original_entry_point

                if instr.new_instruction.address >= new_entry_point:
                    break
                if instr.new_instruction.mnemonic == '.byte':
                    continue
                #checko che non sia dentro una jmp table della .text
                if self.check_if_inside_jmp_table(instr.original_instruction.address) == True:
                    continue


                if inserted_nops >= 35:
                    break
                    # continue
                
                # le nop sono:  NOP, 
                #               XCHG REG,REG,   ----> PER ORA NON FUNZIONA
                #               SUB REG,0x0,    ----> FUNZIONA
                #               ADD REG,0x0,    ----> messa
                #               MOV REG, REG, 
                #               LEA REG, [REG+0],
                #               PUSH REG ----------- POP REG  ---> funziona (ESEGUIRE SOLO 1 volta, nop_num = 1)
                #               OR REG, REG
                #               XOR REG, 0x0
                #               AND REG, REG
                #               INC REG ----------- DEC REG
                #               DEC REG ----------- INC REG
                #               SAR REG, 0x0
                #               SHR REG, 0x0
                #               SHL REG, 0x0
                #               RCL REG, 0x0
                #               RCR REG, 0x0 
                asm = None
                operazione = None
                reg_list = None
                reg = None


                probability = random.randint(0,100)
                if probability < 10:

                    operazione = random.choice(self.no_ops_templates)
                    nop_num = random.randint(1,2)

                    # reg_list = random.choice(self.reg_lists)

                    reg = random.choice(self.reg_list64)

    # ['','','','','','','','','','','','','','','']

                    if operazione == 'nop':
                        asm, _ = self.ks.asm('nop', instr.new_instruction.address + instr.new_instruction.size)

                    if operazione == 'sub':
                        asm, _ = self.ks.asm(f'sub {reg},0x0', instr.new_instruction.address + instr.new_instruction.size)
                    
                    if operazione == 'add':
                        asm, _ = self.ks.asm(f'add {reg},0x0', instr.new_instruction.address + instr.new_instruction.size)
                    
                    if operazione == 'mov':
                        asm, _ = self.ks.asm(f'mov {reg},{reg}', instr.new_instruction.address + instr.new_instruction.size)

                    if operazione == 'lea':
                        asm, _ = self.ks.asm(f'lea {reg},[{reg}+0]', instr.new_instruction.address + instr.new_instruction.size)

                    if operazione == 'push':
                        nop_num = 1
                        asm, _ = self.ks.asm(f'pop {reg}; push {reg}', instr.new_instruction.address + instr.new_instruction.size)


                    if operazione == 'inc':
                        nop_num = 1
                        asm, _ = self.ks.asm(f'dec {reg}; inc {reg}', instr.new_instruction.address + instr.new_instruction.size)
                    
                    if operazione == 'sar':
                        asm, _ = self.ks.asm(f'sar {reg},0x0', instr.new_instruction.address + instr.new_instruction.size)
                    
                    if operazione == 'shr':
                        asm, _ = self.ks.asm(f'shr {reg},0x0', instr.new_instruction.address + instr.new_instruction.size)
                    
                    if operazione == 'shl':
                        asm, _ = self.ks.asm(f'shl {reg},0x0', instr.new_instruction.address + instr.new_instruction.size)
                    
                    if operazione == 'rcl':
                        asm, _ = self.ks.asm(f'rcl {reg},0x0', instr.new_instruction.address + instr.new_instruction.size)
                    
                    if operazione == 'rcr':
                        asm, _ = self.ks.asm(f'rcr {reg},0x0', instr.new_instruction.address + instr.new_instruction.size)
                    
                    if operazione == 'xor':
                        asm, _ = self.ks.asm(f'xor {reg},0x0', instr.new_instruction.address + instr.new_instruction.size)

                    if operazione == 'and':
                        asm, _ = self.ks.asm(f'and {reg},{reg}', instr.new_instruction.address + instr.new_instruction.size)

                    
                    if operazione == 'or':
                        asm, _ = self.ks.asm(f'or {reg},{reg}', instr.new_instruction.address + instr.new_instruction.size)
                    
                    # inserisco una jmp al prossimo indirizzo
                    # if operazione == 'jmp':
                    #     asm = bytearray([0xEB,0x00])


                    # asm, _ = self.ks.asm("nop", instr.new_instruction.address + instr.new_instruction.size)
                    # asm, _ = self.ks.asm(f'or {reg},{reg}', instr.new_instruction.address + instr.new_instruction.size)


                    # for n in range(nop_num):
                
                    asm = bytearray(asm)
                    for x,i in enumerate(self.cs.disasm(asm, instr.new_instruction.address + instr.new_instruction.size )):
                        insr = Instruction(i,i,i,None,None)
                        insr.address_history.append(i.address)

                        self.insert_instruction(num_instr + 1 + x, insr)
                    inserted_nops += 1
            except Exception as e:
                print("Errore in insert_random_nop(): ",e)

                print(f"{operazione} {reg}")
                continue


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
        
        with open(self.file, "r+b") as f:

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

    


    def update_old_instructions(self,instr):
        instr.old_instruction = instr.new_instruction

    def insert_instruction(self,index,instruction):
        try:
            self.instructions[index - 1].next_instruction = instruction
            self.instructions[index].prev_instruction = instruction



            instruction.prev_instruction = self.instructions[index - 1]
            instruction.next_instruction = self.instructions[index]

            self.instructions.insert(index,instruction)
        except Exception as e:
            print("Errore in insert_instruction(): ",e)
            print("Indirizzo: ",hex(instruction.new_instruction.address))


        
    def convert_raw_to_rva(self,raw_address,section):
        return raw_address + section.VirtualAddress - section.PointerToRawData
    
    def check_if_inside_jmp_table(self,address):
        inside_jmp_table = False
        for jmp in self.start_end_table:
            if address >= jmp[0] and address <= jmp[1]:
                inside_jmp_table = True

        return inside_jmp_table


    def create_jmp_table(self):
        print("CREO JUMP TABLE")
        for instr in self.instructions:
            if instr.old_instruction.id == x86_const.X86_INS_JMP and instr.old_instruction.operands[0].type == x86_const.X86_OP_REG:
                if instr.prev_instruction.new_instruction.mnemonic == 'add' and instr.prev_instruction.prev_instruction.new_instruction.mnemonic == 'mov':
                    indirizzo_jmp_table = zone_utils.estrai_valore(instr.prev_instruction.prev_instruction.new_instruction.op_str)
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

        self.pe.write(self.file)


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
                        insr = Instruction(i,i,None,None,None)
                        self.insert_instruction(num_instr + 1, insr)

                    bytes_added += (len(bytes_arr) - len(instr.old_instruction.bytes))
                    change_num += 1
                    if change_num == 2:
                        #break
                        continue
            # trasforma inc reg in add reg,1
            elif (instr.old_instruction.id == x86_const.X86_INS_INC and instr.old_instruction.operands[0].type == x86_const.X86_OP_REG):
                print("ADDRESS DEL PRIMO INC: ", hex(instr.old_instruction.address))
                str_instr = f"add {instr.old_instruction.reg_name(instr.old_instruction.operands[0].reg)},1"
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
            # trasforma dec reg in sub reg,1
            elif (instr.old_instruction.id == x86_const.X86_INS_DEC and instr.old_instruction.operands[0].type == x86_const.X86_OP_REG):
                print("ADDRESS DEL PRIMO DEC: ", hex(instr.old_instruction.address))
                str_instr = f"sub {instr.old_instruction.reg_name(instr.old_instruction.operands[0].reg)},1"
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
            # trasforma and reg

        print("##########################################")
        print("BYTES ADDED: ",hex(bytes_added))
        print("##########################################")




    

if __name__ == "__main__":

    increase_text.increase_text_final(0x7000,sys.argv[1])

    zone = Zone(sys.argv[1])

    zone.create_jmp_table()
    zone.create_label_table()
    zone.equal_instructions()
    zone.insert_random_nop()

    # zone.update_dict()


    zone.update_label_table()
    zone.adjust_out_text_references()

    zone.adjust_reloc_table()
    zone.adjust_jmp_table()

    zone.write_pe_file()
    zone.print_instructions()
    print("FINE")
