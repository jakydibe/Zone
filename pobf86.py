from capstone import *   #e' un disassembler
from keystone import *   #e' un assembler
import sys
import pefile
import time
# import lief
import os
import random
from capstone import x86_const
import zone_utils
import increase_text
import traceback
import asmjit
import subprocess

#blablablableblebleblublublublublublublublublublublublublu

# una classe che rappresenta un istruzione in tutte le sue forme, attuale, vecchia, originale, precedente e prossima
# a class that represents an instruction in all its forms, current, old, original, previous and next
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
        # initialize the disassembler
        self.cs = Cs(CS_ARCH_X86, CS_MODE_32)  #pip install capstone==5.0.0.post1 ONLY INSTALL THIS VERSION. ON OTHER VERSIONS IT DOES NOT WAR skipdataK
        self.cs.detail = True

        #utile per skippare dati inutili nella .text (tipo stringhe o tabelle di jump)
        # useful for skipping useless data in the .text (like strings or jump
        self.cs.skipdata = True 



        #list of registers 
        # self.reg_list32 = ['eax','ebx','ecx','edx','esi','edi','ebp','esp','r8d','r9d','r10d','r11d','r12d','r13d','r14d','r15d']
        # self.reg_list32 = ['eax','ebx','ecx','edx','esi','edi','ebp','esp']
        self.reg_list32 = ['eax','ebx','ecx','edx','esi','edi']

        self.reg_list16 = ['ax','bx','cx','dx','si','di','bp','sp']
        self.reg_list8 = ['al','bl','cl','dl','ah','bh','ch','dh']
        self.reg_lists = [self.reg_list32,self.reg_list16,self.reg_list8]

        # list of all the possible nop instructions
        # self.no_ops_templates = ['nop','sub','add','mov','lea','push','or','xor','and','inc','sar','shr','shl','rcl','rcr', 'jmp']
        self.no_ops_templates = ['nop','sub','add','mov','lea','or','xor','and','inc','sar','shr','shl','rcl','rcr', 'jmp']

        self.file = file

        self.bogus_probability = 20
        # inizializzo l'assembler
        # initialize the assembler
        self.ks = Ks(KS_ARCH_X86, KS_MODE_32)
        
        # i don't remember
        self.push_mov = False




        # blocks for future implementation of bogus control flow
        self.instr_blocks = []
        self.block_size = 7
        self.last_chosen_reg = None


        # lista di tuple (istruzione, indirizzo) per tutte le jmp/call che puntano a indirizzi dentro la .text
        # list of tuples (instruction, address) for all the jmp/call that point to addresses inside the .text, (I use only short for now)
        self.short_label_table = []
        self.far_label_table = []

        #lista dinamica globale di istruzioni
        # dynamic global list of instructions
        self.instructions = []

        #lista di jump table (causate da switch-cases)
        # list of jump tables (caused by switch-cases)
        self.jump_table = []
        
        # lista di tuple (start,end) per le jump table, utile per verificare se un indirizzo e' dentro una jump table
        # list of tuples (start,end) for the jump tables, useful to check if an address is inside a jump table
        self.start_end_table = []
        self.brain_blocks = []
        #dizionario di istruzioni, molto utile dal punto di vista delle performance(tempo di accesso costante)
        #  dictionary of instructions, very useful from a performance point of view (constant access time)
        self.instr_dict = {}
        # ductionary like instr_dict but with key updated to the old_instruction(not the original)
        self.updated_instr_dict = {}

        self.payload_size = 0
        
        self.stub_address = 0
        self.stub_size = 0
        self.mem_address = 0
        self.counter_address = 0
        self.instr_mapping = []
        self.stub2_address = 0
        self.stub2_bytearr = 0
        self.stub2_size = 0

        self.do_not_touch = []

        self.pii_enabled = False

        self.init_address = 0
        self.wrap_instruction_num = 5


        with open(self.file, "rb") as f:
            self.raw_code = f.read()
            f.close()


        # lunghezza del codice originale
        self.original_code_length = len(self.raw_code)
        self.equal_instructions_substitutions = 0
        self.base_address = 0

        self.nops_addedd = 0

        self.bytes_to_add = []



        #con questo ciclo apro il file instr.txt e ci scrivo le istruzioni disassemblate
        # just write instructions to .txt for debugging
        with open('instr_payload.txt', 'r+') as f:

            for i in self.cs.disasm(self.raw_code, 0):
                
                # creo un oggetto Instruction e lo aggiungo alla lista di istruzioni
                # new,old,original = i. prev and next will be assigned later
                instruction = Instruction(i,i,i,None,None) 
                instruction.address_history.append(i.address)
                self.instructions.append(instruction)


                #questo dizionario ci potro' accedere con la chiave dell' indirizzo originale
                self.instr_dict[i.address] = instruction
                #questo dizionario ci potro' accedere con la chiave dell' precedente, e' molto utile in futuro
                # this dictionary can be accessed with the key of the previous address, it is very useful in the future
                self.updated_instr_dict[i.address] = instruction

            
                # just to write to file
                stringa = f"{hex(i.address)} {i.bytes} {i.size}  {i.mnemonic}  {i.op_str}\n"
                last_address = i.address
                last_size = i.size
                f.write(stringa)

        

        print("FINITO DI DISASSEMBLARE")
        #self.cs.skipdata = False

        #assegno i prev_instruction e next_instruction
        # assign prev_instruction and next_instruction
        for x,instr in enumerate(self.instructions):
            instr.new_bytes = instr.new_instruction.bytes

            if x == 0:
                continue
            instr.prev_instruction = self.instructions[x-1]
            if x == len(self.instructions)-1:
                continue
            instr.next_instruction = self.instructions[x+1]



    # Per ogni istruzione JMP o CALL riferite ad elementi dentro la .text creo una tabella di label del tipo (istruzione,indirizzo a cui salto)
    # For each JMP or CALL instruction referring to elements inside the .text I create a label table of the type (instruction, address to which I jump)
    def create_label_table(self):
        print("CREO LABEL TABLE")
        for instr in self.instructions:
            try:
                # always check if the instruction is inside a jump table, and skip it if it is
                inside_jmp_table = self.check_if_inside_jmp_table(instr.original_instruction.address)
                if inside_jmp_table == True:
                    continue
                
                if instr.new_instruction.mnemonic == '.byte':
                    continue
                # checka se JUMP/CALL/LOOP
                if (x86_const.X86_GRP_JUMP in instr.new_instruction.groups) or (x86_const.X86_GRP_CALL in instr.new_instruction.groups) or (instr.new_instruction.mnemonic == 'loop'):
                    if ('ptr' not in instr.new_instruction.op_str) and instr.new_instruction.operands[0].type != x86_const.X86_OP_REG:
                        if instr.new_instruction.mnemonic == 'jrcxz':
                            print("JRCXZ")
                            # time.sleep(2)
                        elif instr.new_instruction.mnemonic == 'loop':
                            print("LOOP")
                            # time.sleep(2)
                        # addr = instr.new_instruction.address + 2
                        addr = zone_utils.estrai_valore(instr.new_instruction.op_str)
                        self.short_label_table.append((instr, self.instr_dict[addr]))
            except Exception as e:
                print("Errore in create_label_table(): ",e)
                print("Indirizzo: ",hex(instr.new_instruction.address))
                print("stringa: ",instr.new_instruction.mnemonic + '  ' + instr.new_instruction.op_str)

                traceback.print_exc()
                continue


        # self.short_label_table.sort()

    def generate_assembly_tautology(self):
    # List of common registers (excluding esp/ebp for simplicity)
        # registers = random.choice(self.reg_list32)
        # print("REGISTERS: ",registers)
        reg = random.choice(self.reg_list32)
        while True:
            if reg != self.last_chosen_reg:
                break
            reg = random.choice(self.reg_list32)
        self.last_chosen_reg = reg
        print("REG: ",reg)
        # Generate a random immediate value (for example, between 0 and 255)
        imm = random.randint(0, 255)
        
        # Choose a random pattern (from 1 to 15)
        pattern = random.randint(1,12)
        code = ""

        # per testing
        
        if pattern == 1:
            # Pattern 1: mov reg, imm; cmp reg, imm
            code = f"pushf;push {reg};mov {reg}, {imm};cmp {reg}, {imm};pop {reg};popf"
        elif pattern == 2:
            # Pattern 2: cmp reg, reg
            code = f"pushf;cmp {reg}, {reg};popf"
        elif pattern == 3:
            # Pattern 3: mov reg, imm; add reg, 0; cmp reg, imm
            code = f"pushf;push {reg};mov {reg}, {imm};add {reg}, 0;cmp {reg}, {imm}; pop {reg};popf"
        elif pattern == 4:
            # Pattern 4: mov reg, imm; sub reg, 0; cmp reg, imm
            code = f"pushf;push {reg};mov {reg}, {imm};sub {reg}, 0;cmp {reg}, {imm}; pop {reg};popf"
        elif pattern == 5:
            # Pattern 5: push imm; pop reg; cmp reg, imm
            code = f"pushf;push {reg};push {imm};pop {reg};cmp {reg}, {imm}; pop {reg};popf"
        elif pattern == 6:
            # Pattern 6: sub reg, reg; cmp reg, 0
            code = f"pushf;push {reg};sub {reg}, {reg};cmp {reg}, 0; pop {reg};popf"
        elif pattern == 7:
            # Pattern 7: xor reg, reg; cmp reg, 0
            code = f"pushf;push {reg}; xor {reg}, {reg};cmp {reg}, 0; pop {reg};popf"
        elif pattern == 8:
            # Pattern 9: mov reg, imm; neg reg; neg reg; cmp reg, imm
            code = f"pushf;push {reg}; mov {reg}, {imm};neg {reg};neg {reg};cmp {reg}, {imm}; pop {reg};popf"
        elif pattern == 9:
            # Pattern 10: mov reg, imm; or reg, 0; cmp reg, imm
            code = f"pushf;push {reg}; mov {reg}, {imm};or {reg}, 0;cmp {reg}, {imm}; pop {reg};popf"
        elif pattern == 10:
            # Pattern 11: mov reg, imm; and reg, 0xFFFFFFFF; cmp reg, imm
            code = f"pushf;push {reg};mov {reg}, {imm};and {reg}, 0xFFFFFFFF;cmp {reg}, {imm}; pop {reg};popf"
        elif pattern == 11:
            # Pattern 12: mov reg, imm; lea reg, [{reg}+0]; cmp reg, imm
            code = f"pushf;push {reg};mov {reg}, {imm};lea {reg}, [{reg}+0];cmp {reg}, {imm}; pop {reg};popf"
        elif pattern == 12:
            # Pattern 13: mov reg, imm; test reg, reg
            code = f"pushf;push {reg};mov {reg}, {imm};test {reg}, {reg}; pop {reg};popf"
        else:
            code = "nop"
        
        return code
    

    def bogus_control_flow(self):
        # SOLUZIONE ULTRA TEMPORANEA
        last_modification = 0
        re_iterate = True
        inserted_instr = 0

        while re_iterate == True:
            re_iterate = False

            self.update_instr()
            self.update_label_table()
            
            for num_instr,instr in enumerate(self.instructions):
                probability = random.randint(0,100)

                # print("NUM_INSTR: ",num_instr)
                # print("LAST_MODIFICATION: ",last_modification)
                # print("INSERTED_INSTR: ",inserted_instr)
                if num_instr < (last_modification + inserted_instr):
                    continue
                if probability < self.bogus_probability:
                    re_iterate = True
                    inserted_instr = 0

                    # trash_block = bytearray()

                    block_size = random.randint(5,10)

                    # appendi popf come pr
                    # for i in range(block_size):
                    #     trash_block.append(0x90)

                    code = self.generate_assembly_tautology()

                    if code == "nop":
                        continue
                    asm, _ = self.ks.asm(code, instr.new_instruction.address + instr.new_instruction.size)
                    asm = bytearray(asm)

                    NOP_NUM = random.randint(2,5)

                    code = code + ';je ' + hex(instr.new_instruction.address + instr.new_instruction.size + len(asm) + len(asm) + 2 + NOP_NUM*1)
                    
                    print("CODE: ",code)
                    last_modification = num_instr

                    asm2, _ = self.ks.asm(code, instr.new_instruction.address + instr.new_instruction.size + len(asm))
                    asm2 = bytearray(asm2)
                    for i in range(NOP_NUM):
                        # random_byte = random.randint(0,255)
                        asm2.append(0x90)
                    tmp_inserted_instr = 0
                    for x,i in enumerate(self.cs.disasm(asm2, instr.new_instruction.address + instr.new_instruction.size)):
                        new_instr = Instruction(i,i,i,None,None)
                        new_instr.address_history.append(i.address)
                        self.insert_instruction(num_instr + x,new_instr)
                        tmp_inserted_instr +=  1
                    # faccio break perche' dovro' fare la reiterazione
                    inserted_instr = tmp_inserted_instr
                    break
        ## DA RIFARE IN MODO GIUSTO
        # num_instr = 0
        # last_modification = 0
        # inserted_instr = 0
        # # index of last instruction
        # last_instruction_index = len(self.instructions) - 1 

        # new_index = 0
        # try:
        #     while True:
        #         instr = self.instructions[num_instr]
        #         probability = random.randint(0,100)

        #         if num_instr >= last_instruction_index:
        #             break

        #         if (num_instr - last_modification) < inserted_instr:
        #             num_instr += 1
        #             # print("Num_instr: ",num_instr)
        #             # print("inserted_instr: ",inserted_instr)
        #             continue
        #         if probability <= 10:
        #             inserted_instr = 0
        #             self.update_instr()
        #             self.update_label_table()
        #             trash_block = bytearray()

        #             block_size = random.randint(5,10)

        #             # appendi popf come pr
        #             for i in range(block_size):
        #                 trash_block.append(0x90)

        #             code = self.generate_assembly_tautology()

        #             if code == "nop":
        #                 continue
        #             asm, _ = self.ks.asm(code, instr.new_instruction.address + instr.new_instruction.size)
        #             asm = bytearray(asm)

        #             NOP_NUM = random.randint(2,5)

        #             code = code + ';je ' + hex(instr.new_instruction.address + instr.new_instruction.size + len(asm) + len(asm) + 2 + NOP_NUM*1)
                    
        #             print("CODE: ",code)

        #             asm2, _ = self.ks.asm(code, instr.new_instruction.address + instr.new_instruction.size + len(asm))
        #             asm2 = bytearray(asm2)
        #             for i in range(NOP_NUM):
        #                 asm2.append(0x90)
        #             for x,i in enumerate(self.cs.disasm(asm2, instr.new_instruction.address + instr.new_instruction.size)):
        #                 new_instr = Instruction(i,i,i,None,None)
        #                 new_instr.address_history.append(i.address)
        #                 self.insert_instruction(num_instr + x,new_instr)
        #                 inserted_instr +=  1
        #                 num_instr += 1
        #                 last_instruction_index += 1
        #             last_modification = num_instr
        #             continue
        #         num_instr += 1
        # except Exception as e:
        #     print("Errore in bogus_control_flow(): ",e)
        #     print("Indirizzo: ",hex(instr.new_instruction.address))
        #     print("stringa: ",instr.new_instruction.mnemonic + '  ' + instr.new_instruction.op_str)
        #     traceback.print_exc()
        #     pass`

    # after every change in the instructions list, I have to update the instr_dict
    # the update is made simply by iterating over the instructions list and updating the instr_dict and updating addresses of instructions
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

                    # also remember to update the dictionary
                    new_instr_dict[i.old_instruction.address] = i
                    i.address_history.append(n.address)

                    i.new_instruction = n

            except Exception as e:
                print("Errore in update_instr(): ",e)
                print('Indirizzo: ',hex(i.new_instruction.address))
                continue
        # also remember to update the dictionary
        self.updated_instr_dict = new_instr_dict
        with open('dict.txt', 'r+') as f:
            for key in self.updated_instr_dict:
                stringa = f"{hex(key)} {hex(self.updated_instr_dict[key].new_instruction.address)}\n"
                f.write(stringa)


    # just print the instructions to a file
    def print_instructions(self):
        with open('instr_payload2.txt', 'r+') as f:

            for x,i in enumerate(self.instructions):
                stringa  = f"{hex(i.new_instruction.address)} {i.new_instruction.bytes} {len(i.new_instruction.bytes)}  {i.new_instruction.mnemonic}  {i.new_instruction.op_str}\n"
                f.write(stringa)

    # this is some serious fucked up stuff
    # patch all JMP and CALL after some modifications




    def update_label_table(self):
        print("UPDATE LABEL TABLE")

        # if during patching some JMP or CALL becomes bigger (example 3 byte --> 5 byte)
        #   i need to re iterate the all patching process
        re_iterate = True
        num_iterazioni = 0

        do_not_touch_instr = []
        inserted_instructions = False
        while re_iterate == True:
            print("ITERANDO: num_iterazioni: ",num_iterazioni)
            # always update instructions beforse patching them, otherwise instructions addresses will be broken
            self.update_instr()
            re_iterate = False
            num_iterazioni += 1
            # try:

            # iterate the list of jmp/call instructions
            for entry in self.short_label_table:
                try:

                    # various checks 
                    if self.check_if_inside_jmp_table(entry[0].new_instruction.address) == True:
                        continue

                    if (x86_const.X86_GRP_JUMP not in entry[0].new_instruction.groups) and (x86_const.X86_GRP_CALL not in entry[0].new_instruction.groups) and (entry[0].new_instruction.mnemonic != 'loop'):
                        continue

                    if (entry[0].new_instruction.operands[0].type == x86_const.X86_OP_REG):
                        continue
                    # check if it is a jmp to far stuff (improbable), do not patch it here because it is patched in adjust_out_text_reference()
                    if 'ptr' in entry[0].new_instruction.op_str:
                        continue



                        # time.sleep(2)

                    # extract the jmp address from the string (yea i love python, so easy)
                    old_jump_address = zone_utils.estrai_valore(entry[0].new_instruction.op_str)


                    if old_jump_address == 0:
                        print(entry[0].new_instruction.mnemonic, entry[0].new_instruction.op_str)
                    


                    jmp_addr = zone_utils.estrai_valore(entry[0].new_instruction.op_str)
                    jmp_addr_ptr = entry[1].new_instruction.address
                    
                    index = self.instructions.index(entry[0])

                    # check if the jmp address is right
                    if jmp_addr != jmp_addr_ptr:

                        original_length = len(entry[0].new_instruction.bytes)

                        # assemblate with a string the new instruction
                        str_instr = f"{entry[0].new_instruction.mnemonic} {hex(jmp_addr_ptr)}"

                        bytes_arr = None
                        ################checko se ci sono istruzioni infami pezze di mmerda cacone ridicole#########
                        if (entry[0].new_instruction.mnemonic == 'jrcxz' or entry[0].new_instruction.mnemonic == 'loop'):

                            # bytes_arr = bytearray(asm(str_instr, arch='amd64'))
                            # bytes_arr = asm(str_instr, arch='x86_64')

                            print("JRCXZ/LOOP: \n")

                        ######################################################

                        if entry[0].new_instruction.mnemonic == 'jrcxz':
                            diff = abs(jmp_addr_ptr - entry[0].new_instruction.address)
                            print(f"###############\nDIFF: {diff}\n###############\n")
                            if diff > 120:
                                
                                print("\n###########################################\n")
                                print("DIFF > 120!!\n")
                                print(f"DIFF: {diff}\n")
                                print("PLEASE RESTART THE SOFTWARE UNTIL DIFF < 120\n")
                                print("EXITING...............\n")
                                print("###########################################\n")

                                # prima di chiudere starta un nuovo processo uguale
                                command = f"python3 {sys.argv[0]} {sys.argv[1]}"
                                os.system(command)
                                exit(0)
                                # start()
                                
                            #     time.sleep(2)
                            #     exit(0)
                            # time.sleep(2)
                        asm, _ = self.ks.asm(str_instr, entry[0].new_instruction.address)
                        bytes_arr = bytearray(asm)

                        new_length = len(bytes_arr)
                        # check if the new assembled instruction is different in size from the old one
                        if original_length != new_length:
                            # if the new size is lower just insert NOPs to pad
                            if original_length > new_length:
                                if self.pii_enabled == True:
                                
                                    print("🚨🚨NINONINO NINONINO POLIZIA DEL DEBUGGING ZIOPERA🚨🚨")
                                    if entry[0].new_instruction.operands[0].type == x86_const.X86_OP_IMM:
                                        offset = (entry[0].new_instruction.address + len(entry[0].new_instruction.bytes)) - entry[1].new_instruction.address
                                        print("OPERAND: IMM")
                                    elif entry[0].new_instruction.operands[0].type == x86_const.X86_OP_MEM:
                                        offset = entry[1].new_instruction.address
                                    else:
                                        offset = entry[0].new_instruction.operands[0].imm - entry[1].new_instruction.address
                                    opcode = entry[0].new_instruction.opcode
                                    original_opcode = []
                                    for byte in opcode:
                                        if byte != 0x00:
                                            original_opcode.append(byte)
                                    original_op_len = len(original_opcode)
                                    # convert original_opcode array to an int
                                    original_opcode = int.from_bytes(original_opcode, byteorder='little')
                                    print("original_opcode: ",original_opcode)
                                    instr_len = len(entry[0].new_instruction.bytes)
                                    
                                    new_bytes = original_opcode.to_bytes(original_op_len, byteorder='little') + offset.to_bytes(instr_len - original_op_len, byteorder='little', signed=True)
                                    bytes_arr = bytearray(new_bytes)
                                    new_length = len(bytes_arr)
                                    print("address: ",hex(entry[0].new_instruction.address))

                                    if instr_len != new_length:
                                        print("PII: instr_len != new_length")
                                        print(f"instr_len: {instr_len}, new_length: {new_length}")
                                        print("bytes_arr: ",bytes_arr)
                                        print("original_opcode: ",original_opcode)
                                        print("offset: ",offset)
                                        print("old_instr: ",entry[0].new_instruction.bytes)
                                        print("new_instr: ",bytes_arr)
                                    else:
                                        for x,i in enumerate(self.cs.disasm(bytes_arr,entry[0].new_instruction.address)):
                                            entry[0].new_instruction = i
                                            print(f"new_instr:{hex(i.address)}  {i.mnemonic} {i.op_str} ")
                                            do_not_touch_instr.append(entry[0].new_instruction)
                                            self.do_not_touch.append(entry[0].new_instruction)
                                        continue


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
                            # if the new size is bigger re-iterate this function
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

                        # if not different just patch the instruction
                        else:
                            for i in self.cs.disasm(bytes_arr,entry[0].new_instruction.address):
                                entry[0].new_instruction = i
                except Exception as e:
                    print("Errore in update_label_table(): ",e)
                    traceback.print_exc()

                    print("Indirizzo: ",hex(entry[0].new_instruction.address))
                    print("stringa: ",entry[0].new_instruction.mnemonic + '  ' + entry[0].new_instruction.op_str)
                    # print("Indirizzo jump: ",hex(jmp_addr))
                    print("bytes: ",entry[0].new_instruction.bytes)
                    print("\n\n\n")

                    continue


    def update_label_table_brain(self):
        print("UPDATE LABEL TABLE")

        # if during patching some JMP or CALL becomes bigger (example 3 byte --> 5 byte)
        #   i need to re iterate the all patching process
        re_iterate = True
        num_iterazioni = 0

        inserted_instructions = False
        while re_iterate == True:
            print("ITERANDO: num_iterazioni: ",num_iterazioni)
            # always update instructions beforse patching them, otherwise instructions addresses will be broken
            self.update_instr()
            re_iterate = False
            num_iterazioni += 1
            # try:

            # iterate the list of jmp/call instructions
            for entry in self.short_label_table:
                try:

                    # various checks 
                    if self.check_if_inside_jmp_table(entry[0].new_instruction.address) == True:
                        continue

                    if (x86_const.X86_GRP_JUMP not in entry[0].new_instruction.groups) and (x86_const.X86_GRP_CALL not in entry[0].new_instruction.groups) and (entry[0].new_instruction.mnemonic != 'loop'):
                        continue

                    if (entry[0].new_instruction.operands[0].type == x86_const.X86_OP_REG):
                        continue
                    # check if it is a jmp to far stuff (improbable), do not patch it here because it is patched in adjust_out_text_reference()
                    if 'ptr' in entry[0].new_instruction.op_str:
                        continue



                        # time.sleep(2)

                    # extract the jmp address from the string (yea i love python, so easy)
                    old_jump_address = zone_utils.estrai_valore(entry[0].new_instruction.op_str)


                    if old_jump_address == 0:
                        print(entry[0].new_instruction.mnemonic, entry[0].new_instruction.op_str)
                    


                    jmp_addr = zone_utils.estrai_valore(entry[0].new_instruction.op_str)
                    jmp_addr_ptr = entry[1].new_instruction.address
                    
                    index = self.instructions.index(entry[0])

                    # check if the jmp address is right
                    if jmp_addr != jmp_addr_ptr:
                        original_length = len(entry[0].new_instruction.bytes)

                        # assemblate with a string the new instruction
                        str_instr = f"{entry[0].new_instruction.mnemonic} {hex(jmp_addr_ptr)}"

                        bytes_arr = None
                        ################checko se ci sono istruzioni infami pezze di mmerda cacone ridicole#########
                        if (entry[0].new_instruction.mnemonic == 'jrcxz' or entry[0].new_instruction.mnemonic == 'loop'):

                            # bytes_arr = bytearray(asm(str_instr, arch='amd64'))
                            # bytes_arr = asm(str_instr, arch='x86_64')

                            print("JRCXZ/LOOP: \n")

                        ######################################################

                        if entry[0].new_instruction.mnemonic == 'jrcxz':
                            diff = abs(jmp_addr_ptr - entry[0].new_instruction.address)
                            print(f"###############\nDIFF: {diff}\n###############\n")
                            if diff > 120:
                                
                                print("\n###########################################\n")
                                print("DIFF > 120!!\n")
                                print(f"DIFF: {diff}\n")
                                print("PLEASE RESTART THE SOFTWARE UNTIL DIFF < 120\n")
                                print("EXITING...............\n")
                                print("###########################################\n")

                                # prima di chiudere starta un nuovo processo uguale
                                command = f"python3 {sys.argv[0]} {sys.argv[1]}"
                                os.system(command)
                                exit(0)
                                # start()
                                
                            #     time.sleep(2)
                            #     exit(0)
                            # time.sleep(2)
                        asm, _ = self.ks.asm(str_instr, entry[0].new_instruction.address)
                        bytes_arr = bytearray(asm)

                        new_length = len(bytes_arr)
                        # check if the new assembled instruction is different in size from the old one
                        if original_length != new_length:
                            # if the new size is lower just insert NOPs to pad
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
                            # if the new size is bigger re-iterate this function
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

                        # if not different just patch the instruction
                        else:
                            for i in self.cs.disasm(bytes_arr,entry[0].new_instruction.address):
                                entry[0].new_instruction = i
                except Exception as e:
                    print("Errore in update_label_table(): ",e)
                    traceback.print_exc()

                    print("Indirizzo: ",hex(entry[0].new_instruction.address))
                    print("stringa: ",entry[0].new_instruction.mnemonic + '  ' + entry[0].new_instruction.op_str)
                    # print("Indirizzo jump: ",hex(jmp_addr))
                    print("bytes: ",entry[0].new_instruction.bytes)
                    print("\n\n\n")

                    continue

    # this also is some serious fucked up stuff
    # this function patched all the jmp/call/mov or all the instructions which have references to some very far addresses
    # these instructions all have this structure:   INSR  OP1, QWORD/DWORD PTR [REG + 0xNUM],
    # i will only patch the instructions with REG = RIP
    def adjust_out_text_references(self):
        # same as before, if instructions become bigger i have to re-iterate
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
                    # 
                    if ('rip +' in instr.new_instruction.op_str):

                        # extract the offset
                        valore_originale = zone_utils.estrai_valore(instr.original_instruction.op_str)
                        if valore_originale == 0:
                            continue
                        if num_instr == len(self.instructions) - 1:
                            continue

                        # calculate the address that is pointing (RIP + offset)
                        addr = self.instructions[num_instr + 1].original_instruction.address + valore_originale


                        #checko se l'indirizzo e'all'interno della .text
                        #  check if the address is inside the .text 
                        # MAYBE THIS CHECK IS WRONG, I SHOULD PATCH ALSO IF IT IS INSIDE .TEXT
                        # if addr > self.base_address and addr < self.base_address + self.code_section_size:
                        #     for i in self.instructions:
                        #         if i.original_instruction.address == addr:
                        #             addr = i.new_instruction.address
                        #             print("NUOVO INDIRIZZO JUMP RIP+ : ",hex(addr))
                        #             break
            
                        # calculate the new offset i need to insert in the instruction
                        offset = addr - self.instructions[num_instr + 1].new_instruction.address

                        old_string = instr.new_instruction.mnemonic + ' ' + instr.new_instruction.op_str

                        # rimpiazzo il nuovo offset con il vecchio offset nella stringa e assemblo
                        # replace the new offset with the old offset in the string and assemble
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


                        # always check if the new instruction is bigger than the old one
                        if(len(asm) < len(instr.new_instruction.bytes)):
                            
                            # this check is caused by the fact that keystone does not assemble the 0x48 byte very often, it is something about x64 arch. i do not remember
                            if(instr.new_instruction.bytes[0] == 0x48 and (len(instr.new_instruction.bytes) - len(asm) == 1)):


                                asm.insert(0,0x48)
                                for i in self.cs.disasm(asm, instr.new_instruction.address):
                                    instr.new_instruction = i
                            else:                     
                                ##########DA IMPLEMENTARE################
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

                    # same stuff but for jump at addressess before
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


    # a simple function that given the original address will return the new address
    def locate_by_address(self, address):
        instr = self.instr_dict[address]            
        if instr.original_instruction.address == address:
            return instr
        return None

    #  a function that will patch the RELOC_TABLE of the PE file
    # https://0xrick.github.io/win-internals/pe7/ read this to understand why we need to patch the reloc table
    def adjust_reloc_table(self):
        # iterate every table
        for entries in self.pe.DIRECTORY_ENTRY_BASERELOC:
            # iterate evry entry (every address to reloc)
            for reloc in entries.entries:
                data = self.pe.get_qword_at_rva(reloc.rva)
                # print("data: ",hex(data))

                data = data - self.pe.OPTIONAL_HEADER.ImageBase


                if data not in self.instr_dict:
                    continue

                if self.instr_dict[data] is not None:
                    # print("RELOC: ",hex(reloc.rva))
                    instr = self.instr_dict[data]

                    self.pe.set_qword_at_rva(reloc.rva, instr.new_instruction.address + self.pe.OPTIONAL_HEADER.ImageBase)

        self.pe.write(self.file)

    # a function that given an index and an instruction will insert the new instruction in self.instructions
    def insert_instruction(self,index,instruction):
        instruction_number = len(self.instructions)
        if index >= instruction_number:
            self.instructions.append(instruction)
            return
        self.instructions[index - 1].next_instruction = instruction
        self.instructions[index].prev_instruction = instruction

        instruction.prev_instruction = self.instructions[index - 1]
        instruction.next_instruction = self.instructions[index]

        self.instructions.insert(index,instruction)

    def eliminate_instruction(self, index):
        self.instructions[index - 1].next_instruction = self.instructions[index + 1]
        self.instructions[index + 1].prev_instruction = self.instructions[index - 1]
        self.instructions.pop(index)
                

    # function that randomly inserts some do-nothing operations
    def insert_random_nop(self):

        inserted_nops = 0
        for num_instr,instr in enumerate(self.instructions):
            if num_instr == 0:
                continue
            try:

                # if instr.new_instruction.address >= new_entry_point:
                #     break
                if instr.new_instruction.mnemonic == '.byte':
                    continue
                #checko che non sia dentro una jmp table della .text
                if self.check_if_inside_jmp_table(instr.original_instruction.address) == True:
                    continue

                if instr.prev_instruction.new_instruction.mnemonic == 'pushf' or instr.new_instruction.mnemonic == 'pushf':
                    continue


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
                reg_list = random.choice(self.reg_lists)
                reg = None

                # just a random probability to insert a nop
                probability = random.randint(0,100)
                if probability <= 20:

                    # choose a random NOP operation
                    operazione = random.choice(self.no_ops_templates)
                    # choose a random number of NOPs to insert
                    nop_num = random.randint(1,2)

                    # choose a random register to do the nop
                    reg = random.choice(reg_list)

# IMPORTANT : Why there is pushf; nop; popf in every instruction?
# BECAUSE even if these operations do nothing they still fuck up the CPU flags, therefore you need to save them and restore
# maybe this is bad solution because it can be easily signatured (?) 

                    if operazione == 'nop':
                        asm, _ = self.ks.asm('pushf;nop; popf', instr.new_instruction.address + instr.new_instruction.size)

                    if operazione == 'sub':
                        asm, _ = self.ks.asm(f'pushf;sub {reg},0x0; popf', instr.new_instruction.address + instr.new_instruction.size)
                    
                    if operazione == 'add':
                        asm, _ = self.ks.asm(f'pushf;add {reg},0x0; popf', instr.new_instruction.address + instr.new_instruction.size)
                    
                    if operazione == 'mov':
                        asm, _ = self.ks.asm(f'pushf;mov {reg},{reg}; popf', instr.new_instruction.address + instr.new_instruction.size)

                    if operazione == 'lea':
                        asm, _ = self.ks.asm(f'pushf;lea {reg},[{reg}+0]; popf', instr.new_instruction.address + instr.new_instruction.size)

                    if operazione == 'inc':
                        nop_num = 1
                        asm, _ = self.ks.asm(f'pushf;dec {reg}; inc {reg}; popf', instr.new_instruction.address + instr.new_instruction.size)
                    
                    if operazione == 'sar':
                        asm, _ = self.ks.asm(f'pushf;sar {reg},0x0; popf', instr.new_instruction.address + instr.new_instruction.size)
                    
                    if operazione == 'shr':
                        asm, _ = self.ks.asm(f'pushf;shr {reg},0x0; popf', instr.new_instruction.address + instr.new_instruction.size)
                    
                    if operazione == 'shl':
                        asm, _ = self.ks.asm(f'pushf;shl {reg},0x0; popf', instr.new_instruction.address + instr.new_instruction.size)
                    
                    if operazione == 'rcl':
                        asm, _ = self.ks.asm(f'pushf;rcl {reg},0x0; popf', instr.new_instruction.address + instr.new_instruction.size)
                    
                    if operazione == 'rcr':
                        asm, _ = self.ks.asm(f'pushf;rcr {reg},0x0; popf', instr.new_instruction.address + instr.new_instruction.size)
                    
                    if operazione == 'xor':
                        asm, _ = self.ks.asm(f'pushf;xor {reg},0x0; popf', instr.new_instruction.address + instr.new_instruction.size)

                    if operazione == 'and':
                        asm, _ = self.ks.asm(f'pushf;and {reg},{reg}; popf', instr.new_instruction.address + instr.new_instruction.size)

                    
                    if operazione == 'or':
                        asm, _ = self.ks.asm(f'pushf;or {reg},{reg}; popf', instr.new_instruction.address + instr.new_instruction.size)
                    
                    if operazione == 'jmp':
                        # stupid jmp to next instruction
                        asm = bytearray([0xEB,0x00])

                        asm = bytearray(b'f\x9c') + asm + bytearray(b'f\x9d')
                        asm = bytearray([0x90])

                    # asm = bytearray([0x90])
                    asm = bytearray(asm)
                    for x,i in enumerate(self.cs.disasm(asm, instr.new_instruction.address + instr.new_instruction.size )):
                        insr = Instruction(i,i,i,None,None)
                        insr.address_history.append(i.address)

                        self.insert_instruction(num_instr + 1 + x, insr)
                    inserted_nops += 1

                self.nops_addedd = inserted_nops
            except Exception as e:
                print("Errore in insert_random_nop(): ",e)
                print("NUM_INSTR ERRORE: ",num_instr)
                traceback.print_exc()

                continue

    def chaos_cf(self):

        #1) dividi il codice in blocchi di istruzioni di grandezza casuale tra 5 e 12
        #2) alla fine di ogni blocco inserisci un jmp al blocco successivo
        # shuffla i blocchi

        single_block = []
        self.block_size = random.randint(5,9)
        # self.block_size = 7
        print("BLOCK LENGTH: ",self.block_size)


        

        skip = False
        for num_instr,instr in enumerate(self.instructions):

            tmp_instr = instr
            
            last_block_instr = False

            if skip == True:
                skip = False
                continue
            if (num_instr == len(self.instructions) - 1):
                break
            if (num_instr + 2) % self.block_size == 0 and num_instr != 0:
                
                # inserisco un jmp al blocco successivo
                single_block.append(tmp_instr)
                address = instr.new_instruction.address + instr.new_instruction.size + 2

                asm, _ = self.ks.asm(f'jmp {address}', instr.new_instruction.address + instr.new_instruction.size)
                # asm = bytearray(b'\xeb\x00')
                asm = bytearray(asm)
                for i in self.cs.disasm(asm, instr.new_instruction.address + instr.new_instruction.size):

                    new_jmp = Instruction(i,i,i,instr.new_instruction,instr.next_instruction)

                    

                    #inserisci istruzione nella lista
                    self.insert_instruction(num_instr +1,new_jmp)
                    #aggiungi alla label table
                    self.short_label_table.append((new_jmp,new_jmp.next_instruction))


                    tmp_instr = new_jmp
                    skip = True

                last_block_instr = True
            
            
            single_block.append(tmp_instr)

            if last_block_instr == True:
                self.instr_blocks.append(single_block)
                single_block = []

        # shuffla i blocchi ma non il primo

    def shuffle_blocks(self):



        blocco_jrcxz = 99999999999
        blocco_jrcxz_jmp = 999999999999

        jmp_addr = None

        block_distance = -1


        
        
        blocks = self.instr_blocks[1:]

        # while  block_distance > 4 and block_distance < 0:
        random.shuffle(blocks)



        self.instr_blocks = [self.instr_blocks[0]] + blocks


        new_instructions = []
        for block in self.instr_blocks:
            for instr in block:
                new_instructions.append(instr)

        self.instructions = new_instructions

        for x,instr in enumerate(self.instructions):
            if x == 0:
                instr.next_instruction = self.instructions[x+1]

            elif x == len(self.instructions) - 1:
                instr.prev_instruction = self.instructions[x-1]

            else:
                instr.prev_instruction = self.instructions[x-1]
                instr.next_instruction = self.instructions[x+1]

        # diff = 99999
        # for entry in self.short_label_table:
        #     if entry[0].new_instruction.mnemonic == "jrcxz":
        #         jmp_addr_ptr = entry[1].new_instruction.address
        #         diff = abs(jmp_addr_ptr - entry[0].new_instruction.address)
        #         print(f"\n################DIFF in shuffle_blocks(): {diff}\n")

        # if diff > 120:
        #     print("diff > 120\n")
        #     print("reiterating shuffle_blocks....")
        #     self.shuffle_blocks()


    def check_jcrxz_ok(self):
        check = False
        for entry in self.short_label_table:
            jmp_addr_ptr = entry[1].new_instruction.address
            diff = abs(jmp_addr_ptr - entry[0].new_instruction.address)
            print("DIFF: ",diff)
            if diff > 120:
                return False
        return True

    # a function that will print the blocks to a file
    def print_blocks(self):
        with open('blocks.txt', 'r+') as f:
            for n,block in enumerate(self.instr_blocks):
                f.write("###############################\n")
                for instr in block:
                    
                    stringa = f"{n} :  {hex(instr.new_instruction.address)} {instr.new_instruction.mnemonic} {instr.new_instruction.op_str}\n"
                    f.write(stringa)




    # function that will write modifications to the PE file
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

    # function that converts raw addressess to relative addresses
    def convert_raw_to_rva(self,raw_address,section):
        return raw_address + section.VirtualAddress - section.PointerToRawData
    
    def eliminate_loop_instructions(self):
        restart = True
        try:
            while restart == True:
                restart = False
                for x,instr in enumerate(self.instructions):
                    if instr.new_instruction.mnemonic == 'loop':
                        print("TROVATO LOOP")
                        addr = zone_utils.estrai_valore(instr.new_instruction.op_str)

                        self.eliminate_instruction(x)
                        
                        stringa = f"dec ecx;jne {hex(addr)}"
                        asm, _ = self.ks.asm(stringa, instr.new_instruction.address)
                        bytes_arr = bytearray(asm)
                        for n,i in enumerate(self.cs.disasm(bytes_arr,instr.new_instruction.address)):
                            new_instr = Instruction(i,i,i,None,None)
                            self.insert_instruction(x+n,new_instr)
                            if i.mnemonic == 'jne':
                                self.short_label_table.append((new_instr,self.instr_dict[addr]))
                        restart = True
                        # break
        except Exception as e:
            print("Errore in eliminate_loop_instructions(): ",e)
            traceback.print_exc()
    
    def eliminate_jrcxz_instructions(self):
        restart = True

        while restart == True:
            restart = False
            for x,instr in enumerate(self.instructions):
                if instr.new_instruction.mnemonic == 'jrcxz':
                    print("TROVATO LOOP")
                    addr = zone_utils.estrai_valore(instr.new_instruction.op_str)

                    self.eliminate_instruction(x)
                    
                    stringa = f"dec rcx;jne {hex(addr)}"
                    asm, _ = self.ks.asm(stringa, instr.new_instruction.address)
                    bytes_arr = bytearray(asm)
                    for n,i in enumerate(self.cs.disasm(bytes_arr,instr.new_instruction.address)):
                        new_instr = Instruction(i,i,i,None,None)
                        self.insert_instruction(x+n,new_instr)
                        if i.mnemonic == 'jne':
                            self.short_label_table.append((new_instr,self.instr_dict[addr]))
                    restart = True
                    # break


    # function that checks if an instruction(given its address) is inside a jump table
    def check_if_inside_jmp_table(self,address):
        inside_jmp_table = False
        for jmp in self.start_end_table:
            if address >= jmp[0] and address <= jmp[1]:
                inside_jmp_table = True

        return inside_jmp_table

    # function that creates a jump table
    # here i found the solution https://blog.es3n1n.eu/posts/obfuscator-pt-1/
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
        with open('jump_table.txt', 'r+') as f:
            for entry in self.start_end_table:
                stringa = f"{hex(entry[0])} {hex(entry[1])}\n"
                f.write(stringa)

    # function that patches the jump table
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

    # another technique that consists of:
    # 1) randomically shuffling every instruction
    # 2) a map that holds the new address and the chronologically ordered instructions
    # 3) A stub that jumps manually to every instruction executing in the correct order
    def check_unused_registers(self):
        unused_regs = []
        for reg in self.reg_list32:
            unused_regs.append(reg)
        
        for instr in self.instructions:
            instr_str = f"{instr.new_instruction.mnemonic} {instr.new_instruction.op_str}"
            for reg in self.reg_list32:
                if reg in instr_str:
                    if reg in unused_regs:
                        unused_regs.remove(reg)
        print("UNUSED REGISTERS: ",unused_regs)

        if len(unused_regs) == 0:
            print("NO UNUSED REGISTERS, using ebp")
            unused_regs.append('ebp')
        return unused_regs
    def estimate_stub_address(self):
        original_size = 0
        instruction_num = 0
        for instr in self.instructions:
            original_size += len(instr.new_instruction.bytes)
            instruction_num += 1

        probable_addr = original_size + (1 + 4 + 5 + 5) * instruction_num    
        probable_addr = probable_addr + (100 - (probable_addr % 100)) + 0x100

        print("EStimated stub address: ",probable_addr)
        return probable_addr
        
    def brain_adjust(self):
        self.stub_address = self.estimate_stub_address()


        bytes_added = 0

        re_iterate = True
        actual_index = 0
        counter = 0
        while re_iterate == True:
            try:
                re_iterate = False
                for x,instr in enumerate(self.instructions):
                    if x < actual_index:
                        continue
                    
                    if x == 0:
                        actual_index += 1
                        continue
                    
                    if instr.new_instruction.mnemonic == 'jrcxz':
                        asm1 = "pop eax"
                        asm1, _ = self.ks.asm(asm1,instr.new_instruction.address + bytes_added)
                        asm1 = bytearray(asm1)

                        asm2 = bytearray(instr.new_instruction.bytes)
                        asm3 = f"push {hex(0x3e8 + actual_index)}"

                        asm3, _ = self.ks.asm(asm3,instr.new_instruction.address + bytes_added)

                        asm4 = f"jmp {hex(self.stub_address)}"
                        asm4, _ = self.ks.asm(asm4,instr.new_instruction.address + bytes_added)
                        asm4 = bytearray(asm4)
                        continue
                    original_length = len(instr.new_instruction.bytes)
                    new_str = f"pop eax;lea esp, [esp + 4];{instr.new_instruction.mnemonic} {instr.new_instruction.op_str};push {hex(0x3e8 + counter)};jmp {hex(self.stub_address)}"
                    
                    asm, _ = self.ks.asm(new_str,instr.new_instruction.address + bytes_added)
                    asm = bytearray(asm)
                    counter += 1

                    for x2,i in enumerate(self.cs.disasm(asm,instr.new_instruction.address + bytes_added)):
                        re_iterate = True
                        if x2 == 2:
                            actual_index += 1
                            continue
                            
                        new_instr = Instruction(i,i,i,None,None)
                        self.insert_instruction(x+x2, new_instr)
                        actual_index += 1
                    bytes_added += (len(asm) - original_length)
                    break
            except Exception as e:
                print("Errore in brain_adjust(): ",e)
                print("new_str: ",new_str)
                traceback.print_exc()
                re_iterate = False
                continue
        payload_size = 0
        for instr in self.instructions:
            payload_size += len(instr.new_instruction.bytes)
        print("OBFUSCATED PAYLOAD SIZE: ",payload_size)

        self.payload_size = payload_size
    def re_adjust_brain(self):
        for x,instr in enumerate(self.instructions):
            if instr.new_instruction.address >= self.stub_address:
                return
            if x % self.wrap_instruction_num != 0:
                continue
            elif instr.new_instruction.mnemonic == 'nop':
                continue
            elif instr.new_instruction.mnemonic == 'jmp':
                new_str = f"{instr.new_instruction.mnemonic} {self.stub_address}"
                asm, _ = self.ks.asm(new_str,instr.new_instruction.address)
                asm = bytearray(asm)
                for i in self.cs.disasm(asm,instr.new_instruction.address):
                    instr.new_instruction = i
            else:
                print("Errore strano, non tornano i conti non c'e' una JMP ogni tre istruzioni")
    def estimate_stub_size(self):
        stub_str = f'''
        push eax;
        push ecx;
        mov ecx, [esp + 0x8]
        pushf;
        sub ecx, 0x3e8;
        inc ecx;

        call 0x1000
        pop eax;

        mov eax, [eax + 0x40];
        mov ecx, [eax + {self.mem_address} - 5 + ecx * 4];
        sub ecx, 0x5
        add eax, ecx
        popf;
        pop ecx;
        jmp eax;
        '''

        asm, _ = self.ks.asm(stub_str,self.stub_address)
        bytes_arr = bytearray(asm)
        return len(bytes_arr)     

    def estimate_stub2_size(self):
        stub2_str = f'''
        pop ebp;
        mov [ebp - 5 + 0x1000], ebp;
        push ebp;
        jmp ebp;
        '''
        asm, _ = self.ks.asm(stub2_str,self.stub_address)
        bytes_arr = bytearray(asm)
        return len(bytes_arr)

    def shuffle_brain_blocks(self):
        counter = 0

        blocks = []
        block = []

        for x,instr in enumerate(self.instructions):
            if instr.new_instruction.mnemonic == 'pop' and instr.new_instruction.op_str == 'eax':
                if instr.next_instruction.new_instruction.mnemonic == "lea":
                    block.append(instr)
                    continue
            if x == len(self.instructions) - 1:
                block.append(instr)
                blocks.append(block)
                block = []
                continue
            if instr.new_instruction.mnemonic == 'jmp' and instr.next_instruction.new_instruction.mnemonic == 'pop' and instr.next_instruction.new_instruction.op_str == 'eax':
                block.append(instr)
                blocks.append(block)
                block = []
                continue
            block.append(instr)

        firstBlock = blocks[0]
        blocks = blocks[1:]

        random.shuffle(blocks)
        blocks = [firstBlock] + blocks

        new_instructions = []
        for block in blocks:
            for instr in block:
                new_instructions.append(instr)

        self.instructions = new_instructions       

        for x,instr in enumerate(self.instructions):
            if x == 0:
                instr.next_instruction = self.instructions[x+1]

            elif x == len(self.instructions) - 1:
                instr.prev_instruction = self.instructions[x-1]

            else:
                instr.prev_instruction = self.instructions[x-1]
                instr.next_instruction = self.instructions[x+1]

    def brain_obfuscator(self):
        brain_shuffle = True
        # salva indirizzi di inizio blocco e poi shuffla i blocchi
        calc_base_str = f"call 0x1000"
        asm, _ = self.ks.asm(calc_base_str,0x0)
        bytes_arr = bytearray(asm)
        for x,i in enumerate(self.cs.disasm(bytes_arr,0x0)):
            insr = Instruction(i,i,i,None,None)
            self.insert_instruction(0,insr)

        # self.update_instr()


        self.brain_adjust()


        if brain_shuffle == True:
            self.shuffle_brain_blocks()


        self.update_label_table()

        unused_regs = self.check_unused_registers()

        random_unused_reg = random.choice(unused_regs)


        # estimated_stub_addr = self.estimate_stub_address()

        self.payload_size = 0
        for instr in self.instructions:
            self.payload_size += len(instr.new_instruction.bytes)
        
        
        print("Estimated stub address: ",self.stub_address)
        print("Payload SIZE: ", self.payload_size)
        nop_sled_size = self.stub_address - self.payload_size

        print("NOP SLED SIZE: ",nop_sled_size)

        instr_number = len(self.instructions)

        for i in range(nop_sled_size):
            nop = bytearray([0x90])

            for instr in self.cs.disasm(nop, self.payload_size + i):
                insr = Instruction(instr,instr,instr,None,None)
                self.insert_instruction(instr_number + i, insr)
                instr_number += 1

        instruction_num = 0
        for x,instr in enumerate(self.instructions):
            if x == 0:
                continue
            if instr.new_instruction.mnemonic == "pop" and instr.new_instruction.op_str == "eax" and x % self.wrap_instruction_num == 1:
                
                self.instr_mapping.append((x,instr.new_instruction.address))
            instruction_num += 1

        for x,instr in enumerate(self.instructions):
            index  = 0
            if x == 0:
                continue
            if instr.new_instruction.mnemonic == "pop" and instr.new_instruction.op_str == "eax" and x % self.wrap_instruction_num == 1:
                for instr2 in self.instructions[x:x+5]:
                    if instr2.new_instruction.mnemonic == "push" and instr2.next_instruction.new_instruction.mnemonic == "jmp":
                        # print("push found")
                        index = int(instr2.new_instruction.op_str,16) - 0x3e8
                        # print("index: ",index)
                        self.instr_mapping[index] = (index,instr.new_instruction.address)
        # sort instr_mapping by index
        self.instr_mapping.sort(key=lambda x: x[0])

        # print instr mapping to a file
        with open('instr_mapping.txt', 'w') as f:
            for entry in self.instr_mapping:
                f.write(f"{entry[0]} {hex(entry[1])}\n")
            
            f.close()

        
        
        # write map to file

        self.stub_size = self.estimate_stub_size()
        self.stub2_size = self.estimate_stub2_size()
        print("STUB SIZE: ",self.stub_size)




        mem_size_on_disk = instruction_num * 4

        self.stub2_address = self.stub_address + self.stub_size
        self.stub2_address = self.stub2_address + (0x10 - (self.stub2_address % 0x10))

        

        self.mem_address = self.stub2_address + self.stub2_size
        self.mem_address = self.mem_address + (100 - (self.mem_address % 100)) + 0x100

        self.init_address = self.stub2_address + self.stub2_size + 0x10

        print("MEMORY ADDRESS: ",hex(self.mem_address))
        padding = self.mem_address - self.stub_address - self.stub_size
        print("PADDING SIZE: ",padding)
        print("init address: ",hex(self.init_address))

        # self.stub2_address = self.counter_address + 0x10
        # self.stub2_address = self.stub2_address + (0x10 - (self.stub2_address % 0x10))


        init_addr_offset = self.init_address - (self.stub_address + 0x14) 
        print("INIT ADDR OFFSET: ",init_addr_offset)    

        stub_str = f'''
        push eax;
        push ecx;
        mov ecx, [esp + 0x8]
        pushf;
        sub ecx, 0x3e8;
        inc ecx;

        call {self.stub_address + 0x14};
        pop eax;

        mov eax, [eax + {init_addr_offset}];
        mov ecx, [eax + {self.mem_address} - 5 + ecx * 4];
        sub ecx, 0x5
        add eax, ecx
        popf;
        pop ecx;
        jmp eax;
        '''

        stub2_str = f'''
        pop {random_unused_reg};
        mov [{random_unused_reg} - 5 + {self.init_address}], {random_unused_reg};
        push {random_unused_reg};
        jmp {random_unused_reg};
        '''


        asm, _ = self.ks.asm(stub_str,self.stub_address)

        bytes_arr = bytearray(asm)
        for x,i in enumerate(self.cs.disasm(bytes_arr,self.stub_address)):
            insr = Instruction(i,i,i,None,None)
            self.insert_instruction(instr_number + x , insr)
            instr_number += 1

        nop_sled_size2 = self.stub2_address - (self.stub_address + self.stub_size)

        print("NOP SLED SIZE 2: ",nop_sled_size2)

        print("STUB2 ADDRESS: ",hex(self.stub2_address))
        for i in range(nop_sled_size2):
            nop = bytearray([0x90])
            for instr in self.cs.disasm(nop, (self.stub_address + self.stub_size + i)):
                insr = Instruction(instr,instr,instr,None,None)
                self.insert_instruction(instr_number + i, insr)
                instr_number += 1

        asm2, _ = self.ks.asm(stub2_str,self.stub2_address)
        bytes_arr2 = bytearray(asm2)

        for x,i in enumerate(self.cs.disasm(bytes_arr2,self.stub2_address)):
            insr = Instruction(i,i,i,None,None)
            self.insert_instruction(instr_number + x , insr)
            instr_number += 1

        new_first_instr_str = f"call {self.stub2_address}"
        asm3, _ = self.ks.asm(new_first_instr_str,0x0)
        bytes_arr3 = bytearray(asm3)
        for x,i in enumerate(self.cs.disasm(bytes_arr3,0x0)):
            self.instructions[0].new_instruction = i
        self.re_adjust_brain()


    def equal_instructions(self):
        change_num = 0
        bytes_added = 0
        for num_instr,instr in enumerate(self.instructions):
            #substitue xor reg,rex with mov reg,0x0

            prob = random.randint(0,100)
            if prob > 50:
                continue

            # if change_num > 10:
            #     break

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

            # trasforma and reg

        print("##########################################")
        print("BYTES ADDED: ",hex(bytes_added))
        print("##########################################")

    
    def write_strange_file(self,output_file):
        new_bytes = b''
        for x,i in enumerate(self.instructions):
            new_bytes += i.new_instruction.bytes

        padding1 = self.mem_address - len(new_bytes)
        # add 
        new_bytes += bytearray([0x90 for _ in range(padding1)])

        # create a bytearray of the instruction map
        map_bytes = b''
        for x,i in enumerate(self.instr_mapping):
            map_bytes += i[1].to_bytes(4, byteorder='little')

        new_bytes += map_bytes
        
        if output_file == None:
            output_file = 'new_payload.bin'

        # non modificare il file esistente, creano uno nuovo
        with open(output_file, 'wb') as f:
            f.seek(0)
            f.write(new_bytes)
    
    def write_file(self, output_file):
        new_bytes = b''
        for i in self.instructions:
            new_bytes += i.new_instruction.bytes

        # non modificare il file esistente, creano uno nuovo
        if output_file == None:
            output_file = 'new_payload.bin'
        with open(output_file, 'wb') as f:
            f.seek(0)
            f.write(new_bytes)


def print_usage():
    print("Usage: python pobf86.py <file> <options>")
    print("Options:")
    print("--help                                           Show  this help message and exit")
    print("--equal-instructions, -eq                        Modify instructions to make them equal")
    print("--bogus-cf, -bcf                                 Add bogus control flow instructions")
    print("--insert-nop, -nop                               Insert NOP instructions")
    print("--instruction-block-permutation, -ibp            Permute instruction blocks")
    print("--position-independent-instr, -pii               VM technique")
    print("--output,-o <file>                               Output file name")


def start():
        # 1st increase the text sectiona


    equal_instr = False
    bogus_cf = False
    insert_nop = False
    instruction_block_permutation = False
    position_independent_instr = False
    output_file = None
    
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)
    if "--help" in sys.argv or "-h" in sys.argv:
        print_usage()
        sys.exit(0)

    opt_args = sys.argv[1:]

    for arg in opt_args:
        if arg == "--equal-instructions" or arg == "-eq":
            equal_instr = True
        elif arg == "--bogus-cf" or arg == "-bcf":
            bogus_cf = True
        elif arg == "--insert-nop" or arg == "-nop":
            insert_nop = True
        elif arg == "--instruction-block-permutation" or arg == "-ibp":
            instruction_block_permutation = True
        elif arg == "--position-independent-instr" or arg == "-pii":
            position_independent_instr = True
        elif arg == "--output" or arg == "-o":
            output_file = opt_args[opt_args.index(arg) + 1]

    


    brain_mode = True
    zone = Zone(sys.argv[1])

    # print available registers

    zone.eliminate_loop_instructions()
    # zone.eliminate_jrcxz_instructions()
    

# INITIALIZATION
    zone.create_jmp_table()
    zone.create_label_table()

# CODE MODIFICATION
    if equal_instr == True:
        zone.equal_instructions()
    if insert_nop == True:
        zone.insert_random_nop()


    
    if position_independent_instr == True:
    # if brain_mode == True:
        zone.pii_enabled = True
        zone.brain_obfuscator()

    if bogus_cf == True:
        zone.bogus_control_flow()

    if instruction_block_permutation == True:
        zone.chaos_cf()
        zone.shuffle_blocks()

        # zone.update_label_table_brain()
    
    if position_independent_instr == False:
        zone.update_label_table()



    # while check == False:
    # check = zone.check_jcrxz_ok()



# CODE PATCHING
    # zone.update_label_table()
    
    zone.print_blocks()

    zone.print_instructions()
    # zone.adjust_out_text_references()

    # zone.adjust_reloc_table()
    # zone.adjust_jmp_table()

# WRITE MODIFICATION
    if brain_mode == True:
        zone.write_strange_file(output_file)
    else:
        zone.write_file(output_file)
    zone.print_instructions()
    print("FINE")
    

if __name__ == "__main__":
    start()
