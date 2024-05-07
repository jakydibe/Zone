import pefile
from capstone import *
from keystone import *
import time
import re
from capstone import x86_const


#COSE DA FARE PER INCREMENTARE LA SEZIONE .TEXT


#0) aumentare la .text, semplicemente aumento il content 


#1) aggiustare i vari header, 
#   DOS HEADER -->      X
#   RICH HEADER -->     X
#   FILE HEADER -->     X (se voglio aggiungere una sezione devo cambiare il numero di sezioni)
#   
#   OPTIONAL_HEADER --> 
#           1) Size of Code 
#           2) Size Of Image (sempre allineato)          
#           3) DATA DIRECTORY:
#               Semplicemente incrementare di X Tutti i valori diversi da 0(di indirizzi).        
#
#   SECTION HEADER -->
# 0x218      0x8   Misc:                          0x156A0
# 0x218      0x8   Misc_PhysicalAddress:          0x156A0
# 0x218      0x8   Misc_VirtualSize:              0x156A0
# 0x21C      0xC   VirtualAddress:                0x1000
# 0x220      0x10  SizeOfRawData:                 0x15800
# 0x224      0x14  PointerToRawData:              0x400
#           1) .text, raw size, virtual size,
#               2) per tutte le altre, patchare: raw addr, virtual addr, PointerToRawData        


#   IMPORT TABLE
# [IMAGE_IMPORT_DESCRIPTOR]
# 0x1FAE4    0x0   OriginalFirstThunk:            0x20F10
# 0x1FAE4    0x0   Characteristics:               0x20F10
# 0x1FAE8    0x4   TimeDateStamp:                 0x0        [Thu Jan  1 00:00:00 1970 UTC]
# 0x1FAEC    0x8   ForwarderChain:                0x0
# 0x1FAF0    0xC   Name:                          0x212B0
# 0x1FAF4    0x10  FirstThunk:                    0x17000
#   incrementare di X tutti i valori di indirizzi
#
#   
#

# ----------LOAD_CONFIG----------

# [IMAGE_LOAD_CONFIG_DIRECTORY]
# 0x1E030    0x0   Size:                          0x140
# 0x1E034    0x4   TimeDateStamp:                 0x0        [Thu Jan  1 00:00:00 1970 UTC]
# 0x1E038    0x8   MajorVersion:                  0x0
# 0x1E03A    0xA   MinorVersion:                  0x0
# 0x1E03C    0xC   GlobalFlagsClear:              0x0
# 0x1E040    0x10  GlobalFlagsSet:                0x0
# 0x1E044    0x14  CriticalSectionDefaultTimeout: 0x0
# 0x1E048    0x18  DeCommitFreeBlockThreshold:    0x0
# 0x1E050    0x20  DeCommitTotalFreeThreshold:    0x0
# 0x1E058    0x28  LockPrefixTable:               0x0
# 0x1E060    0x30  MaximumAllocationSize:         0x0
# 0x1E068    0x38  VirtualMemoryThreshold:        0x0
# 0x1E070    0x40  ProcessAffinityMask:           0x0
# 0x1E078    0x48  ProcessHeapFlags:              0x0
# 0x1E07C    0x4C  CSDVersion:                    0x0
# 0x1E07E    0x4E  Reserved1:                     0x0
# 0x1E080    0x50  EditList:                      0x0
# 0x1E088    0x58  SecurityCookie:                0x140022040
# 0x1E090    0x60  SEHandlerTable:                0x0
# 0x1E098    0x68  SEHandlerCount:                0x0
# 0x1E0A0    0x70  GuardCFCheckFunctionPointer:   0x140017258
# 0x1E0A8    0x78  GuardCFDispatchFunctionPointer: 0x140017268
# 0x1E0B0    0x80  GuardCFFunctionTable:          0x0
# 0x1E0B8    0x88  GuardCFFunctionCount:          0x0
# 0x1E0C0    0x90  GuardFlags:                    0x100
# 0x1E0C4    0x94  CodeIntegrityFlags:            0x0
# 0x1E0C6    0x96  CodeIntegrityCatalog:          0x0
# 0x1E0C8    0x98  CodeIntegrityCatalogOffset:    0x0
# 0x1E0CC    0x9C  CodeIntegrityReserved:         0x0
# 0x1E0D0    0xA0  GuardAddressTakenIatEntryTable: 0x0
# 0x1E0D8    0xA8  GuardAddressTakenIatEntryCount: 0x0
# 0x1E0E0    0xB0  GuardLongJumpTargetTable:      0x0
# 0x1E0E8    0xB8  GuardLongJumpTargetCount:      0x0
# 0x1E0F0    0xC0  DynamicValueRelocTable:        0x0
# 0x1E0F8    0xC8  CHPEMetadataPointer:           0x0
# 0x1E100    0xD0  GuardRFFailureRoutine:         0x0
# 0x1E108    0xD8  GuardRFFailureRoutineFunctionPointer: 0x0
# 0x1E110    0xE0  DynamicValueRelocTableOffset:  0x0
# 0x1E114    0xE4  DynamicValueRelocTableSection: 0x0
# 0x1E116    0xE6  Reserved2:                     0x0
# 0x1E118    0xE8  GuardRFVerifyStackPointerFunctionPointer: 0x0
# 0x1E120    0xF0  HotPatchTableOffset:           0x0
# 0x1E124    0xF4  Reserved3:                     0x0
# 0x1E128    0xF8  EnclaveConfigurationPointer:   0x0

#2) patchare tutte le ref dalla .text alle altre sezioni (copiare il codice gia' fatto)
#

#3) patchare la RELOC table se contiene address fuori dalla .text, teoricamente basta patchare solo i valori di indirizzo perche' il resto sono offset da lui

def estrai_valore(instruzione):
    # Usa un'espressione regolare per cercare un numero esadecimale nella stringa
    match = re.search(r'0x[0-9a-fA-F]+', instruzione)
    
    # Se un numero esadecimale è stato trovato, convertilo in un intero e restituiscilo
    if match:
        return int(match.group(), 16)
    else:
        return 0


def get_section(pe_file,name):
    for section in pe_file.sections:
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


class PEFile:
    def __init__(self,file,increase_size):
        self.pe = pefile.PE(file)
        self.text_section = get_section(self.pe,b'.text\x00\x00\x00')
        self.next_section = get_section(self.pe,b'.rdata\x00\x00')
        self.increase_size = increase_size
        self.file = file

        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True
        self.cs.skipdata = True

        self.ks = Ks(KS_ARCH_X86, KS_MODE_64)

        self.instructions = []

        self.jump_table = []
        self.start_end_table = []

        self.base_address = self.text_section.VirtualAddress
        self.raw_base_address = self.text_section.PointerToRawData

        self.code_section_size = self.text_section.SizeOfRawData

        self.raw_code = self.text_section.get_data(self.base_address, self.code_section_size)

        self.ImportAddressTable = None


        with open('instr_incrs_text.txt', 'r+') as f:
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

        self.create_jmp_table()


    def print_instructions(self):
        with open('instr_incrs_text.txt', 'r+') as f:

            for x,i in enumerate(self.instructions):
                stringa  = f"{hex(i.new_instruction.address)} {i.new_instruction.bytes} {len(i.new_instruction.bytes)}  {i.new_instruction.mnemonic}  {i.new_instruction.op_str}\n"
                f.write(stringa)


    def patch_headers_and_sections(self):
        with open(self.file, 'r+b') as f:
            opt_hdr = self.pe.OPTIONAL_HEADER
            print(opt_hdr)
            dict = opt_hdr.dump_dict()

            original_file = bytearray(f.read())

    ##################################################################### AGGIUSTO SIZE OF CODE
            SizeOfCode_addr = int(dict['SizeOfCode']['FileOffset'])
            new_SizeOfCode = int(dict['SizeOfCode']['Value'])
            new_SizeOfCode += self.increase_size


            print("new_SizeOfCode: ", hex(new_SizeOfCode))

            original_file[SizeOfCode_addr:SizeOfCode_addr+4] = new_SizeOfCode.to_bytes(4,byteorder='little')
    #####################################################################

    #####################################################################AGGIUSTO SIZE OF IMAGE
            SizeOfImage_addr = int(dict['SizeOfImage']['FileOffset'])
            new_SizeOfImage = int(dict['SizeOfImage']['Value'])
            new_SizeOfImage += self.increase_size
            original_file[SizeOfImage_addr:SizeOfImage_addr+4] = new_SizeOfImage.to_bytes(4,byteorder='little')
    #####################################################################
    #####################################################################AGGIUSTO DATA DIRECTORY

            for data in opt_hdr.DATA_DIRECTORY:
                if data.VirtualAddress != 0:
                    data = data.dump_dict()
                    addr = data['VirtualAddress']['FileOffset']
                    nuovo_valore = data['VirtualAddress']['Value'] + self.increase_size
                    #data.Size += increase_size
                    original_file[addr:addr+4] = nuovo_valore.to_bytes(4,byteorder='little')



    #####################################################################AGIUSTO SEZIONI
            for section in self.pe.sections:
                section = section.dump_dict()
                print(section)
                print("\n\n")
                if '.text' in section['Name']['Value']:
                    #patcho la .text
                    section_addr = section['SizeOfRawData']['FileOffset']
                    section_size = section['SizeOfRawData']['Value']
                    section_virtual_size = section['Misc_VirtualSize']['Value']

                    section_size += self.increase_size
                    section_virtual_size += self.increase_size

                    original_file[section_addr:section_addr+4] = section_size.to_bytes(4,byteorder='little')
                    original_file[section['Misc_VirtualSize']['FileOffset']:section['Misc_VirtualSize']['FileOffset']+4] = section_virtual_size.to_bytes(4,byteorder='little')

                else:
                    #patcho le altre sezioni

                    section_virtual_addr = section['VirtualAddress']['Value']
                    section_pointer_to_raw_data = section['PointerToRawData']['Value']

                    section_virtual_addr += self.increase_size
                    section_pointer_to_raw_data += self.increase_size

                    original_file[section['VirtualAddress']['FileOffset']:section['VirtualAddress']['FileOffset']+4] = section_virtual_addr.to_bytes(4,byteorder='little')
                    original_file[section['PointerToRawData']['FileOffset']:section['PointerToRawData']['FileOffset']+4] = section_pointer_to_raw_data.to_bytes(4,byteorder='little')


            f.seek(0)
            f.write(original_file)
            f.close()


    def patch_import_table(self):
        import_table = self.pe.DIRECTORY_ENTRY_IMPORT
        for i in import_table:
            struct = i.struct
            struct = struct.dump_dict()
            FirstThunk = struct['FirstThunk']['Value']
            indirizzo = self.pe.get_qword_at_rva(FirstThunk)
            new_FirstThunk = FirstThunk + self.increase_size
            self.pe.set_qword_at_rva(FirstThunk,new_FirstThunk)
            print("indirizzo: ",hex(indirizzo))
        self.pe.write(self.file)

            
        time.sleep(10000)
        for imp in import_table:
            struct = imp.struct
            struct = struct.dump_dict()
            #print(struct)

            OriginalFirstThunk = struct['OriginalFirstThunk']['Value']
            OriginalFirstThunk_addr = struct['OriginalFirstThunk']['FileOffset']
            new_OriginalFirstThunk = OriginalFirstThunk + self.increase_size

            Characteristics = struct['Characteristics']['Value']
            Characteristics_addr = struct['Characteristics']['FileOffset']
            new_Characteristics = Characteristics + self.increase_size

            Name = struct['Name']['Value']
            Name_addr = struct['Name']['FileOffset']
            new_Name = Name + self.increase_size

            FirstThunk = struct['FirstThunk']['Value']
            FirstThunk_addr = struct['FirstThunk']['FileOffset']
            new_FirstThunk = FirstThunk + self.increase_size

            with open(self.file, 'r+b') as f:
                original_file = bytearray(f.read())

                original_file[OriginalFirstThunk_addr:OriginalFirstThunk_addr+4] = new_OriginalFirstThunk.to_bytes(4,byteorder='little')
                original_file[Characteristics_addr:Characteristics_addr+4] = new_Characteristics.to_bytes(4,byteorder='little')
                original_file[Name_addr:Name_addr+4] = new_Name.to_bytes(4,byteorder='little')
                original_file[FirstThunk_addr:FirstThunk_addr+4] = new_FirstThunk.to_bytes(4,byteorder='little')

                f.seek(0)
                f.write(original_file)
                f.close()

            



    def patch_reloc_table(self):
        for entries in self.pe.DIRECTORY_ENTRY_BASERELOC:
            entry_struct = entries.struct
            entry_struct = entry_struct.dump_dict()
            print(entry_struct)

            VirtualAddress = entry_struct['VirtualAddress']['Value']
            VirtualAddress_addr = entry_struct['VirtualAddress']['FileOffset']
            new_VirtualAddress = VirtualAddress + self.increase_size
            print("new_VirtualAddress: ",hex(new_VirtualAddress))

            with open(self.file, 'r+b') as f:
                original_file = bytearray(f.read())

                original_file[VirtualAddress_addr:VirtualAddress_addr+4] = new_VirtualAddress.to_bytes(4,byteorder='little')

                f.seek(0)
                f.write(original_file)
                f.close()

            #for reloc in entries.entries:
                

    def increase_text_section(self):
        new_bytes = b'\x90' * self.increase_size

        text_section_start = self.raw_base_address
        text_section_end = self.raw_base_address + self.code_section_size

        with open(self.file, 'r+b') as f:
            original_file = bytearray(f.read())
            original_file = original_file[:text_section_end] + new_bytes + original_file[text_section_end:]
            f.seek(0)
            f.write(original_file)
            f.close()

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


    def check_if_inside_jmp_table(self,address):
        inside_jmp_table = False
        for jmp in self.start_end_table:
            if address >= jmp[0] and address <= jmp[1]:
                inside_jmp_table = True

        return inside_jmp_table
    
    def adjust_out_text_references(self):
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

                    addr = self.instructions[num_instr + 1].original_instruction.address + valore_originale

                    # print("valore_originale: ",valore_originale)
                    # print("nuovo indirizzo: ",hex(addr))
                    #checko se l'indirizzo e'all'interno della .text
                    if addr > self.base_address and addr < self.base_address + self.code_section_size:
                        continue
                    offset = addr - self.instructions[num_instr + 1].new_instruction.address
                    offset += self.increase_size

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
                        continue


                    offset = self.instructions[num_instr + 1].new_instruction.address - addr
                    offset += self.increase_size

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




if __name__ == '__main__':
    file = "hello_world.exe"

    increase_size = 0x2000
    # text_section = get_section(pe,b'.text\x00\x00\x00')

    # next_section = get_section(pe,b'.rdata\x00\x00')
    extend = PEFile(file,increase_size)
    #extend.patch_import_table()
    #time.sleep(10000)

    # extend.patch_headers_and_sections()
    # extend.adjust_out_text_references()
    extend.patch_import_table()
    # extend.patch_reloc_table()
    
    # extend.increase_text_section()
    # extend.print_instructions()

