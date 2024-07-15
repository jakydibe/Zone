from capstone import *
import sys
import pefile
import time

instr_max_size = 9


adjusted_array = []

def get_base_address(pe):
    return pe.OPTIONAL_HEADER.BaseOfCode

def get_entry_point(pe):
    return pe.OPTIONAL_HEADER.AddressOfEntryPoint

def get_size_of_image(pe):
     return pe.OPTIONAL_HEADER.SizeOfImage

def get_text_section(pe, address):
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

if __name__ == '__main__':
     #try:
     #exe_path = str(sys.argv[1])

     pe = pefile.PE("C:\\Users\\jakyd\\Downloads\\startup.exe")

     base_address = get_base_address(pe)
     print("Base address: 0x%x" %base_address)
     code_section = get_text_section(pe, base_address)
     print(code_section.Name, hex(code_section.VirtualAddress),hex(code_section.Misc_VirtualSize), code_section.SizeOfRawData )
     code_section_size = get_section_size(code_section)
     raw_bytes = code_section.get_data(base_address,code_section_size)



     cs = Cs(CS_ARCH_X86, CS_MODE_64)

     for x,i in enumerate(cs.disasm(raw_bytes, base_address)):
          #scrivimi tutti i campi di i (address, mnemonic, op_str)
          #time.sleep(1000)
          print("{}:\t{} \t{}\t{}".format(hex(i.address),bytearray(i.bytes), i.mnemonic, i.op_str))
          #print(len(i.bytes))
          adjusted_array.append(i.bytes)
          for n in range(instr_max_size - len(i.bytes)):
               adjusted_array[x] += b'\x90'


print(adjusted_array)
