import re

def estrai_valore(instruzione):
    # Usa un'espressione regolare per cercare un numero esadecimale nella stringa
    match = re.search(r'0x[0-9a-fA-F]+', instruzione)
    
    # Se un numero esadecimale è stato trovato, convertilo in un intero e restituiscilo
    if match:
        return int(match.group(), 16)
    else:
        return 0
    

def get_text_section(pe, address):
    #return pe.O
    for section in pe.sections:
        if section.contains_rva(address):
            print(section.Name, hex(section.VirtualAddress),hex(section.Misc_VirtualSize), section.SizeOfRawData )
            return section


def get_section(pe,name):
    for section in pe.sections:
        if section.Name == name:
            print(section.Name, hex(section.VirtualAddress),hex(section.Misc_VirtualSize), section.SizeOfRawData )
            return section
    return None
