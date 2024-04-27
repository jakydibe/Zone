import pefile



pe = pefile.PE("hello_world.exe")

#dumping the relocation table
#DIRECTORY_ENTRY_BASERELOC: list of BaseRelocationData instances
# struct
# IMAGE_BASE_RELOCATION structure.
# entries
# List of relocation data as RelocationData instances.

# RelocationData
def adjust_reloc_table(pe):
    for entries in pe.DIRECTORY_ENTRY_BASERELOC:
        for reloc in entries.entries:
            data = pe.get_qword_at_rva(reloc.rva)
            data = data - pe.OPTIONAL_HEADER.ImageBase
            #print(hex(reloc.rva), reloc.type,hex(data))#, reloc.value)
            print(hex(reloc.rva), hex(data))


#adjust_reloc_table(pe)
print(pe.dump_info())