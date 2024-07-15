    # import r2pipe

    # # Crea un'istanza di r2pipe collegata all'eseguibile
    # r2 = r2pipe.open("hello_world.exe")

    # # Analizza l'eseguibile
    # r2.cmd('aaa')

    # # Trova tutte le xref al tuo indirizzo
    # xrefs = r2.cmdj('axt 0x140001000')

    # # Stampa le xref
    # for xref in xrefs:
    #     print(hex(xref))

    # # Chiudi r2pipe
    # r2.quit()
import lief

pe = lief.parse("hello_world.exe")

xref = pe.xref(0x1f5d4)
for x in xref:
    print(hex(x))