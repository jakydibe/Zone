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
#0) inizializzare tutto
#1) dumpare la .text
#2) disassemblare la .text e aggiungere le istruzioni alla lista self.instructions
#3) creare le label
#4) modificare un'istruzione (solo per testing)
#5) aggiornare (incrementare) le varie istruzioni
#6) aggiornare le varie jump o varie references    ##########################*********************************######################
#7) controllare tutte istruzioni con 'rip +' dentro (sono istruzioni che puntano alla .data)
#   7.1) similmente alle jump, calcolare l' indirizzo grazie all'indirizzo originale
#8) scrivere il PE
#
#
from capstone import *   #e' un disassembler
from keystone import *   #e' un assembler
import sys
import pefile
import lief
import time
import os
import re
from capstone import x86_const

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

