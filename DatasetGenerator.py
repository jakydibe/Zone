from capstone import *
import os
import sys
import random
import json

payload_dir = 'out_payloads'


# 1) prendi in input i payload e crea una lista da passare alla classe
# 2) disassembla i payload e e crea una lista di classe con istruzioni per ogni payload
# 3) crea un dataset inserendo randomicamente byte casuali in mezzo alle istruzioni
# 4) Crea un json con formato seguente: {nome_payload: [array di array di byte(ogni sotto array e' istruzione)], posizione raw byte aggiunti}



class DatasetGenerator:
    def __init__(self, payloads):
        self.classifiers = []
        self.payloads = payloads
        self.cs32 = Cs(CS_ARCH_X86, CS_MODE_32)
        self.cs64 = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs32.detail = True
        self.cs64.detail = True
        self.payload_instr_dict = {}
        
        self.cs64.skipdata = True
        self.cs32.skipdata = True

        self.cs64.skipdata_callback = self.cb
        self.cs32.skipdata_callback = self.cb

        self.additional_data_positions_tmp = []
        self.additional_data_positions_dict = {}

        self.data_prob = 0.025

        self.final_dataset = {}
        self.debug = False
    def cb(self,b, s, o, d):
        print("Callback called")
        print("Buffer: ", b)
        print("Size: ", s)
        print("Offset: ", o)
        print("Data: ", d)
        self.additional_data_positions_tmp.append(o)
        return 4
    def disassemble(self, payload, mode):
        
        with open(os.path.join(payload_dir, payload), 'rb') as f:
            data = f.read()
        disassembled = []
        # check if payload is valid

        if mode == 64:
            for i in self.cs64.disasm(data, 0x0):
                # if i.mnemonic == '.byte':
                #     print("raw bytes!!")
                raw_bytes = i.bytes
                # converto bytearray in array di interi
                raw_bytes = [byte for byte in raw_bytes] 
                disassembled.append(raw_bytes)
        elif mode == 32:
            for i in self.cs32.disasm(data, 0x0):
                raw_bytes = i.bytes
                raw_bytes = [byte for byte in raw_bytes]
                disassembled.append(raw_bytes)

        self.additional_data_positions_dict[payload] = self.additional_data_positions_tmp
        self.additional_data_positions_tmp = []
        if len(data) == 0:
            return -1
        return disassembled
    def insert_random_bytes(self, payload):
        byte_array = self.payload_instr_dict[payload]
        new_byte_array = []

        data_pos_array = []
        inserted_arrs = 0
            
        for x,instr in enumerate(byte_array):
            new_byte_array.append(instr)
            
            random_prob = random.randint(0, 100) / 100
            if random_prob < self.data_prob:
                # random_num_bytes = random.randint(1, 10) 
                # random_num_bytes = random.choices(range(1, 11), weights=[10-i for i in range(10)])[0]
                weights = [11 - i for i in range(1, 11)] 
                random_num_bytes = random.choices(range(1, 11), weights=weights, k=1)[0]

                instr_arr = []
                inserted_arrs += 1

                for _ in range(random_num_bytes):
                    if self.debug:
                        instr_arr.append(random.randint(1000, 1010))
                    else:
                        instr_arr.append(random.randint(0, 255))
                data_pos_array.append(x + inserted_arrs)

                new_byte_array.append(instr_arr)
        
        self.final_dataset[payload] = [new_byte_array, data_pos_array]
        # aggiungo altri dati
        byte_added = 0
        for x,instr in enumerate(new_byte_array):
            already_added = False
            for data_pos in self.additional_data_positions_dict[payload]:
                if already_added:
                    break
                if data_pos >= byte_added and data_pos < byte_added + len(instr):
                    already_added = True
                    if self.final_dataset[payload][1].count(x) == 0:
                        self.final_dataset[payload][1].append(x)
            byte_added += len(instr)
                    
    
    def check_dataset_debug(self,payload):
        data_arr_pos = self.final_dataset[payload][1]
        data_arr = self.final_dataset[payload][0]

        for x,pos in enumerate(data_arr_pos):
            if data_arr[pos][0] < 1000:
                print(f"Error at pos {pos}")
            else:
                print(f"Correct dataset generated at pos {pos}")
    

def main():

    # iterate through payloads
    # out_payloads is a directory that contains subdirectories with payloads
    subdirs = os.listdir(payload_dir)
    payloads = []
    for subdir in subdirs:
        relative_path = os.path.join(payload_dir, subdir)
        tmp_payloads = os.listdir(relative_path)
        for pl in tmp_payloads:
            payloads.append(os.path.join(subdir, pl))

    print(payloads)

    dg = DatasetGenerator(payloads)

    for x,payload in enumerate(payloads):
        disassembled = dg.disassemble(payload, 64)
        if disassembled == -1:
            print(f"Invalid payload: {payload}")
            continue
        print(f"Payload: {payload}")
        dg.payload_instr_dict[payload] = disassembled
        dg.insert_random_bytes(payload)
        
        # if x > 1:
        #     break
        print(dg.final_dataset[payload])
        if dg.debug:
            dg.check_dataset_debug(payload)

    # save the final dataset to file
    with open('dataset.json', 'w') as f:
        json.dump(dg.final_dataset, f)

if __name__ == '__main__':
    main()