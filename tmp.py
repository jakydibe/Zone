import os

INPUT_FILE = 'original_working.txt'

OUTPUT_DIR = 'original_pl'

NEW_PL_DIR64 = 'new_pl\\new_pl\\output\\x64'
NEW_PL_DIR86 = 'new_pl\\new_pl\\output\\x86'



nice_pl = []

nice_x64 = []
nice_x86 = []

with open(INPUT_FILE, 'r') as f:
    lines = f.readlines()
    
    for line in lines:
        line = line.strip()
        # print(line)
        line = line.split(',')
        # print(line)
        if line[2] == 'OK':
            pl_name = line[0][4:]
            
            if 'x64' in line[0]:
                nice_x64.append(pl_name)
            elif 'x86' in line[0]:
                nice_x86.append(pl_name)
            # print(line[0])

print("Number of x64 PLs: ", len(nice_x64))
print("Number of x86 PLs: ", len(nice_x86))

for x64_pl in nice_x64:
    pl_path = os.path.join(NEW_PL_DIR64, x64_pl)
    # copy the file to the new directory
    new_pl_path = os.path.join(OUTPUT_DIR, 'x64', x64_pl)
    os.makedirs(os.path.dirname(new_pl_path), exist_ok=True)
    os.system(f'copy "{pl_path}" "{new_pl_path}"')

for x86_pl in nice_x86:
    pl_path = os.path.join(NEW_PL_DIR86, x86_pl)
    # copy the file to the new directory
    new_pl_path = os.path.join(OUTPUT_DIR, 'x86', x86_pl)
    os.makedirs(os.path.dirname(new_pl_path), exist_ok=True)
    os.system(f'copy "{pl_path}" "{new_pl_path}"')
