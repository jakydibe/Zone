# Zone: A PE-Obfuscator with Metamorphic Engine

## Overview

**Zone** is a PE-obfuscator equipped with a metamorphic engine, designed to evade static analysis. This project represents a significant personal achievement, likened to the most challenging "hello_world.exe" I've ever created.

## Introduction to Metamorphism

Metamorphism is a sophisticated technique used in software obfuscation, particularly for evading static analysis. Unlike simpler techniques, metamorphism modifies the executable at the assembly level while preserving its original functionality. This approach inserts a high level of randomness, making it extremely difficult to create a reliable signature for detection.

## Why Metamorphism?

Static analysis evasion techniques often fall short as they can be easily detected and signatured, especially in the case of crypters/packers and simple payload executors. Metamorphism addresses these limitations by ensuring every run of the engine generates a different version of the executable, with no detectable stubs left behind.

## The Journey

Creating a metamorphic engine/PE obfuscator is no small feat. This project has been the most challenging endeavor of my life, largely due to the lack of existing code to reference. The name ‘Zone’ is inspired by the film "Stalker" by Andrei Tarkovsky, reflecting a place where every path appears different but leads to the same destination.

## Code Morphing Techniques

### 1. Equal Code Substitution

This technique involves replacing certain instructions with other instructions that achieve the same result but in a different way. For example:
- `xor reg, reg` → `mov reg, 0`
- `sub reg, 0xVALUE` → `add reg, -0xVALUE`
- `mov REG, 0xVALUE` → `push VALUE; pop REG`

### 2. Random NOPs Insertion

Random instructions that do not affect the functionality of the program are inserted into the code. These include:
- `NOP`
- `SUB REG, 0x0`
- `ADD REG, 0x0`
- `MOV REG, REG`
- `LEA REG, [REG+0]`
- `PUSH REG` and `POP REG`
- Various other instructions that modify CPU flags, surrounded by `PUSHF` and `POPF` to preserve the flags' state.

## Future Enhancements

### Bogus Control Flow

This technique, planned for future implementation, involves creating fake conditions and blocks of code that will never be executed, confusing decompilers, malware analysts, and AVs.

### Instruction Blocks Permutation

Currently in development, this feature will involve dividing instructions into blocks, adding jumps at the end of each block, and shuffling these blocks to create highly obfuscated code.

## Implementation Details

### Tools

This project utilizes two Python libraries:
- **Capstone**: A disassembler.
- **Keystone**: An assembler.

# How Instructions are Patched



The program searches the .text section of the file and takes all the raw code. It then disassembles all the code with Capstone and iterates through the instructions, creating a global list of a struct named `Instruction` (which I created). 

This is the struct:

# Example struct definition
class Instruction:
    def __init__(self, address, mnemonic, op_str):
        self.address = address
        self.mnemonic = mnemonic
        self.op_str = op_str
```

Creating a global dictionary which will be `self.instr_dict[‘address’] = instruction`. It is done this way only because dictionaries are faster to use than lists.

Create a list of addresses which are used for jump-tables (`self.create_jmp_table()`).

I found a way to detect jump tables in this article: [Obfuscator Part 1](https://blog.es3n1n.eu/posts/obfuscator-pt-1/). Basically, jump tables are created by switch-case statements, and if I modify the addresses of my instruction, I also need to modify the addresses inside the jump tables.

Create a LABEL TABLE (`self.create_label_table()`).

This label table will be a list of tuples. I create the label table by iterating through all instructions and checking if they are some sort of JUMP or CALL. If they are a JUMP or a CALL, I create the tuple like this: 

```python
(JMP_INSTRUCTION, INSTRUCTION_WHERE_I_JUMP)
```

5. Do all the code modifications (equal code substitution, NOP insertions, etc.).

6. Patch the JUMP/CALL and all the references.

First, I patch all the jump/call instructions which typically do not have references outside of the .text section (`self.update_label_table()`). Then, I patch all the instructions (for example JMP/CALL/MOV) which have references to outside of the .text section. To know if they have such references, just search the disassembled string for something like `JMP QWORD PTR [RIP + 0x12345]`.

7. Patch the RELOC TABLE:

    A. Since all addresses changed and subroutine addresses changed, we need to patch the RELOC_TABLE, which is a structure used by the LOADER to modify hardcoded addresses when loading an .exe in memory.
    
    Check this to learn more about why we need to patch the RELOC TABLE: [PE Internals Part 7](https://0xrick.github.io/win-internals/pe7/).

8. Writing modifications to the file:

    A. Writing a new entry point.

