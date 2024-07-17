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

### Process

1. **Disassemble the .text section**: Use Capstone to iterate through instructions, creating a global list of an `Instruction` struct.
2. **Create a label table**: Identify and list all jump and call instructions.
3. **Code modifications**: Implement equal code substitution, NOP insertions, and other techniques.
4. **Patch jump/call instructions**: Adjust references within and outside the .text section.
5. **Patch the relocation table**: Update hardcoded addresses used by the loader.
6. **Write modifications to the file**: Create a new entry point if necessary.
7. **Increase the .text section**: If heavily modified, adjust the section size and patch relevant headers.

### Challenges

Modifying the .text section requires:
- Patching headers such as `SizeOfCode`, `SizeOfImage`, and entries in the `DATA_DIRECTORY`.
- Adjusting the import table, security cookie, and references outside the .text section.

## Conclusion

Zone represents a significant advancement in the field of PE-obfuscation with its metamorphic engine. While challenging to develop, this tool provides a robust method for evading static analysis, paving the way for future enhancements and more sophisticated obfuscation techniques.
