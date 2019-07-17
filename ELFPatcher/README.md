# ELF Patcher

> ELF Patcher for x86/x86-64/ARM ELF executables, currently only ARM binaries has PIE support.
> This is a helper for migrating AFL instrumentation to native, and also could be used for patching
> in an Attack & Defense style CTF game.

## Todo

+ Add PIE support for x86/x86-64 ELFs

## Interfaces

```python
from elfpatcher import ELF

# open elf file from 'inputfile'
elf = ELF(filename='inputfile')

# import 'libc.so.6'
elf.add_imported_library(libfile='libc.so.6')

# import 'puts' from 'libc.so.6', which can be referenced by label '_puts', if libfile is not
# imported, it will be imported automatically
elf.add_imported_symbol(name='puts', label='_puts', libfile='libc.so.6')

# add string data 'Hello World\x00' with alignment = ALIGN_DATA, which can be referenced by
# label 'data_string'
elf.add_data(label='data_string', data='Hello World\x00', align=ALIGN_DATA)

# add a pointer in data section, which can be referenced by label 'reflabel'. and its content
# is a pointer points to an address referenced by label 'target'
elf.add_pointer(label='reflabel', target_label='target')

# add code snippet "xor rax, rax" with alignment = ALIGN_CODE, which can be referenced by label
# 'code_label'
elf.add_code(label='code_label', code="xor rax, rax", align=ALIGN_CODE)

# add code snippet "xor rax, rax" with alignment = ALIGN_CODE, which can be referenced by label
# 'code_label1'. the code is executed before instructions at virtual address 0x1000 in the elf.
# nbound is the boundary for patching safely, if boundary is too small to fit a patched branch
# instruction, this will fail. if nbound is None, no boundary check will be made
elf.insert_code(where=0x1000, label='code_label1', code="xor rax, rax", nbound=0x1010, 
                align=ALIGN_CODE)

# add code snippet "xor rax, rax" with alignment = ALIGN_CODE, which can be referenced by label
# 'code_label2'. the code replaces instructions between virtual address 0x1000 and 0x1010 in the
# elf. this is done by branch out and branch back, so if there is not enough space for a branch
# instruction, this will fail.
elf.patch_code(fromwhere=0x1000, towhere=0x1010, label='code_label2', code="xor rax, rax",
               align=ALIGN_CODE)

# create 'exlabel' = 0xdeadbeef for further reference, if reloc is True, this value is treated
# as virtual address, and will be relocated for PIE ELF
elf.add_exlabel(label='exlabel', value=0xdeadbeef, reloc=False)

# add label 'rlabel' which points to 'tlabel' + 0x10
elf.add_relative_label(label='rlabel', target='tlabel', offset=0x10)

# add code snippet referenced by 'init_entry' to .init_array
elf.add_init_function(label='init_entry')

# add tls uninitialized data with size = 0x100, and symbol name = 'tls_data', the offset of the
# data inside tls block can be referenced as a long int by label 'tls_data_offset'
elf.add_tls_bss_data(name='tls_data', size=0x100, offset_label='tls_data_offset')

# change elf interpreter to new interpreter path '/tmp/newld.so'
elf.change_interp(new_interp='/tmp/newld.so')

# save all changes to 'outputfile'
elf.save(filename='outputfile')
```
