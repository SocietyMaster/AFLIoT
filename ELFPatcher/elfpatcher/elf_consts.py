#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Himyth / AAA """

Elf32_Addr = 4
Elf32_Half = 2
Elf32_Off = 4
Elf32_Sword = 4
Elf32_Word = 4
Elf32_Char = 1

Elf64_Addr = 8
Elf64_Half = 2
Elf64_Off = 8
Elf64_Sword = 4
Elf64_Word = 4
Elf64_Sxword = 8
Elf64_Xword = 8
Elf64_Char = 1

PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_SHLIB = 5
PT_PHDR = 6
PT_TLS = 7
PT_GNU_EH_FRAME = 0x6474e550
PT_GNU_STACK = 0x6474e551
PT_GNU_RELRO = 0x6474e552

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_HASH = 5
SHT_DYNAMIC = 6
SHT_NOTE = 7
SHT_NOBITS = 8
SHT_REL = 9
SHT_SHLIB = 10
SHT_DYNSYM = 11
SHT_INIT_ARRAY = 14
SHT_FINI_ARRAY = 15
SHT_PREINIT_ARRAY = 16
SHT_GROUP = 17
SHT_SYMTAB_SHNDX = 18
SHT_GNU_HASH = 0x6ffffff6
SHT_GNU_VERDEF = 0x6ffffffd
SHT_GNU_VERNEED = 0x6ffffffe
SHT_GNU_VERSYM = 0x6fffffff

DT_NULL = 0
DT_NEEDED = 1
DT_PLTRELSZ = 2
DT_PLTGOT = 3
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_STRSZ = 10
DT_SYMENT = 11
DT_INIT = 12
DT_FINI = 13
DT_SONAME = 14
DT_RPATH = 15
DT_SYMBOLIC = 16
DT_REL = 17
DT_RELSZ = 18
DT_RELENT = 19
DT_PLTREL = 20
DT_DEBUG = 21
DT_TEXTREL = 22
DT_JMPREL = 23
DT_INIT_ARRAY = 25
DT_FINI_ARRAY = 26
DT_INIT_ARRAYSZ = 27
DT_FINI_ARRAYSZ = 28
DT_GNU_HASH = 0x6ffffef5
DT_GNU_VERSYM = 0x6ffffff0
DT_RELACOUNT = 0x6ffffff9
DT_RELCOUNT = 0x6ffffffa

PF_R = 0x4
PF_W = 0x2
PF_X = 0x1

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SHF_MERGE = 0x10
SHF_STRINGS = 0x20
SHF_INFO_LINK = 0x40
SHF_LINK_ORDER = 0x80
SHF_OS_NONCONFORMING = 0x100
SHF_GROUP = 0x200
SHF_TLS = 0x400

STN_UNDEF = 0

STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2
STB_LOPROC = 13
STB_HIPROC = 15

STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STT_SECTION = 3
STT_FILE = 4
STT_COMMON = 5
STT_TLS = 6
STT_LOPROC = 13
STT_HIPROC = 15

R_ARM_GLOB_DAT = 0x15
R_386_GLOB_DAT = 0x6
R_X86_64_GLOB_DAT = 0x6

R_ARM_TLS_TPOFF32 = 19
R_386_TLS_TPOFF32 = 37
R_X86_64_TPOFF64 = 18

R_ARM_RELATIVE = 23
R_386_RELATIVE = 8
R_X86_64_RELATIVE = 8

ELFCLASSNONE = 0x0
ELFCLASS32 = 0x1
ELFCLASS64 = 0x2

ELFDATANONE = 0x0
ELFDATA2LSB = 0x1
ELFDATA2MSB = 0x2

EM_386 = 3
EM_MIPS = 8
EM_ARM = 40
EM_X86_64 = 62

ET_NONE = 0
ET_REL = 1
ET_EXEC = 2
ET_DYN = 3
ET_CORE = 4
ET_LOPROC = 0xff00
ET_HIPROC = 0xffff

SZ_ELF32_REL_ENT = 0x8
SZ_ELF32_RELA_ENT = 0xc
SZ_ELF64_REL_ENT = 0x10
SZ_ELF64_RELA_ENT = 0x18

SZ_EI_MAGIC = 4
SZ_EI_PAD = 7

ALIGN_SECTION = 0x8
ALIGN_DATA = 0x8
ALIGN_CODE = 0x10

EI_NIDENT = 0x10
PAGE_SIZE = 0x1000

STRTAB_SH = 0
STRTAB_SYM = 1

ARM_WRAP_NONE = 0x0
ARM_WRAP_JUMPTABLE = 0x1
ARM_WRAP_NORMAL = 0x2
ARM_WRAP_PUSHPC = 0x3

X64_WRAP_NONE = 0x0
X64_WRAP_NORMAL = 0x1
