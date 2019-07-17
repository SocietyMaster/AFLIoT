#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Himyth / AAA """

from elf_utils import *


class Elf64_Dyn(object):

    def __init__(self, packer=None, d_tag=0, d_val=0):
        self.packer = packer  # type: Packer
        self.d_tag = d_tag
        self.d_val = d_val

    def __str__(self):
        return ("Elf64_Dyn:\n" +
                ("\t%-16s: %#x\n" % ('d_tag', self.d_tag)) +
                ("\t%-16s: %#x\n" % ('d_val', self.d_val))
                )

    def parse(self, stream, offset, packer):
        self.packer = packer
        stream.seek(offset, 0)

        self.d_tag = self.packer.unpack(stream.read(Elf64_Sxword))
        self.d_val = self.packer.unpack(stream.read(Elf64_Xword))

        return self

    def serialize(self):
        data = ''

        data += self.packer.pack(self.d_tag, Elf64_Sxword)
        data += self.packer.pack(self.d_val, Elf64_Xword)

        return data


class Elf64_Ehdr(object):

    def __init__(self, packer=None, e_type=0, e_machine=0, e_version=0,
                 e_entry=0, e_phoff=0, e_shoff=0, e_flags=0, e_ehsize=0,
                 e_phentsize=0, e_phnum=0, e_shentsize=0, e_shnum=0,
                 e_shstrndx=0, **kwargs):
        self.packer = packer  # type: Packer
        self.e_ident = Elf64_E_Ident(packer=packer, **kwargs)
        self.e_type = e_type
        self.e_machine = e_machine
        self.e_version = e_version
        self.e_entry = e_entry
        self.e_phoff = e_phoff
        self.e_shoff = e_shoff
        self.e_flags = e_flags
        self.e_ehsize = e_ehsize
        self.e_phentsize = e_phentsize
        self.e_phnum = e_phnum
        self.e_shentsize = e_shentsize
        self.e_shnum = e_shnum
        self.e_shstrndx = e_shstrndx

    def __str__(self):
        return ("Elf64_Ehdr:\n" +
                ("\t%-16s: \n%s\n" % ('e_ident', str(self.e_ident))) +
                ("\t%-16s: %#x\n" % ('e_type', self.e_type)) +
                ("\t%-16s: %#x\n" % ('e_machine', self.e_machine)) +
                ("\t%-16s: %#x\n" % ('e_version', self.e_version)) +
                ("\t%-16s: %#x\n" % ('e_entry', self.e_entry)) +
                ("\t%-16s: %#x\n" % ('e_phoff', self.e_phoff)) +
                ("\t%-16s: %#x\n" % ('e_shoff', self.e_shoff)) +
                ("\t%-16s: %#x\n" % ('e_flags', self.e_flags)) +
                ("\t%-16s: %#x\n" % ('e_ehsize', self.e_ehsize)) +
                ("\t%-16s: %#x\n" % ('e_phentsize', self.e_phentsize)) +
                ("\t%-16s: %#x\n" % ('e_phnum', self.e_phnum)) +
                ("\t%-16s: %#x\n" % ('e_shentsize', self.e_shentsize)) +
                ("\t%-16s: %#x\n" % ('e_shnum', self.e_shnum)) +
                ("\t%-16s: %#x\n" % ('e_shstrndx', self.e_shstrndx))
                )

    def parse(self, stream, offset):
        stream.seek(offset, 0)

        self.e_ident = Elf64_E_Ident().parse(stream, stream.tell())
        self.packer = self.e_ident.packer

        self.e_type = self.packer.unpack(stream.read(Elf64_Half))
        self.e_machine = self.packer.unpack(stream.read(Elf64_Half))
        self.e_version = self.packer.unpack(stream.read(Elf64_Word))
        self.e_entry = self.packer.unpack(stream.read(Elf64_Addr))
        self.e_phoff = self.packer.unpack(stream.read(Elf64_Off))
        self.e_shoff = self.packer.unpack(stream.read(Elf64_Off))
        self.e_flags = self.packer.unpack(stream.read(Elf64_Word))
        self.e_ehsize = self.packer.unpack(stream.read(Elf64_Half))
        self.e_phentsize = self.packer.unpack(stream.read(Elf64_Half))
        self.e_phnum = self.packer.unpack(stream.read(Elf64_Half))
        self.e_shentsize = self.packer.unpack(stream.read(Elf64_Half))
        self.e_shnum = self.packer.unpack(stream.read(Elf64_Half))
        self.e_shstrndx = self.packer.unpack(stream.read(Elf64_Half))

        return self

    def serialize(self):
        data = ''

        data += self.e_ident.serialize()
        data += self.packer.pack(self.e_type, Elf64_Half)
        data += self.packer.pack(self.e_machine, Elf64_Half)
        data += self.packer.pack(self.e_version, Elf64_Word)
        data += self.packer.pack(self.e_entry, Elf64_Addr)
        data += self.packer.pack(self.e_phoff, Elf64_Off)
        data += self.packer.pack(self.e_shoff, Elf64_Off)
        data += self.packer.pack(self.e_flags, Elf64_Word)
        data += self.packer.pack(self.e_ehsize, Elf64_Half)
        data += self.packer.pack(self.e_phentsize, Elf64_Half)
        data += self.packer.pack(self.e_phnum, Elf64_Half)
        data += self.packer.pack(self.e_shentsize, Elf64_Half)
        data += self.packer.pack(self.e_shnum, Elf64_Half)
        data += self.packer.pack(self.e_shstrndx, Elf64_Half)

        return data


class Elf64_Nhdr(object):

    def __init__(self, packer=None, n_namesz=0, n_descsz=0, n_type=0):
        self.packer = packer  # type: Packer
        self.n_namesz = n_namesz
        self.n_descsz = n_descsz
        self.n_type = n_type

    def __str__(self):
        return ("Elf64_Nhdr:\n" +
                ("\t%-16s: %#x\n" % ('n_namesz', self.n_namesz)) +
                ("\t%-16s: %#x\n" % ('n_descsz', self.n_descsz)) +
                ("\t%-16s: %#x\n" % ('n_type', self.n_type))
                )

    def parse(self, stream, offset, packer):
        self.packer = packer
        stream.seek(offset, 0)

        self.n_namesz = self.packer.unpack(stream.read(Elf64_Word))
        self.n_descsz = self.packer.unpack(stream.read(Elf64_Word))
        self.n_type = self.packer.unpack(stream.read(Elf64_Word))

        return self

    def serialize(self):
        data = ''

        data += self.packer.pack(self.n_namesz, Elf64_Word)
        data += self.packer.pack(self.n_descsz, Elf64_Word)
        data += self.packer.pack(self.n_type, Elf64_Word)

        return data


class Elf64_Phdr(object):

    def __init__(self, packer=None, p_type=0, p_flags=0, p_offset=0, p_vaddr=0, p_paddr=0,
                 p_filesz=0, p_memsz=0, p_align=0):
        self.packer = packer  # type: Packer
        self.p_type = p_type
        self.p_flags = p_flags
        self.p_offset = p_offset
        self.p_vaddr = p_vaddr
        self.p_paddr = p_paddr
        self.p_filesz = p_filesz
        self.p_memsz = p_memsz
        self.p_align = p_align

    def __str__(self):
        return ("Elf64_Phdr:\n" +
                ("\t%-16s: %#x\n" % ('p_type', self.p_type)) +
                ("\t%-16s: %#x\n" % ('p_flags', self.p_flags)) +
                ("\t%-16s: %#x\n" % ('p_offset', self.p_offset)) +
                ("\t%-16s: %#x\n" % ('p_vaddr', self.p_vaddr)) +
                ("\t%-16s: %#x\n" % ('p_paddr', self.p_paddr)) +
                ("\t%-16s: %#x\n" % ('p_filesz', self.p_filesz)) +
                ("\t%-16s: %#x\n" % ('p_memsz', self.p_memsz)) +
                ("\t%-16s: %#x\n" % ('p_align', self.p_align))
                )

    def parse(self, stream, offset, packer):
        self.packer = packer
        stream.seek(offset, 0)

        self.p_type = self.packer.unpack(stream.read(Elf64_Word))
        self.p_flags = self.packer.unpack(stream.read(Elf64_Word))
        self.p_offset = self.packer.unpack(stream.read(Elf64_Off))
        self.p_vaddr = self.packer.unpack(stream.read(Elf64_Addr))
        self.p_paddr = self.packer.unpack(stream.read(Elf64_Addr))
        self.p_filesz = self.packer.unpack(stream.read(Elf64_Xword))
        self.p_memsz = self.packer.unpack(stream.read(Elf64_Xword))
        self.p_align = self.packer.unpack(stream.read(Elf64_Xword))

        return self

    def serialize(self):
        data = ''

        data += self.packer.pack(self.p_type, Elf64_Word)
        data += self.packer.pack(self.p_flags, Elf64_Word)
        data += self.packer.pack(self.p_offset, Elf64_Off)
        data += self.packer.pack(self.p_vaddr, Elf64_Addr)
        data += self.packer.pack(self.p_paddr, Elf64_Addr)
        data += self.packer.pack(self.p_filesz, Elf64_Xword)
        data += self.packer.pack(self.p_memsz, Elf64_Xword)
        data += self.packer.pack(self.p_align, Elf64_Xword)

        return data


class Elf64_Rel(object):

    def __init__(self, packer=None, r_offset=0, **kwargs):
        self.packer = packer  # type: Packer
        self.r_offset = r_offset
        self.r_info = Elf64_Rel_R_Info(packer=packer, **kwargs)

    def __str__(self):
        return ("Elf64_Rel:\n" +
                ("\t%-16s: %#x\n" % ('r_offset', self.r_offset)) +
                ("\t%-16s: \n%s\n" % ('r_info', str(self.r_info)))
                )

    def parse(self, stream, offset, packer):
        self.packer = packer
        stream.seek(offset, 0)

        self.r_offset = self.packer.unpack(stream.read(Elf64_Addr))
        self.r_info = Elf64_Rel_R_Info().parse(stream, stream.tell(), packer)

        return self

    def serialize(self):
        data = ''

        data += self.packer.pack(self.r_offset, Elf64_Addr)
        data += self.r_info.serialize()

        return data


class Elf64_Rela(object):

    def __init__(self, packer=None, r_offset=0, r_addend=0, **kwargs):
        self.packer = packer  # type: Packer
        self.r_offset = r_offset
        self.r_info = Elf64_Rel_R_Info(packer=packer, **kwargs)
        self.r_addend = r_addend

    def __str__(self):
        return ("Elf64_Rela:\n" +
                ("\t%-16s: %#x\n" % ('r_offset', self.r_offset)) +
                ("\t%-16s: \n%s\n" % ('r_info', str(self.r_info))) +
                ("\t%-16s: %#x\n" % ('r_addend', self.r_addend))
                )

    def parse(self, stream, offset, packer):
        self.packer = packer
        stream.seek(offset, 0)

        self.r_offset = self.packer.unpack(stream.read(Elf64_Addr))
        self.r_info = Elf64_Rel_R_Info().parse(stream, stream.tell(), packer)
        self.r_addend = self.packer.unpack(stream.read(Elf64_Sxword))

        return self

    def serialize(self):
        data = ''

        data += self.packer.pack(self.r_offset, Elf64_Addr)
        data += self.r_info.serialize()
        data += self.packer.pack(self.r_addend, Elf64_Sxword)

        return data


class Elf64_Rel_R_Info(object):

    def __init__(self, packer=None, r_sym=0, r_type=0):
        self.packer = packer  # type: Packer
        self.r_sym = r_sym
        self.r_type = r_type

    def __str__(self):
        return ("Elf64_Rel_R_Info:\n" +
                ("\t%-16s: %#x\n" % ('r_sym', self.r_sym)) +
                ("\t%-16s: %#x\n" % ('r_type', self.r_type))
                )

    def parse(self, stream, offset, packer):
        self.packer = packer
        stream.seek(offset, 0)

        r_info = self.packer.unpack(stream.read(Elf64_Xword))
        self.r_sym = r_info >> 32
        self.r_type = r_info & (2 ** 32 - 1)

        return self

    def serialize(self):
        data = ''

        r_info = (self.r_sym << 32) | self.r_type
        data += self.packer.pack(r_info, Elf64_Xword)

        return data


class Elf64_Shdr(object):

    def __init__(self, packer=None, sh_name=0, sh_type=0, sh_flags=0, sh_addr=0,
                 sh_offset=0, sh_size=0, sh_link=0, sh_info=0,
                 sh_addralign=0, sh_entsize=0, data=''):
        self.packer = packer  # type: Packer
        self.sh_name = sh_name
        self.sh_type = sh_type
        self.sh_flags = sh_flags
        self.sh_addr = sh_addr
        self.sh_offset = sh_offset
        self.sh_size = 0 if sh_type == SHT_NOBITS else sh_size
        self.sh_link = sh_link
        self.sh_info = sh_info
        self.sh_addralign = sh_addralign
        self.sh_entsize = sh_entsize
        self.sh_size_dummy = sh_size
        self.data = data

    def __str__(self):
        return ("Elf64_Shdr:\n" +
                ("\t%-16s: %#x\n" % ('sh_name', self.sh_name)) +
                ("\t%-16s: %#x\n" % ('sh_type', self.sh_type)) +
                ("\t%-16s: %#x\n" % ('sh_flags', self.sh_flags)) +
                ("\t%-16s: %#x\n" % ('sh_addr', self.sh_addr)) +
                ("\t%-16s: %#x\n" % ('sh_offset', self.sh_offset)) +
                ("\t%-16s: %#x\n" % ('sh_size', self.sh_size)) +
                ("\t%-16s: %#x\n" % ('sh_link', self.sh_link)) +
                ("\t%-16s: %#x\n" % ('sh_info', self.sh_info)) +
                ("\t%-16s: %#x\n" % ('sh_addralign', self.sh_addralign)) +
                ("\t%-16s: %#x\n" % ('sh_entsize', self.sh_entsize))
                )

    def parse(self, stream, offset, packer):
        self.packer = packer
        stream.seek(offset, 0)

        self.sh_name = self.packer.unpack(stream.read(Elf64_Word))
        self.sh_type = self.packer.unpack(stream.read(Elf64_Word))
        self.sh_flags = self.packer.unpack(stream.read(Elf64_Xword))
        self.sh_addr = self.packer.unpack(stream.read(Elf64_Addr))
        self.sh_offset = self.packer.unpack(stream.read(Elf64_Off))
        self.sh_size = self.packer.unpack(stream.read(Elf64_Xword))
        self.sh_size_dummy = self.sh_size
        self.sh_link = self.packer.unpack(stream.read(Elf64_Word))
        self.sh_info = self.packer.unpack(stream.read(Elf64_Word))
        self.sh_addralign = self.packer.unpack(stream.read(Elf64_Xword))
        self.sh_entsize = self.packer.unpack(stream.read(Elf64_Xword))

        # dummy size might present here
        if self.sh_type == SHT_NOBITS:
            self.sh_size = 0

        stream.seek(self.sh_offset, 0)
        self.data = stream.read(self.sh_size)

        return self

    def serialize(self):
        data = ''

        data += self.packer.pack(self.sh_name, Elf64_Word)
        data += self.packer.pack(self.sh_type, Elf64_Word)
        data += self.packer.pack(self.sh_flags, Elf64_Xword)
        data += self.packer.pack(self.sh_addr, Elf64_Addr)
        data += self.packer.pack(self.sh_offset, Elf64_Off)
        size = self.sh_size_dummy if self.sh_type == SHT_NOBITS else self.sh_size
        data += self.packer.pack(size, Elf64_Xword)
        data += self.packer.pack(self.sh_link, Elf64_Word)
        data += self.packer.pack(self.sh_info, Elf64_Word)
        data += self.packer.pack(self.sh_addralign, Elf64_Xword)
        data += self.packer.pack(self.sh_entsize, Elf64_Xword)

        return data


class Elf64_Sym(object):

    def __init__(self, packer=None, st_name=0, st_visibility=0, st_shndx=0,
                 st_value=0, st_size=0, **kwargs):
        self.packer = packer  # type: Packer
        self.st_name = st_name
        self.st_info = Elf64_Sym_St_Info(packer=packer, **kwargs)
        self.st_other = Elf64_Sym_St_Other(packer=packer, st_visibility=st_visibility)
        self.st_shndx = st_shndx
        self.st_value = st_value
        self.st_size = st_size

    def __str__(self):
        return ("Elf64_Sym:\n" +
                ("\t%-16s: %#x\n" % ('st_name', self.st_name)) +
                ("\t%-16s: \n%s\n" % ('st_info', str(self.st_info))) +
                ("\t%-16s: \n%s\n" % ('st_other', str(self.st_other))) +
                ("\t%-16s: %#x\n" % ('st_shndx', self.st_shndx)) +
                ("\t%-16s: %#x\n" % ('st_value', self.st_value)) +
                ("\t%-16s: %#x\n" % ('st_size', self.st_size))
                )

    def parse(self, stream, offset, packer):
        self.packer = packer
        stream.seek(offset, 0)

        self.st_name = self.packer.unpack(stream.read(Elf64_Word))
        self.st_info = Elf64_Sym_St_Info().parse(stream, stream.tell(), packer)
        self.st_other = Elf64_Sym_St_Other().parse(stream, stream.tell(), packer)
        self.st_shndx = self.packer.unpack(stream.read(Elf64_Half))
        self.st_value = self.packer.unpack(stream.read(Elf64_Addr))
        self.st_size = self.packer.unpack(stream.read(Elf64_Xword))

        return self

    def serialize(self):
        data = ''

        data += self.packer.pack(self.st_name, Elf64_Word)
        data += self.st_info.serialize()
        data += self.st_other.serialize()
        data += self.packer.pack(self.st_shndx, Elf64_Half)
        data += self.packer.pack(self.st_value, Elf64_Addr)
        data += self.packer.pack(self.st_size, Elf64_Xword)

        return data


class Elf64_Sym_St_Info(object):

    def __init__(self, packer=None, st_bind=0, st_type=0):
        self.packer = packer  # type: Packer
        self.st_bind = st_bind
        self.st_type = st_type

    def __str__(self):
        return ("Elf64_Sym_St_Info:\n" +
                ("\t%-16s: %#x\n" % ('st_bind', self.st_bind)) +
                ("\t%-16s: %#x\n" % ('st_type', self.st_type))
                )

    def parse(self, stream, offset, packer):
        self.packer = packer
        stream.seek(offset, 0)

        st_info = self.packer.unpack(stream.read(Elf64_Char))
        self.st_bind = st_info >> 4
        self.st_type = st_info & 0xf

        return self

    def serialize(self):
        data = ''

        st_info = (self.st_bind << 4) | self.st_type
        data += self.packer.pack(st_info, Elf64_Char)

        return data


class Elf64_Sym_St_Other(object):

    def __init__(self, packer=None, st_visibility=0):
        self.packer = packer  # type: Packer
        self.st_visibility = st_visibility

    def __str__(self):
        return ("Elf64_Sym_St_Other:\n" +
                ("\t%-16s: %#x\n" % ('st_visibility', self.st_visibility))
                )

    def parse(self, stream, offset, packer):
        self.packer = packer
        stream.seek(offset, 0)

        st_other = self.packer.unpack(stream.read(Elf64_Char))
        self.st_visibility = st_other & 0x3

        return self

    def serialize(self):
        data = ''

        st_other = self.st_visibility
        data += self.packer.pack(st_other, Elf64_Char)

        return data


class Elf64_Syminfo(object):

    def __init__(self, packer=None, si_boundto=0, si_flags=0):
        self.packer = packer  # type: Packer
        self.si_boundto = si_boundto
        self.si_flags = si_flags

    def __str__(self):
        return ("Elf64_Syminfo:\n" +
                ("\t%-16s: %#x\n" % ('si_boundto', self.si_boundto)) +
                ("\t%-16s: %#x\n" % ('si_flags', self.si_flags))
                )

    def parse(self, stream, offset, packer):
        self.packer = packer
        stream.seek(offset, 0)

        self.si_boundto = self.packer.unpack(stream.read(Elf64_Half))
        self.si_flags = self.packer.unpack(stream.read(Elf64_Half))

        return self

    def serialize(self):
        data = ''

        data += self.packer.pack(self.si_boundto, Elf64_Half)
        data += self.packer.pack(self.si_flags, Elf64_Half)

        return data


class Elf64_Verdaux(object):

    def __init__(self, packer=None, vda_name=0, vda_next=0):
        self.packer = packer  # type: Packer
        self.vda_name = vda_name
        self.vda_next = vda_next

    def __str__(self):
        return ("Elf64_Verdaux:\n" +
                ("\t%-16s: %#x\n" % ('vda_name', self.vda_name)) +
                ("\t%-16s: %#x\n" % ('vda_next', self.vda_next))
                )

    def parse(self, stream, offset, packer):
        self.packer = packer
        stream.seek(offset, 0)

        self.vda_name = self.packer.unpack(stream.read(Elf64_Word))
        self.vda_next = self.packer.unpack(stream.read(Elf64_Word))

        return self

    def serialize(self):
        data = ''

        data += self.packer.pack(self.vda_name, Elf64_Word)
        data += self.packer.pack(self.vda_next, Elf64_Word)

        return data


class Elf64_Verdef(object):

    def __init__(self, packer=None, vd_version=0, vd_flags=0, vd_ndx=0, vd_cnt=0,
                 vd_hash=0, vd_aux=0, vd_next=0):
        self.packer = packer  # type: Packer
        self.vd_version = vd_version
        self.vd_flags = vd_flags
        self.vd_ndx = vd_ndx
        self.vd_cnt = vd_cnt
        self.vd_hash = vd_hash
        self.vd_aux = vd_aux
        self.vd_next = vd_next

    def __str__(self):
        return ("Elf64_Verdef:\n" +
                ("\t%-16s: %#x\n" % ('vd_version', self.vd_version)) +
                ("\t%-16s: %#x\n" % ('vd_flags', self.vd_flags)) +
                ("\t%-16s: %#x\n" % ('vd_ndx', self.vd_ndx)) +
                ("\t%-16s: %#x\n" % ('vd_cnt', self.vd_cnt)) +
                ("\t%-16s: %#x\n" % ('vd_hash', self.vd_hash)) +
                ("\t%-16s: %#x\n" % ('vd_aux', self.vd_aux)) +
                ("\t%-16s: %#x\n" % ('vd_next', self.vd_next))
                )

    def parse(self, stream, offset, packer):
        self.packer = packer
        stream.seek(offset, 0)

        self.vd_version = self.packer.unpack(stream.read(Elf64_Half))
        self.vd_flags = self.packer.unpack(stream.read(Elf64_Half))
        self.vd_ndx = self.packer.unpack(stream.read(Elf64_Half))
        self.vd_cnt = self.packer.unpack(stream.read(Elf64_Half))
        self.vd_hash = self.packer.unpack(stream.read(Elf64_Word))
        self.vd_aux = self.packer.unpack(stream.read(Elf64_Word))
        self.vd_next = self.packer.unpack(stream.read(Elf64_Word))

        return self

    def serialize(self):
        data = ''

        data += self.packer.pack(self.vd_version, Elf64_Half)
        data += self.packer.pack(self.vd_flags, Elf64_Half)
        data += self.packer.pack(self.vd_ndx, Elf64_Half)
        data += self.packer.pack(self.vd_cnt, Elf64_Half)
        data += self.packer.pack(self.vd_hash, Elf64_Word)
        data += self.packer.pack(self.vd_aux, Elf64_Word)
        data += self.packer.pack(self.vd_next, Elf64_Word)

        return data


class Elf64_Vernaux(object):

    def __init__(self, packer=None, vna_hash=0, vna_flags=0, vna_other=0, vna_name=0,
                 vna_next=0):
        self.packer = packer  # type: Packer
        self.vna_hash = vna_hash
        self.vna_flags = vna_flags
        self.vna_other = vna_other
        self.vna_name = vna_name
        self.vna_next = vna_next

    def __str__(self):
        return ("Elf64_Vernaux:\n" +
                ("\t%-16s: %#x\n" % ('vna_hash', self.vna_hash)) +
                ("\t%-16s: %#x\n" % ('vna_flags', self.vna_flags)) +
                ("\t%-16s: %#x\n" % ('vna_other', self.vna_other)) +
                ("\t%-16s: %#x\n" % ('vna_name', self.vna_name)) +
                ("\t%-16s: %#x\n" % ('vna_next', self.vna_next))
                )

    def parse(self, stream, offset, packer):
        self.packer = packer
        stream.seek(offset, 0)

        self.vna_hash = self.packer.unpack(stream.read(Elf64_Word))
        self.vna_flags = self.packer.unpack(stream.read(Elf64_Half))
        self.vna_other = self.packer.unpack(stream.read(Elf64_Half))
        self.vna_name = self.packer.unpack(stream.read(Elf64_Word))
        self.vna_next = self.packer.unpack(stream.read(Elf64_Word))

        return self

    def serialize(self):
        data = ''

        data += self.packer.pack(self.vna_hash, Elf64_Word)
        data += self.packer.pack(self.vna_flags, Elf64_Half)
        data += self.packer.pack(self.vna_other, Elf64_Half)
        data += self.packer.pack(self.vna_name, Elf64_Word)
        data += self.packer.pack(self.vna_next, Elf64_Word)

        return data


class Elf64_Verneed(object):

    def __init__(self, packer=None, vn_version=0, vn_cnt=0, vn_file=0, vn_aux=0, vn_next=0):
        self.packer = packer  # type: Packer
        self.vn_version = vn_version
        self.vn_cnt = vn_cnt
        self.vn_file = vn_file
        self.vn_aux = vn_aux
        self.vn_next = vn_next

    def __str__(self):
        return ("Elf64_Verneed:\n" +
                ("\t%-16s: %#x\n" % ('vn_version', self.vn_version)) +
                ("\t%-16s: %#x\n" % ('vn_cnt', self.vn_cnt)) +
                ("\t%-16s: %#x\n" % ('vn_file', self.vn_file)) +
                ("\t%-16s: %#x\n" % ('vn_aux', self.vn_aux)) +
                ("\t%-16s: %#x\n" % ('vn_next', self.vn_next))
                )

    def parse(self, stream, offset, packer):
        self.packer = packer
        stream.seek(offset, 0)

        self.vn_version = self.packer.unpack(stream.read(Elf64_Half))
        self.vn_cnt = self.packer.unpack(stream.read(Elf64_Half))
        self.vn_file = self.packer.unpack(stream.read(Elf64_Word))
        self.vn_aux = self.packer.unpack(stream.read(Elf64_Word))
        self.vn_next = self.packer.unpack(stream.read(Elf64_Word))

        return self

    def serialize(self):
        data = ''

        data += self.packer.pack(self.vn_version, Elf64_Half)
        data += self.packer.pack(self.vn_cnt, Elf64_Half)
        data += self.packer.pack(self.vn_file, Elf64_Word)
        data += self.packer.pack(self.vn_aux, Elf64_Word)
        data += self.packer.pack(self.vn_next, Elf64_Word)

        return data


class Elf64_E_Ident(object):

    def __init__(self, packer=None, ei_class=0, ei_data=0, ei_version=0,
                 ei_osabi=0, ei_abiversion=0):
        self.packer = packer  # type: Packer
        self.ei_magic = "\x7fELF"
        self.ei_class = ei_class
        self.ei_data = ei_data
        self.ei_version = ei_version
        self.ei_osabi = ei_osabi
        self.ei_abiversion = ei_abiversion
        self.ei_pad = "\x00" * SZ_EI_PAD

    def __str__(self):
        return ("Elf64_E_Ident:\n" +
                ("\t%-16s: %s\n" % ('ei_magic', self.ei_magic.encode('hex'))) +
                ("\t%-16s: %#x\n" % ('ei_class', self.ei_class)) +
                ("\t%-16s: %#x\n" % ('ei_data', self.ei_data)) +
                ("\t%-16s: %#x\n" % ('ei_version', self.ei_version)) +
                ("\t%-16s: %#x\n" % ('ei_osabi', self.ei_osabi)) +
                ("\t%-16s: %#x\n" % ('ei_abiversion', self.ei_abiversion)) +
                ("\t%-16s: %s\n" % ('ei_pad', self.ei_pad.encode('hex')))
                )

    def parse(self, stream, offset):
        self.packer = Packer(ELFDATA2LSB)   # this is fine for Elf64_Char
        stream.seek(offset, 0)

        self.ei_magic = stream.read(Elf64_Char * SZ_EI_MAGIC)
        assert(self.ei_magic == "\x7fELF")
        self.ei_class = self.packer.unpack(stream.read(Elf64_Char))
        self.ei_data = self.packer.unpack(stream.read(Elf64_Char))
        self.ei_version = self.packer.unpack(stream.read(Elf64_Char))
        self.ei_osabi = self.packer.unpack(stream.read(Elf64_Char))
        self.ei_abiversion = self.packer.unpack(stream.read(Elf64_Char))
        self.ei_pad = stream.read(Elf64_Char * SZ_EI_PAD)

        # update packer
        self.packer = Packer(self.ei_data)

        return self

    def serialize(self):
        data = ''

        data += self.ei_magic
        data += self.packer.pack(self.ei_class, Elf64_Char)
        data += self.packer.pack(self.ei_data, Elf64_Char)
        data += self.packer.pack(self.ei_version, Elf64_Char)
        data += self.packer.pack(self.ei_osabi, Elf64_Char)
        data += self.packer.pack(self.ei_abiversion, Elf64_Char)
        data += self.ei_pad

        return data


class Elf64_GNU_Hash(object):

    def __init__(self, packer=None, h_nbucket=0, h_symndx=0, h_maskwords=0, h_shift=0):
        self.packer = packer  # type: Packer
        self.h_nbucket = h_nbucket
        self.h_symndx = h_symndx
        self.h_maskwords = h_maskwords
        self.h_shift = h_shift
        self.h_bloom = []
        self.h_buckets = []
        self.h_chains = []

    def __str__(self):
        return ("Elf64_GNU_Hash:\n" +
                ("\t%-16s: %#x\n" % ('h_nbucket', self.h_nbucket)) +
                ("\t%-16s: %#x\n" % ('h_symndx', self.h_symndx)) +
                ("\t%-16s: %#x\n" % ('h_maskwords', self.h_maskwords)) +
                ("\t%-16s: %#x\n" % ('h_shift', self.h_shift)) +
                ("\t%-16s: %#x\n" % ('len(h_bloom)', len(self.h_bloom))) +
                ("\t%-16s: %#x\n" % ('len(h_buckets)', len(self.h_buckets))) +
                ("\t%-16s: %#x\n" % ('len(h_chains)', len(self.h_chains)))
                )

    def parse(self, stream, offset, size, packer, symcnt):
        self.packer = packer
        stream.seek(offset, 0)

        self.h_nbucket = self.packer.unpack(stream.read(Elf64_Word))
        self.h_symndx = self.packer.unpack(stream.read(Elf64_Word))
        self.h_maskwords = self.packer.unpack(stream.read(Elf64_Word))
        self.h_shift = self.packer.unpack(stream.read(Elf64_Word))
        self.h_bloom = [self.packer.unpack(stream.read(Elf64_Xword))
                        for _ in xrange(self.h_maskwords)]
        self.h_buckets = [self.packer.unpack(stream.read(Elf64_Word))
                          for _ in xrange(self.h_nbucket)]
        nchains = (size - (stream.tell() - offset)) / Elf64_Word
        self.h_chains = [self.packer.unpack(stream.read(Elf64_Word))
                         for _ in xrange(nchains)]

        # we have to fill in the blanks in order to add more chains in the future
        total_chains = symcnt - self.h_symndx
        self.h_chains += [STN_UNDEF] * (total_chains - len(self.h_chains))

        return self

    def serialize(self):
        data = ''

        data += self.packer.pack(self.h_nbucket, Elf64_Word)
        data += self.packer.pack(self.h_symndx, Elf64_Word)
        data += self.packer.pack(self.h_maskwords, Elf64_Word)
        data += self.packer.pack(self.h_shift, Elf64_Word)
        data += ''.join([self.packer.pack(_, Elf64_Xword) for _ in self.h_bloom])
        data += ''.join([self.packer.pack(_, Elf64_Word) for _ in self.h_buckets])
        data += ''.join([self.packer.pack(_, Elf64_Word) for _ in self.h_chains])

        return data


class Elf64_Hash(object):

    def __init__(self, packer=None, h_nbucket=0, h_nchain=0):
        self.packer = packer  # type: Packer
        self.h_nbucket = h_nbucket
        self.h_nchain = h_nchain
        self.h_buckets = [0] * h_nbucket
        self.h_chains = [0] * h_nchain

    def __str__(self):
        return ("Elf64_Hash:\n" +
                ("\t%-16s: %#x\n" % ('h_nbucket', self.h_nbucket)) +
                ("\t%-16s: %#x\n" % ('h_nchain', self.h_nchain))
                )

    def parse(self, stream, offset, packer):
        self.packer = packer
        stream.seek(offset, 0)

        self.h_nbucket = self.packer.unpack(stream.read(Elf64_Word))
        self.h_nchain = self.packer.unpack(stream.read(Elf64_Word))
        self.h_buckets = [self.packer.unpack(stream.read(Elf64_Word))
                          for _ in xrange(self.h_nbucket)]
        self.h_chains = [self.packer.unpack(stream.read(Elf64_Word))
                         for _ in xrange(self.h_nchain)]

        return self

    def serialize(self):
        data = ''

        data += self.packer.pack(self.h_nbucket, Elf64_Word)
        data += self.packer.pack(self.h_nchain, Elf64_Word)
        data += ''.join([self.packer.pack(_, Elf64_Word) for _ in self.h_buckets])
        data += ''.join([self.packer.pack(_, Elf64_Word) for _ in self.h_chains])

        return data
