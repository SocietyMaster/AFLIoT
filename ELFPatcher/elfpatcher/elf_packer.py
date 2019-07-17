#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Himyth / AAA """

from elf_structs32 import *
from elf_structs64 import *


# this is a dirty hack for dynamically generating classes, copying from
# https://stackoverflow.com/questions/21060073/dynamic-inheritance-in-python
# we have to do this since we need both different base classes and the
# functions we implemented here.

# dynamically generate Elf_Shdr class with string data optimized
def Elf_ShdrData(elf):
    Elf_Shdr = choose(elf, Elf32_Shdr, Elf64_Shdr)

    class Inner_Elf_ShdrData(Elf_Shdr):

        def __init__(self, **kwargs_inner):
            self.data = ''      # make pycharm happy

            super(Inner_Elf_ShdrData, self).__init__(**kwargs_inner)

            # internal structure for data, speed up string concatenation
            data = kwargs_inner['data'] if 'data' in kwargs_inner else ''
            self._data_str = data           # string storage of data
            self._data_list = [data]        # list storage of data pieces
            self._data_up_to_date = True    # if _data_str equals to _data_list

        # update _data_str if not up-to-date, and return string
        @property
        def data(self):
            if not self._data_up_to_date:
                self._data_str = ''.join(self._data_list)
                self._data_up_to_date = True
            return self._data_str

        # update both _data_str and _data_list
        @data.setter
        def data(self, newdata):
            self._data_str = newdata
            self._data_list = [newdata]
            self._data_up_to_date = True

        # store new piece in _data_list fisrt, unset up-to-date
        def append_data(self, data):
            self._data_list.append(data)
            self._data_up_to_date = False

        def update_data(self, offset, data):
            self.data = self.data[:offset] + data + self.data[offset + len(data):]

        def update_data_many(self, updates):
            """
            update many pieces once to speed up string concatenation, join all pieces,
            and fill gap with original data, should be faster than concat one by one.

            :param updates: [(offset, data)]
            :return:        True
            """
            # sort updates by offset
            updates.sort(key=lambda x: x[0])

            updated = []
            cur_offset = 0
            for offset, data in updates:

                # gap between 2 adjacent updates, fill with original data
                if offset > cur_offset:
                    updated.append(self.data[cur_offset:offset])

                # append current update
                updated.append(data)
                cur_offset = offset + len(data)

            # copy the tail if any
            if cur_offset < len(self.data):
                updated.append(self.data[cur_offset:])

            # join all pieces to get updated data
            self.data = ''.join(updated)
            return True

    return Inner_Elf_ShdrData


def ElfPatch_Shdr(elf, **kwargs):
    Elf_Shdr = Elf_ShdrData(elf)

    class Inner_ElfPatch_Shdr(Elf_Shdr):

        def __init__(self, permtype, **kwargs_inner):
            self.sh_addralign = 0   # make pycharm happy here

            super(Inner_ElfPatch_Shdr, self).__init__(**kwargs_inner)

            # we use Recorder here just for laying out all the items, so we dont care
            # the segmentation it constructs. but we should care about how many bytes
            # reside in this section, which is vital for future section layout.
            #
            # therefore, we set recorder's (vaddr/offset) both to zero. firstly, it will
            # not affected by future alignment operation. secondly, it equals to the
            # length of our data, which is an empty string now. for any data coming, we
            # can easily tell how many alignment we should put here.
            self.recorder = Recorder(0, 0, 0, self.packer)
            self.datalen = 0
            self.permtype = permtype    # we only use 1 type here
            self.items = dict()         # label: (offset, length)

        def add(self, label, data, align=0):
            if self.recorder.is_finalized():
                return False

            if label in self.items:
                return False

            # record datalen manually to avoid accessing self.data, which will interrupt
            # the optimization Elf_ShdrData make speeding up string concatenation.
            prevlen = self.datalen
            curaddr = alignment(prevlen, align)
            curlen = len(data)
            self.datalen = curaddr + curlen

            # add to items, offset is aligned existing data length
            self.items[label] = (curaddr, curlen)

            # pad and append the new data, optimized
            self.append_data((curaddr - prevlen) * '\x00' + data)

            # add item to recorder
            self.recorder.add(label=label, size=curlen, align=align, _type=self.permtype)

            # this is the first item we've added, we should set section alignment to the LCM
            # of the original alignment and the alignment of the first object, which will
            # guarantee a perfect alignment for all items in this section.
            if len(self.recorder.resolved) == 1:
                self.sh_addralign = merge_alignment(self.sh_addralign, align)

            return True

        def update(self, label, data):
            """
            update data with same length

            :param label:   label for data
            :param data:    new data
            :return:        True or False
            """
            # existing label with same length
            if label not in self.items or len(data) != self.items[label][1]:
                return False

            # do update self.data
            self.update_data(self.items[label][0], data)
            return True

        def update_many(self, updates):
            """
            update a list of (label, data), avoid using self.update_data() every time,
            which can be quite slow.

            :param updates: [(label, data), ...]
            :return:        number of succeed updates
            """
            updates_valid = []
            for label, data in updates:
                if label not in self.items or len(data) != self.items[label][1]:
                    continue
                updates_valid.append((self.items[label][0], data))

            self.update_data_many(updates_valid)
            return len(updates_valid)

        def finalize(self):
            if self.recorder.is_finalized():
                return False

            # assume we have finalized the section itself
            self.recorder.rebase(self.sh_offset, self.sh_addr)
            self.recorder.finalize()

        def get(self, label):
            if not self.recorder.is_finalized():
                return None

            record = self.recorder.get(label)
            return None if record is None else record[1]    # we dont care offset

        def fetch_all(self):
            if not self.recorder.is_finalized():
                return None

            return self.recorder.fetch_all_vaddr()

    return Inner_ElfPatch_Shdr(packer=elf.packer, **kwargs)


# nothing but a packer to choose architecture
class ElfPack_Ehdr(object):

    def parse(self, stream, offset):
        attempt = Elf32_Ehdr().parse(stream, offset)
        if attempt.e_ident.ei_class == ELFCLASS32:
            return attempt
        if attempt.e_ident.ei_class != ELFCLASS64:
            raise ValueError("ELF class type should be either 32 or 64")
        return Elf64_Ehdr().parse(stream, offset)


class ElfPack_GNU_Version(object):

    def __init__(self):
        self.shdr = None  # type: Elf32_Shdr or Elf64_Shdr
        self.versyms = None  # type: [int]
        self.verneeds = None
        self.strtab = None  # type: ElfPack_StrTab
        self.packer = None  # type: Packer
        self.Elf_Verneed = None
        self.Elf_Vernaux = None
        self.Elf_Half = None

    def parse(self, stream, elf):
        self.packer = elf.packer
        self.strtab = elf.strtab

        self.Elf_Verneed = choose(elf, Elf32_Verneed, Elf64_Verneed)
        self.Elf_Vernaux = choose(elf, Elf32_Vernaux, Elf64_Vernaux)
        self.Elf_Half = choose(elf, Elf32_Half, Elf64_Half)

        if not elf.shdr.find_by_type(SHT_GNU_VERSYM):
            return None
        self.shdr = elf.shdr.find_by_type(SHT_GNU_VERSYM)[0]

        self.versyms = list()
        for i in xrange(self.shdr.sh_size / self.shdr.sh_entsize):
            offset = self.shdr.sh_offset + self.shdr.sh_entsize * i
            stream.seek(offset, 0)
            self.versyms.append(self.packer.unpack(stream.read(self.Elf_Half)))

        self.verneeds = dict()
        if not elf.shdr.find_by_type(SHT_GNU_VERNEED):
            return self

        # parse verneed and vernaux array
        verneed_shdr = elf.shdr.find_by_type(SHT_GNU_VERNEED)[0]
        curoffset = verneed_shdr.sh_offset
        while True:
            verneed = self.Elf_Verneed().parse(stream, curoffset, self.packer)
            self.verneeds[verneed] = list()
            nextoffset = curoffset + verneed.vn_next
            curoffset += verneed.vn_aux
            for i in xrange(verneed.vn_cnt):
                vernaux = self.Elf_Vernaux().parse(stream, curoffset, self.packer)
                self.verneeds[verneed].append(vernaux)
                curoffset += vernaux.vna_next
            if verneed.vn_next == 0:
                break
            curoffset = nextoffset

        return self

    def serialize(self):
        return ''.join(map(lambda x: self.packer.pack(x, self.Elf_Half), self.versyms))

    def add(self, versym):
        self.versyms.append(versym)
        self.shdr.data = self.serialize()

    # return lowest version for target library, if we can find it.
    # otherwise just return *GLOBAL*, emmmm, lets hope it will work.
    def find_version(self, libfile):
        for verneed in self.verneeds:
            if self.strtab.get(verneed.vn_file, STRTAB_SYM) == libfile:
                break
        else:
            return 1        # *GLOBAL*

        choices = []
        for vernaux in self.verneeds[verneed]:
            choices.append((vernaux.vna_other,
                            self.strtab.get(vernaux.vna_name, STRTAB_SYM)))
        choices.sort(key=lambda x: x[1])    # sort by version string
        return choices[0][0]    # return version


class ElfPack_Rel(object):

    def __init__(self):
        self.rels = None  # type: [Elf32_Rel or Elf64_Rel]
        self.shdr = None  # type: Elf32_Shdr or Elf64_Shdr
        self.nrels = dict()  # type: {str: Elf32_Rel or Elf64_Rel}
        self.packer = None  # type: Packer
        self.Elf_Rel = None
        self.Elf_Addr = None
        self.R_GLOB_DAT = None
        self.R_TPOFF = None
        self.R_RELATIVE = None
        self.DT_COUNT = None
        self.elf = None

    def __str__(self):
        return '\n'.join(map(lambda x: str(x), self.rels))

    def __len__(self):
        return len(self.rels)

    def parse(self, stream, elf):
        self.packer = elf.packer
        self.elf = elf

        r_glob_dats = {EM_386: R_386_GLOB_DAT,
                       EM_ARM: R_ARM_GLOB_DAT,
                       EM_X86_64: R_X86_64_GLOB_DAT}
        self.R_GLOB_DAT = r_glob_dats[elf.ehdr.e_machine]

        r_tpoffs = {EM_386: R_386_TLS_TPOFF32,
                    EM_ARM: R_ARM_TLS_TPOFF32,
                    EM_X86_64: R_X86_64_TPOFF64}
        self.R_TPOFF = r_tpoffs[elf.ehdr.e_machine]

        r_relatives = {EM_386: R_386_RELATIVE,
                       EM_ARM: R_ARM_RELATIVE,
                       EM_X86_64: R_X86_64_RELATIVE}
        self.R_RELATIVE = r_relatives[elf.ehdr.e_machine]

        self.Elf_Addr = choose(elf, Elf32_Addr, Elf64_Addr)

        # should be one of the rel and the rela sections
        if elf.shdr.find_by_name('.rel.dyn'):
            self.shdr = elf.shdr.find_by_name('.rel.dyn')[0]
            self.Elf_Rel = choose(elf, Elf32_Rel, Elf64_Rel)
            self.DT_COUNT = DT_RELCOUNT

        # if rel can not be found, try rela
        elif elf.shdr.find_by_name('.rela.dyn'):
            self.shdr = elf.shdr.find_by_name('.rela.dyn')[0]
            self.Elf_Rel = choose(elf, Elf32_Rela, Elf64_Rela)
            self.DT_COUNT = DT_RELACOUNT

        # if neither rel nor rela is found, we shall add a .rel section ourselves
        else:
            self.Elf_Rel = choose(elf, Elf32_Rel, Elf64_Rel)
            self.DT_COUNT = DT_RELCOUNT

            Elf_Shdr = choose(elf, Elf32_Shdr, Elf64_Shdr)
            rel_entsize = choose(elf, SZ_ELF32_REL_ENT, SZ_ELF64_REL_ENT)
            sh_name = elf.strtab.add('.rel.dyn', STRTAB_SH)
            sh_link = elf.shdr.index(elf.shdr.find_by_type(SHT_DYNSYM)[0])

            self.shdr = Elf_Shdr(packer=self.packer,
                                 sh_name=sh_name,
                                 sh_type=SHT_REL,
                                 sh_flags=SHF_ALLOC,
                                 sh_link=sh_link,
                                 sh_addralign=ALIGN_DATA,
                                 sh_entsize=rel_entsize)
            elf.shdr.add(self.shdr)

            # add corresponding dynamic entries, value will be updated during saving
            elf.dynamic.add(DT_REL, 0)
            elf.dynamic.add(DT_RELSZ, 0)
            elf.dynamic.add(DT_RELENT, rel_entsize)

        self.rels = []
        for i in xrange(self.shdr.sh_size / self.shdr.sh_entsize):
            offset = self.shdr.sh_offset + self.shdr.sh_entsize * i
            self.rels.append(self.Elf_Rel().parse(stream, offset, self.packer))
        return self

    def serialize(self):
        return ''.join(map(lambda x: x.serialize(), self.rels))

    def add(self, label, **kwargs):
        if label in self.nrels:
            return
        self.nrels[label] = self.Elf_Rel(packer=self.packer, **kwargs)
        self.rels.append(self.nrels[label])

        # we have to update data everytime, since section finalizes before
        # we do, and it needs our size as a hint
        self.shdr.data = self.serialize()

    def add_global_symbol(self, **kwargs):
        self.add(r_type=self.R_GLOB_DAT, **kwargs)

    def add_tls_offset(self, **kwargs):
        self.add(r_type=self.R_TPOFF, **kwargs)

    def add_relative(self, **kwargs):
        self.add(r_type=self.R_RELATIVE, **kwargs)
        self.update_count()

    # way too slow to add relatives one by one, so pack them up
    def add_relative_many(self, labels):
        for label in labels:
            if label in self.nrels:
                continue
            self.nrels[label] = self.Elf_Rel(packer=self.packer, r_type=self.R_RELATIVE)
            self.rels.append(self.nrels[label])

        self.shdr.data = self.serialize()
        self.update_count()

    # offset should be the `offset` of relocation, not the value within `offset`
    def remove(self, offset):
        self.rels = [rel for rel in self.rels if rel.r_offset != offset]
        self.nrels = {label: rel for label, rel in self.nrels.iteritems() if rel.r_offset != offset}
        self.shdr.data = self.serialize()
        self.update_count()

    # update rel(a)count in .dynamics
    def update_count(self):
        count = len([0 for rel in self.rels if rel.r_info.r_type == self.R_RELATIVE])

        if self.elf.dynamic.find_by_type(self.DT_COUNT):
            self.elf.dynamic.update(self.DT_COUNT, count)
        elif count != 0:
            self.elf.dynamic.add(self.DT_COUNT, count)

    def finalize(self, finder):

        # update r_offset of label-related relocation
        for label in self.nrels:
            self.nrels[label].r_offset = finder(label)

        # update r_addend of rela R_RELATIVE relocation
        if self.DT_COUNT == DT_RELACOUNT:
            for rel in self.rels:
                if rel.r_info.r_type == self.R_RELATIVE:
                    rel.r_addend = self.elf.peek_data(rel.r_offset, self.Elf_Addr)

        # i found no documentation saying that R_RELATIVE should preceding other
        # types of relocation, but the result is anything in front or in the middle
        # of R_RELATIVEs mishaved. so we sort R_RELATIVE in the front here.
        sorted_rels = []
        for rel in self.rels:
            if rel.r_info.r_type == self.R_RELATIVE:
                sorted_rels.append(rel)
        for rel in self.rels:
            if rel.r_info.r_type != self.R_RELATIVE:
                sorted_rels.append(rel)
        self.rels = sorted_rels

        self.shdr.data = self.serialize()


class ElfPack_Sym(object):

    def __init__(self):
        self.dynsyms = None  # type: [Elf32_Sym or Elf64_Sym]
        self.shdr = None  # type: Elf32_Shdr or Elf64_Shdr
        self.packer = None  # type: Packer
        self.Elf_Sym = None

    def __str__(self):
        return '\n'.join(map(lambda x: str(x), self.dynsyms))

    def __len__(self):
        return len(self.dynsyms)

    def parse(self, stream, elf):
        self.packer = elf.packer
        self.Elf_Sym = choose(elf, Elf32_Sym, Elf64_Sym)
        self.shdr = elf.shdr.find_by_type(SHT_DYNSYM)[0]

        self.dynsyms = []
        for i in xrange(self.shdr.sh_size / self.shdr.sh_entsize):
            offset = self.shdr.sh_offset + self.shdr.sh_entsize * i
            self.dynsyms.append(self.Elf_Sym().parse(stream, offset, self.packer))
        return self

    def serialize(self):
        return ''.join(map(lambda x: x.serialize(), self.dynsyms))

    def add(self, **kwargs):
        self.dynsyms.append(self.Elf_Sym(**kwargs))
        self.shdr.data = self.serialize()
        return len(self.dynsyms) - 1


class ElfPack_Dyn(object):

    def __init__(self):
        self.dynamics = None  # type: [Elf32_Dyn or Elf64_Dyn]
        self.shdr = None  # type: Elf32_Shdr or Elf64_Shdr
        self.packer = None  # type: Packer
        self.Elf_Dyn = None

    def __str__(self):
        return '\n'.join(map(lambda x: str(x), self.dynamics))

    def __len__(self):
        return len(self.dynamics)

    def parse(self, stream, elf):
        self.packer = elf.packer
        self.Elf_Dyn = choose(elf, Elf32_Dyn, Elf64_Dyn)
        self.shdr = elf.shdr.find_by_type(SHT_DYNAMIC)[0]

        self.dynamics = [self.Elf_Dyn().parse(stream, self.shdr.sh_offset, self.packer)]
        while self.dynamics[-1].d_tag != DT_NULL:
            offset = self.shdr.sh_offset + len(self.dynamics) * self.shdr.sh_entsize
            self.dynamics.append(self.Elf_Dyn().parse(stream, offset, self.packer))

        # there might be extra DT_NULL entries in the back, update the shdr.data
        self.shdr.data = self.serialize()
        return self

    def serialize(self):
        return ''.join(map(lambda x: x.serialize(), self.dynamics))

    def update(self, _type, value):
        if _type is None:
            return
        for dyn in filter(lambda x: x.d_tag == _type, self.dynamics):
            dyn.d_val = value
        self.shdr.data = self.serialize()

    def find_by_type(self, _type):
        return filter(lambda x: x.d_tag == _type, self.dynamics)

    # add an entry to .dynamic, default offset will insert new entry in front of
    # the last DT_NULL entry.
    def add(self, _type, value, offset=-1):
        self.dynamics.insert(offset, self.Elf_Dyn(self.packer, _type, value))
        self.shdr.data = self.serialize()


class ElfPack_Shdr(object):

    def __init__(self):
        self.shdrs = None  # type: [Elf32_Shdr or Elf64_Shdr]
        self.strtab = None  # type: ElfPack_StrTab
        self.packer = None  # type: Packer
        self.Elf_Shdr = None

    def __str__(self):
        return '\n'.join(map(lambda x: str(x), self.shdrs))

    def __len__(self):
        return len(self.shdrs)

    def parse(self, stream, elf):
        self.packer = elf.packer
        self.Elf_Shdr = Elf_ShdrData(elf)

        self.shdrs = []
        for i in xrange(elf.ehdr.e_shnum):
            offset = elf.ehdr.e_shoff + i * elf.ehdr.e_shentsize
            self.shdrs.append(self.Elf_Shdr().parse(stream, offset, self.packer))
        return self

    def serialize(self):
        return ''.join(map(lambda x: x.serialize(), self.shdrs))

    def serialize_data(self):
        for shdr in self.shdrs:
            yield shdr.sh_offset, shdr.data

    def add(self, shdr):
        self.shdrs.append(shdr)

    def set_strtab(self, strtab):
        self.strtab = strtab

    def find_by_type(self, _type):
        return filter(lambda x: x.sh_type == _type, self.shdrs)

    def find_by_perm(self, perm, exact=False):
        if exact:
            return filter(lambda x: x.sh_flags == perm, self.shdrs)
        return filter(lambda x: x.sh_flags & perm == perm, self.shdrs)

    def find_by_index(self, index):
        if 0 < index < len(self.shdrs):
            return self.shdrs[index]
        return None

    def find_by_name(self, name):
        if not self.strtab:
            return None
        return filter(lambda x: (self.strtab.get(x.sh_name, STRTAB_SH) == name), self.shdrs)

    def index(self, shdr):
        if shdr in self.shdrs:
            return self.shdrs.index(shdr)
        return -1


class ElfPack_Phdr(object):

    def __init__(self):
        self.phdrs = None  # type: [Elf32_Phdr or Elf64_Phdr]
        self.phdr = None  # type: Elf32_Phdr or Elf64_Phdr
        self.phentsize = 0
        self.recorder = None  # type: Recorder
        self.packer = None  # type: Packer
        self.Elf_Phdr = None

    def __str__(self):
        return '\n'.join(map(lambda x: str(x), self.phdrs))

    def __len__(self):
        return len(self.phdrs)

    def parse(self, stream, elf):
        self.packer = elf.packer
        self.Elf_Phdr = choose(elf, Elf32_Phdr, Elf64_Phdr)

        self.phdrs = []
        for i in xrange(elf.ehdr.e_phnum):
            offset = elf.ehdr.e_phoff + i * elf.ehdr.e_phentsize
            self.phdrs.append(self.Elf_Phdr().parse(stream, offset, self.packer))

        if filter(lambda x: x.p_type == PT_PHDR, self.phdrs):
            self.phdr = filter(lambda x: x.p_type == PT_PHDR, self.phdrs)[0]
        self.phentsize = elf.ehdr.e_phentsize

        # setup Recorder to where we can put data in memory and the file.
        #
        # we used to reserve some space behind the end-of-file for incoming section
        # headers, but that basically rely on a hypothesis that section headers reside
        # at the end of the file. this is true for binaries i tested before, but
        # failed on uclibc-gcc compiled binaries, which puts section headers between
        # some sections, totally different from the elf specification.
        #
        # anyway, to support such binary, we will no longer reserve spaces here, in-
        # stead, lets move the section headers to the end as well.
        stream.seek(0, 2)
        filesz = stream.tell()
        page_align = vaddr = 0
        for phdr in filter(lambda x: x.p_type == PT_LOAD, self.phdrs):
            vaddr = max([vaddr, alignment(phdr.p_vaddr + phdr.p_memsz, phdr.p_align)])
            page_align = phdr.p_align
        vaddr += filesz & (page_align - 1)      # congruent to offset, modulo page_align

        self.recorder = Recorder(filesz, vaddr, page_align, self.packer)
        return self

    def serialize(self):

        # update PT_PHDR in program header table if it presents
        if self.phdr:
            phdrs_size = len(self.phdrs) * self.phentsize
            self.phdr.p_filesz = phdrs_size
            self.phdr.p_memsz = phdrs_size

        return ''.join(map(lambda x: x.serialize(), self.phdrs))

    def add(self, phdr):
        self.phdrs.append(phdr)

    def update(self, _type, offset, vaddr, size):
        if _type is None:
            return
        for phdr in filter(lambda x: x.p_type == _type, self.phdrs):
            phdr.p_offset = offset
            phdr.p_vaddr = phdr.p_paddr = vaddr
            phdr.p_filesz = phdr.p_memsz = size

    def get(self, _type):
        return filter(lambda x: x.p_type == _type, self.phdrs)


class ElfPack_StrTab(object):

    def __init__(self):
        self.symstrtab = None  # type: Elf32_Shdr or Elf64_Shdr
        self.shstrtab = None  # type: Elf32_Shdr or Elf64_Shdr

    def get(self, offset, _type=STRTAB_SYM):
        strtab = {STRTAB_SYM: self.symstrtab, STRTAB_SH: self.shstrtab}[_type]
        end = strtab.data.index('\x00', offset)
        return strtab.data[offset:end]

    def add(self, data, _type=STRTAB_SYM):
        strtab = {STRTAB_SYM: self.symstrtab, STRTAB_SH: self.shstrtab}[_type]
        offset = len(strtab.data)
        strtab.append_data(data + '\x00')
        return offset

    def parse(self, elf):
        self.shstrtab = elf.shdr.find_by_index(elf.ehdr.e_shstrndx)

        # since shdr.strtab is not set yet, we have to find the section ourselves
        self.symstrtab = filter(lambda x: (self.get(x.sh_name, STRTAB_SH) == '.dynstr'),
                                elf.shdr.shdrs)[0]
        return self


class ElfPack_Hash(object):

    def __init__(self):
        self.gnuhash_shdr = None  # type: Elf32_Shdr or Elf64_Shdr
        self.gnuhash = None  # type: Elf32_GNU_Hash or Elf64_GNU_Hash
        self.oldhash_shdr = None  # type: Elf32_Shdr or Elf64_Shdr
        self.oldhash = None  # type: Elf32_Hash or Elf64_Hash
        self.packer = None  # type: Packer

    def __str__(self):
        return ((str(self.gnuhash) if self.gnuhash else '') +
                (str(self.oldhash) if self.oldhash else ''))

    def parse(self, stream, elf):
        self.packer = elf.packer
        Elf_Xword = choose(elf, Elf32_Word, Elf64_Xword)
        Elf_GNU_Hash = choose(elf, Elf32_GNU_Hash, Elf64_GNU_Hash)
        Elf_Hash = choose(elf, Elf32_Hash, Elf64_Hash)

        # deal with SHT_GNU_HASH, here is a dirty hack by setting the bitmask to
        # (2 ** (Elf_Xword * 8) - 1), so no hash will be rejected in the first step.
        # modifying the bitmask is possible, but it will make things too much messy.
        shdrs = elf.shdr.find_by_type(SHT_GNU_HASH)
        if shdrs:
            self.gnuhash_shdr = shdrs[0]
            self.gnuhash = Elf_GNU_Hash().parse(stream, shdrs[0].sh_offset,
                                                shdrs[0].sh_size, self.packer,
                                                symcnt=len(elf.dynsym))
            self.gnuhash_allow_all(self.gnuhash.h_bloom, Elf_Xword)

        # deal with SHT_HASH too if any
        shdrs = elf.shdr.find_by_type(SHT_HASH)
        if shdrs:
            self.oldhash_shdr = shdrs[0]
            self.oldhash = Elf_Hash().parse(stream, shdrs[0].sh_offset, self.packer)

        return self

    def serialize(self):
        if self.gnuhash:
            self.gnuhash_shdr.data = self.gnuhash.serialize()
        if self.oldhash:
            self.oldhash_shdr.data = self.oldhash.serialize()
        return True

    # set all bits in the bitmap
    def gnuhash_allow_all(self, h_bloom, Elf_Xword):
        for index in xrange(len(h_bloom)):
            h_bloom[index] = (2 ** (Elf_Xword * 8)) - 1

    def add_chain(self, chain):
        if self.gnuhash:
            self.gnuhash.h_chains.append(chain)

        if self.oldhash:
            self.oldhash.h_chains.append(chain)
            self.oldhash.h_nchain = len(self.oldhash.h_chains)

        self.serialize()
        return True

    def add_symbol_hash(self, st_name, st_ndx):
        if self.gnuhash:
            self.add_gnuhash(st_name, st_ndx)
        if self.oldhash:
            self.add_oldhash(st_name, st_ndx)
        self.serialize()
        return True

    # the structure of gnu_hash table is not fesible after everything is determined.
    # in a gnu_hash table, we have chain_index identical to symbol_index. which means,
    # if we want to add a chain_item into some h_buckets[N], we have to put the item
    # within the chain range, and this range is highly likely to be in the middle of
    # the whole chain, whose symbol will also be in the middle of the symbols table,
    # but the problem is we can not afford the complexity by turning the symbol table
    # upside down, therefore new symbol can only be inserted at the tail.
    # simply saying, it is not possible to add a symbol into the gnu_hash table without
    # changing the order of the symbols in symbol table.
    # the only location we can insert a symbol at is the tail of the table, so the only
    # location for the hash is the last slot. here is a dirty hack,
    # if we append the hash to the tail, and wipe out the last bit of every chain_item
    # in front of it, then the whole chain will act like a single chain, any hash mapped
    # into the chain will search the whole chain, until the target hash is reached, or
    # the last one is reached, this wont affect the symbol who indeed exists, only those
    # who does not exists may travel longer than expected. this is totally acceptable.
    #
    # ref: https://code.woboq.org/userspace/glibc/elf/dl-lookup.c.html
    def add_gnuhash(self, st_name, st_ndx):
        # should be called right after the symbol is added
        assert(st_ndx - self.gnuhash.h_symndx == len(self.gnuhash.h_chains))

        # update chains
        for i in xrange(len(self.gnuhash.h_chains)):    # clear END bit
            self.gnuhash.h_chains[i] &= 2 ** 32 - 2
        _hash = self.calculate_hash_new(st_name)
        self.gnuhash.h_chains.append(_hash | 1)         # set END bit

        # update buckets
        # if bucket == 0, then nobody is using this bucket, we can simple point it to
        # our added chain item. otherwise, it has been used by someoneelse, and we are
        # adding the last one, so the symbol is also accessible under the circumstance
        bucket_ndx = _hash % self.gnuhash.h_nbucket
        if self.gnuhash.h_buckets[bucket_ndx] == 0:
            self.gnuhash.h_buckets[bucket_ndx] = st_ndx

        return True

    # old SysV-style hash table is much more flexible, we can insert hash by pointing
    # the end of the chain to the last one added. this shall perfectly.
    def add_oldhash(self, st_name, st_ndx):
        # should be called right after the symbol is added
        assert(st_ndx == len(self.oldhash.h_chains))

        self.oldhash.h_chains.append(STN_UNDEF)     # end of the chain
        self.oldhash.h_nchain = len(self.oldhash.h_chains)

        bucket_ndx = self.calculate_hash_old(st_name) % self.oldhash.h_nbucket
        index = self.oldhash.h_buckets[bucket_ndx]

        # if this is a empty chain, point bucket directly to the added one
        if index == STN_UNDEF:
            self.oldhash.h_buckets[bucket_ndx] = st_ndx

        # find the last one in the chain, point it to the newly added one
        else:
            while self.oldhash.h_chains[index] != STN_UNDEF:
                index = self.oldhash.h_chains[index]
            self.oldhash.h_chains[index] = st_ndx

        return True

    # sysv style hash function
    def calculate_hash_old(self, string):
        _hash = 0
        for ch in map(ord, string):
            _hash = ((_hash << 4) + ch) % 2 ** 32
            hi = _hash & 0xf0000000
            _hash = (_hash ^ (hi >> 24)) & ~hi
        return _hash

    # gnu style hash function
    def calculate_hash_new(self, string):
        _hash = 5381
        for ch in map(ord, string):
            _hash = _hash * 33 + ch
        return _hash % 2 ** 32


class ElfPack_Init_Array(object):

    def __init__(self):
        self.built_inits = list()   # type: [Elf32_Addr or Elf64_Addr]
        self.new_inits = list()     # labels or addresses for new init_array entry
        self.shdr = None            # type: Elf32_Shdr or Elf64_Shdr
        self.packer = None          # type: Packer
        self.elf = None
        self.Elf_Addr = None
        self.inithead_label = None
        self.should_relocate = False

    def __str__(self):
        return ', '.join(map(lambda x: hex(x), self.built_inits) + self.new_inits)

    def __len__(self):
        return len(self.built_inits) + len(self.new_inits)

    def parse(self, elf):
        self.packer = elf.packer
        self.Elf_Addr = choose(elf, Elf32_Addr, Elf64_Addr)
        self.elf = elf

        shdrs = elf.shdr.find_by_type(SHT_INIT_ARRAY)
        if not shdrs:
            return self
        self.shdr = shdrs[0]

        for index in xrange(0, len(self.shdr.data), self.Elf_Addr):
            init_entry = self.packer.unpack(self.shdr.data[index:index + self.Elf_Addr])
            self.built_inits.append(init_entry)

        return self

    def serialize_array(self, inits):
        return ''.join(map(lambda x: self.packer.pack(x, self.Elf_Addr), inits))

    def serialize(self):
        return self.serialize_array(self.built_inits)

    # adding an entry to .init_array. we cannot move the .init_array somewhere directly or
    # append entries after the array, b/c somehow gcc does not use the information stored in
    # DT_INIT_ARRAY and DT_INIT_ARRAYSZ. changing this wont change the behaviour of elf, since
    # it has already hardcoded the range of .init_array into __libc_csu_init. so basically we
    # cannot move .init_array or enlarge it. there are 2 choices left here for us:
    # + edit the hardcoded range in __libc_csu_init, reassemble the instructions, but I think
    #   this makes things much more complicated.
    # + change one of the entry already present in .init_array to our stub, which shall perform
    #   exactly the same as __libc_csu_init, except it will pick entries from another array we
    #   setup containing the new entries we added and the old entry we replaced.
    # we will take the second approach here to add new init entries.
    def add(self, label):
        self.new_inits.append(label)

    # we have first determine how many entries we have in this new allocated .init_array,
    # and add the array into patch_data section, as well as the stub into patch_code section.
    def prefinalize(self):
        if not self.new_inits:
            return

        # the original elf does not have a .init_array, add one for it
        if self.shdr is None:

            # add a new .init_array section header
            sh_name = self.elf.strtab.add('.init_array', STRTAB_SH)
            Elf_Shdr = self.elf.shdr.Elf_Shdr
            self.shdr = Elf_Shdr(sh_name=sh_name,
                                 sh_type=SHT_INIT_ARRAY,
                                 sh_flags=SHF_WRITE | SHF_ALLOC,
                                 sh_entsize=self.Elf_Addr,
                                 sh_addralign=self.Elf_Addr,
                                 packer=self.packer)
            self.elf.shdr.add(self.shdr)
            self.should_relocate = True

            # pretend we have 1 entry here in .init_array, it will be updated to inserted
            # csu_init entry when finalizing
            self.shdr.data = self.packer.pack(0, self.Elf_Addr)

            # also add .dynamics entry for ld.so, value will be update during saving
            self.elf.dynamic.add(DT_INIT_ARRAY, 0)
            self.elf.dynamic.add(DT_INIT_ARRAYSZ, 0)

        # if we do have an .init_array section, but nothing presents in the section, we shall then
        # add a dummy entry ourselves. (this is just a corner case, which most likely may not be
        # the case in a realworld application)
        elif not self.built_inits:
            self.shdr.data = self.packer.pack(0, self.Elf_Addr)

        # if we have at least one entry in the orignal array, move it to new_inits
        if self.built_inits:
            self.new_inits.insert(0, self.built_inits.pop())  # add replaced init_entry

        # add dummy init_array data
        init_array_length = self.Elf_Addr * len(self.new_inits)
        self.inithead_label = 'added_init_array_head'
        self.elf.add_data(self.inithead_label, '\x00' * init_array_length)

        # add new csu_init code
        added_csu_init_label = 'added_csu_init'
        new_csu_init = self.elf.assembler.make_csu_init(self.inithead_label, len(self.new_inits))
        self.elf.add_code(added_csu_init_label, new_csu_init)
        self.built_inits.append(added_csu_init_label)

        # we are done here if no relocation is needed
        if not self.elf.pie:
            return

        # if a new .init_array is added, add relocation for the only new entries
        # otherwise the original relative relocations should work fine
        if self.should_relocate:

            # add relocation for enties in original init_array
            for index, init in enumerate(self.built_inits):
                label = 'moved_init_array_%d' % index
                self.elf.add_relative_label(label, 'section_init_array', index * self.Elf_Addr)
                self.elf.reloc.add_relative(label=label)

        # add relocation for entries in new init_array
        for index, init in enumerate(self.new_inits):
            label = 'added_init_array_%d' % index
            self.elf.add_relative_label(label, self.inithead_label, index * self.Elf_Addr)
            self.elf.reloc.add_relative(label=label)

    def update_entry(self, inits, finder):
        for index in xrange(len(inits)):
            entry = inits[index]
            if type(entry) is str:
                inits[index] = finder(entry)
        return True

    # now we can finally find address for all labels, update builtin init_array and
    # the init_array we added, if any.
    def finalize(self, finder):
        if not self.new_inits:
            return

        self.update_entry(self.built_inits, finder)
        self.update_entry(self.new_inits, finder)

        self.elf.pdatashdr.update(self.inithead_label, self.serialize_array(self.new_inits))
        self.shdr.data = self.serialize()


class ElfPack_TLS(object):
    """
    currently only support TLS BSS data manipulation
    """

    def __init__(self):
        self.packer = None      # type: Packer
        self.elf = None
        self.Elf_Addr = None
        self.tbssdata = list()

    def parse(self, elf):
        self.packer = elf.packer
        self.elf = elf
        self.Elf_Addr = choose(elf, Elf32_Addr, Elf64_Addr)
        return self

    # create a tls bss section or take existing one, same for tls program header
    def create_bss(self, size):
        # if .tbss section already exists, we will take this one as well as the
        # PT_TLS program header
        shdrs = self.elf.shdr.find_by_name('.tbss')
        if shdrs:
            tbss_shdr = shdrs[0]
            tbss_shndx = self.elf.shdr.index(tbss_shdr)
            tbss_offset = tbss_shdr.sh_size_dummy
            tls_phdr = self.elf.phdr.get(PT_TLS)[0]
            tls_phdr.p_memsz += size
            tbss_shdr.sh_size_dummy += size
            return tbss_shndx, tbss_offset

        # there is no .tbss section, then we shall create one ourselves from now.
        # if .tdata(1) section does exists, we will add the .tbss right behind the
        # .tdata(1) section
        shdrs = (self.elf.shdr.find_by_name('.tdata') +
                 self.elf.shdr.find_by_name('.tdata1'))
        if shdrs:
            tdata_shdr = shdrs[0]
            sh_addr = tdata_shdr.sh_addr + tdata_shdr.sh_size
            sh_offset = tdata_shdr.sh_offset + tdata_shdr.sh_size
            tls_phdr = self.elf.phdr.get(PT_TLS)[0]
            tls_phdr.p_memsz += size

        # otherwise, there shall be no presence of TLS-related stuff
        else:
            if self.elf.phdr.get(PT_TLS):
                raise ValueError("PT_TLS found without .tbss or .tdata(1) section.")

            # we will pick the first section with RW permission as the boundary
            # for the new .tbss section, and as well add a PT_TLS program header
            victim = self.elf.shdr.find_by_perm(SHF_ALLOC | SHF_WRITE)[0]
            sh_addr = victim.sh_addr
            sh_offset = victim.sh_offset
            Elf_Phdr = self.elf.phdr.Elf_Phdr
            tls_phdr = Elf_Phdr(p_type=PT_TLS,
                                p_offset=sh_offset,
                                p_vaddr=sh_addr,
                                p_paddr=sh_addr,
                                p_filesz=0,
                                p_memsz=size,
                                p_flags=PF_R,
                                p_align=ALIGN_DATA,
                                packer=self.packer)
            self.elf.phdr.add(tls_phdr)

        # add new .tbss section
        sh_name = self.elf.strtab.add('.tbss', STRTAB_SH)
        Elf_Shdr = self.elf.shdr.Elf_Shdr
        tbss_shdr = Elf_Shdr(sh_name=sh_name,
                             sh_type=SHT_NOBITS,
                             sh_flags=SHF_WRITE | SHF_ALLOC | SHF_TLS,
                             sh_addr=sh_addr,
                             sh_offset=sh_offset,
                             sh_size=size,
                             sh_addralign=ALIGN_DATA,
                             packer=self.packer)
        self.elf.shdr.add(tbss_shdr)
        tbss_shndx = self.elf.shdr.index(tbss_shdr)
        return tbss_shndx, 0

    def finalize(self):
        if not self.tbssdata:
            return

        # create new tls section and program header
        tls_data_size = sum(map(lambda x: x[1], self.tbssdata))
        tbss_shndx, tbss_offset = self.create_bss(tls_data_size)

        # for each item, add necessary tls relocation informations
        for name, size, offset_label in self.tbssdata:

            # add STT_TLS symbol, specify offset within TLS block
            st_name = self.elf.strtab.add(name, STRTAB_SYM)
            symndx = self.elf.dynsym.add(st_name=st_name,
                                         st_value=tbss_offset,
                                         st_size=size,
                                         st_bind=STB_GLOBAL,
                                         st_type=STT_TLS,
                                         st_shndx=tbss_shndx,
                                         packer=self.packer)
            tbss_offset += size

            # add TLS offset relocation for the symbol
            self.elf.reloc.add_tls_offset(label=offset_label, r_sym=symndx)

            # add gnu version information, *GLOBAL*
            if self.elf.gnuver:
                self.elf.gnuver.add(1)

            # add STB_GLOBAL symbol to hash table
            self.elf.hash.add_symbol_hash(name, symndx)

            # add a pointer data to reference the resolved TLS offset
            self.elf.add_data(offset_label, self.packer.pack(0, self.Elf_Addr))

        return True

    def add_bss(self, name, size, offset_label):
        self.tbssdata.append((name, size, offset_label))
