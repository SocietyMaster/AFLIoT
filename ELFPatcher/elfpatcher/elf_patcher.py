#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Himyth / AAA """

from elf_packer import *
from elf_assembler import *


class ELF(object):

    def __init__(self, filename):
        self.ehdr = None  # type: Elf32_Ehdr or Elf64_Ehdr
        self.shdr = None  # type: ElfPack_Shdr
        self.phdr = None  # type: ElfPack_Phdr
        self.dynamic = None  # type: ElfPack_Dyn
        self.dynsym = None  # type: ElfPack_Sym
        self.reloc = None  # type: ElfPack_Rel
        self.strtab = None  # type: ElfPack_StrTab
        self.hash = None  # type: ElfPack_Hash
        self.gnuver = None  # type: ElfPack_GNU_Version
        self.recorder = None  # type: Recorder
        self.assembler = None  # type: Assembler
        self.pdatashdr = None
        self.pcodeshdr = None
        self.codeshdrs = None  # type: [Elf32_Shdr or Elf64_Shdr]
        self.packer = None  # type: Packer
        self.finalizer_args = list()
        self.pcodes = dict()
        self.updateinfos = dict()
        self.exlabel = dict()
        self.displacements = dict()
        self.Elf_Addr = None
        self.initarray = None  # type: ElfPack_Init_Array
        self.tlsdata = None  # type: ElfPack_TLS
        self.pointers = list()
        self.pie = False
        self.relative_labels = dict()
        self.relocatable_labels = set()
        self.label_cache = None

        self.parse(filename)

    def parse(self, filename):
        stream = ExactFile(filename, 'rb')

        self.ehdr = ElfPack_Ehdr().parse(stream, 0)
        self.packer = self.ehdr.packer
        self.shdr = ElfPack_Shdr().parse(stream, self)
        self.strtab = ElfPack_StrTab().parse(self)
        self.shdr.set_strtab(self.strtab)   # find_by_name activated
        self.phdr = ElfPack_Phdr().parse(stream, self)
        self.dynamic = ElfPack_Dyn().parse(stream, self)
        self.dynsym = ElfPack_Sym().parse(stream, self)
        self.reloc = ElfPack_Rel().parse(stream, self)
        self.hash = ElfPack_Hash().parse(stream, self)
        self.gnuver = ElfPack_GNU_Version().parse(stream, self)
        self.recorder = self.phdr.recorder
        self.assembler = Assembler(self)
        self.codeshdrs = self.shdr.find_by_perm(SHF_EXECINSTR)
        self.Elf_Addr = choose(self, Elf32_Addr, Elf64_Addr)
        self.initarray = ElfPack_Init_Array().parse(self)
        self.tlsdata = ElfPack_TLS().parse(self)
        self.pie = self.ehdr.e_type == ET_DYN

        stream.close()

    # relocate all sections changed, newly added, or meant to shift
    def relocate_sections(self):

        # shift interp and note section behind to make rooms for program headers,
        # update program header entry is also needed
        self.do_relocate_section(shdrs=self.shdr.find_by_name('.interp'),
                                 label='interp', tphdr=PT_INTERP)
        self.do_relocate_section(shdrs=self.shdr.find_by_type(SHT_NOTE),
                                 label='note', tphdr=PT_NOTE)

        # shift gnuhash, dynsym, dynstr and gnuversion, reldyn section behind,
        # since they may be changed and old space size wont fit,
        # update of dynamic section is also needed
        self.do_relocate_section(shdrs=self.shdr.find_by_type(SHT_GNU_HASH),
                                 label='gnuhash', tdynaddr=DT_GNU_HASH)
        self.do_relocate_section(shdrs=self.shdr.find_by_type(SHT_DYNSYM),
                                 label='dynsym', tdynaddr=DT_SYMTAB)
        self.do_relocate_section(shdrs=self.shdr.find_by_name('.dynstr'),
                                 label='dynstr', tdynaddr=DT_STRTAB, tdynsz=DT_STRSZ)
        self.do_relocate_section(shdrs=self.shdr.find_by_type(SHT_GNU_VERSYM),
                                 label='gnuversion', tdynaddr=DT_GNU_VERSYM)

        # shift .hash section, some binary has this one, operate same as above
        self.do_relocate_section(shdrs=self.shdr.find_by_type(SHT_HASH),
                                 label='hash', tdynaddr=DT_HASH)

        # choose from one of the rel and the rela sections
        self.do_relocate_section(shdrs=self.shdr.find_by_name('.rel.dyn'),
                                 label='reldyn', tdynaddr=DT_REL, tdynsz=DT_RELSZ)
        self.do_relocate_section(shdrs=self.shdr.find_by_name('.rela.dyn'),
                                 label='reladyn', tdynaddr=DT_RELA, tdynsz=DT_RELASZ)

        # since libc_csu_init will hardcode address of .init_array, we shall not relocate
        # .init_array unless we have added a new .init_array
        if self.initarray.should_relocate:
            self.do_relocate_section(shdrs=self.shdr.find_by_type(SHT_INIT_ARRAY),
                                     label='initarray', _type='w',
                                     tdynaddr=DT_INIT_ARRAY, tdynsz=DT_INIT_ARRAYSZ)

        # shift shstrtab section behind since it will expand when new section
        # added, and shstrtab will not be loaded into memory
        self.do_relocate_section(shdrs=self.shdr.find_by_name('.shstrtab'),
                                 label='shstrtab', loadable=False)

        # shift dynamics section, program header should be adjusted too.
        #
        # here is something messy, according to our current strategy, the content will be
        # laid out in the order of X/R/W. this means, if there are no W sections other than
        # .dynamic section(say, we have not added any W data), .dynamic section will be
        # the last section in the file, and there is a check in readelf.c:
        #
        # https://chromium.googlesource.com/native_client/nacl-binutils/+
        # /upstream/master/binutils/readelf.c
        # 4784 if (dynamic_addr + dynamic_size >= current_file_size)
        # 4785 {
        # 4786  error ( ("the dynamic segment offset + size exceeds the size of the file\n"));
        # 4787  dynamic_addr = dynamic_size = 0;
        # 4788 }
        #
        # this will deactived our shifted .dynamic section, so we can not have both ends
        # of the file and .dynamic section coincided. an ugly fix will be make when we
        # flush the file, that is, appending an extra word to the file.
        self.do_relocate_section(shdrs=self.shdr.find_by_type(SHT_DYNAMIC),
                                 label='dynamics', _type='w', tphdr=PT_DYNAMIC)

        # add patched data/code section if any
        self.do_relocate_section(shdrs=[self.pdatashdr], label='pdata', _type='w')
        self.do_relocate_section(shdrs=[self.pcodeshdr], label='pcode', _type='x')

    # apply all the modifications we made to actual structure
    def apply_modifications(self, verbose):

        # finalize recorder, now addresses for every label is determined
        new_phdrs = self.recorder.finalize(self.phdr.Elf_Phdr)

        # run registered finalizers to really apply changes
        for args, kwargs in self.finalizer_args:
            self.do_finalize_section(*args, **kwargs)

        # now we know where patch section locates, address of symbols reside
        # are determined, then we should update all the references
        self.do_finalize_patch(verbose)

        # add new program headers for loadable segments
        for phdr in new_phdrs:
            self.phdr.add(phdr)

        # update elf header
        self.ehdr.e_phnum = len(self.phdr)
        self.ehdr.e_shnum = len(self.shdr)

        # check if new program header could fit in the slot
        min_offset, min_sh_name = 2 ** 64, ''
        for shdr in self.shdr.shdrs:
            if 0 < shdr.sh_offset < min_offset:
                min_sh_name = self.strtab.get(shdr.sh_name, STRTAB_SH)
                min_offset = shdr.sh_offset
        if min_offset - self.ehdr.e_phoff < self.ehdr.e_phnum * self.ehdr.e_phentsize:
            raise ValueError('Section "%s" overlapped with program header.' % min_sh_name)

    # there are stuffs we cannot determine the size or something else, we can only determine
    # it here when save is called and no more further changes will be make. after removing
    # these uncertainties, we can relocate section using their real size and perform others.
    def determine_uncertainties(self, verbose):
        self.initarray.prefinalize()    # size of new .init_array shall be determined
        self.tlsdata.finalize()         # size of tbss section shall be determined
        self.assembler.make_code_relative(self, verbose)

    def save(self, filename, verbose=False):
        self.determine_uncertainties(verbose)
        self.relocate_sections()
        self.apply_modifications(verbose)

        verbose_log('Writing to target file.', verbose)

        # now flush them out
        stream = open(filename, 'wb')
        swrite(stream, self.ehdr.e_phoff, self.phdr.serialize())
        for offset, data in self.shdr.serialize_data():
            swrite(stream, offset, data)

        # put section headers after the end of the file, update ehdr as well
        stream.seek(0, 2)
        self.ehdr.e_shoff = alignment(stream.tell(), ALIGN_DATA)
        swrite(stream, 0, self.ehdr.serialize())
        swrite(stream, self.ehdr.e_shoff, self.shdr.serialize())

        # ugly fix to keep any section from touching the file end
        stream.seek(0, 2)
        swrite(stream, stream.tell(), self.packer.pack(0, self.Elf_Addr))

        stream.close()

    # relocate sections, add to recorder, and register finalizer
    # this is just a probe, action will be taken after finalization
    def do_relocate_section(self, shdrs, label, _type='r', **kwargs):
        if not shdrs or not filter(lambda x: x is not None, shdrs):
            return

        for i, shdr in enumerate(shdrs):
            shdr.sh_size = len(shdr.data)
            self.recorder.add(label=('section(%s)(%d)' % (label, i)),
                              size=shdr.sh_size,
                              align=shdr.sh_addralign,
                              _type=_type)
        self.finalizer_args.append(((label, shdrs), kwargs))

    # do finalize, update section header/program header/dynamic section
    def do_finalize_section(self, label, shdrs, tphdr=None, tdynaddr=None,
                            tdynsz=None, loadable=True):
        # assume all section laid out continuously
        updates = []
        for i, shdr in enumerate(shdrs):
            shdr.sh_offset, sh_addr = self.recorder.get('section(%s)(%d)' % (label, i))
            shdr.sh_addr = 0 if not loadable else sh_addr
            updates.append((shdr.sh_offset, shdr.sh_addr, len(shdr.data)))

        if updates:
            # calculate memory layout
            updates.sort(key=lambda x: x[1])      # sort by sh_addr
            offset, vaddr, _ = updates[0]
            size = (updates[-1][0] - updates[0][0]) + updates[-1][2]

            self.phdr.update(tphdr, offset, vaddr, size)
            self.dynamic.update(tdynaddr, vaddr)
            self.dynamic.update(tdynsz, size)

        return True

    # recursively resolve relative labels
    def resolve_relative_label(self, label):

        # if this is already resolved
        if label in self.label_cache:
            return self.label_cache[label]

        # this leads to another relative label, resolve recursively
        if label in self.relative_labels:
            target, offset = self.relative_labels[label]
            raddr = self.resolve_relative_label(target)
            return raddr + offset

        # we cannot find this label
        return None

    # we should have already finished address layout finalization when this gets called,
    # instead of finding label from pcode and pdata every time query happens, which is quiet
    # slow. lets speed it up by building a cache for all possible labels here.
    def find_label(self, label):

        # finalization not yet completed
        if self.label_cache is None:
            return None

        # cache had been built, just pick it up
        if self.label_cache is not 0:
            return self.label_cache.get(label, None)

        # called the first time, build the cache
        self.label_cache = dict()
        self.label_cache.update(self.pdatashdr.fetch_all() if self.pdatashdr else {})
        self.label_cache.update(self.pcodeshdr.fetch_all() if self.pcodeshdr else {})
        self.label_cache.update(self.exlabel)
        for rlabel in self.relative_labels:
            self.label_cache[rlabel] = self.resolve_relative_label(rlabel)

        return self.find_label(label)

    # peek data from one of the section with length
    def peek_data(self, sh_addr, length):
        for shdr in self.shdr.shdrs:
            if (shdr.sh_addr <= sh_addr) and (shdr.sh_addr + len(shdr.data) >= sh_addr + length):
                break
        else:
            return None
        offset = sh_addr - shdr.sh_addr
        return shdr.data[offset:offset + length]

    # called after finalization, addresses should be fix now
    def do_finalize_patch(self, verbose):

        verbose_log('Finalizing inserted data and code section.', verbose)

        # if we have patch data, update relocations
        if self.pdatashdr is not None:
            self.pdatashdr.finalize()

        # add all section to exlabel so find_label can find them, this has to be done before
        # enabling label_cache.
        for shdr in self.shdr.shdrs:
            sh_name = re.sub('[^\w]', '', self.strtab.get(shdr.sh_name, STRTAB_SH))
            self.add_exlabel('section_%s' % sh_name, shdr.sh_addr)

        # address layout finalization almost done here, there are 4 types of label:
        # + patch data, which is finalized above
        # + patch code, if pcodeshdr is None then we already done, if not it will be finalized
        #   in the next a few lines, no big difference here
        # + relative label, all occurrences of add_relative_label happened before
        # + extra label, all occurrences of add_exlabel happened before
        # thus, it is safe to enable the label_cache here
        self.label_cache = 0

        # if we have patch code, update referenced labels and
        # recompile code into the section data
        if self.pcodeshdr:
            self.pcodeshdr.finalize()

            # displacement works with simple text substitution, calculate the offset here
            disps = dict()
            for disp, info in self.displacements.items():
                label = info['patch_label']
                offset = info['insert_addr'] - (self.find_label(label) + info['wrap_offset'])
                disps[label] = (disp, offset)

            # record updates and update once
            updates = list()
            for label, (code, _) in self.pcodes.iteritems():
                vaddr = self.pcodeshdr.get(label)
                asm, _ = self.assembler.generate_code(code=code, vaddr=vaddr,
                                                      finder=self.find_label,
                                                      disp=disps.get(label, None))
                updates.append((label, asm))
            self.pcodeshdr.update_many(updates)

        # update pointers, also one time update
        updates = list()
        for label, target_label in self.pointers:
            data = self.packer.pack(self.find_label(target_label), self.Elf_Addr)
            updates.append((label, data))
        self.pdatashdr.update_many(updates)

        # finalize labels referenced in .init_array
        self.initarray.finalize(finder=self.find_label)

        verbose_log('Updating .text section for branches to inserted code.', verbose)

        # update patched text code, one time update
        updates = dict()
        for vaddr, update in self.updateinfos.items():
            shdr = update['shdr']
            offset = update['offset']
            asm, _ = self.assembler.generate_code(code=update['code'], vaddr=vaddr,
                                                  finder=self.find_label)
            if shdr in updates:
                updates[shdr].append((offset, asm))
            else:
                updates[shdr] = [(offset, asm)]
        for shdr in updates:
            shdr.update_data_many(updates[shdr])

        # finalize relocation in the end
        self.reloc.finalize(self.find_label)

        return True

    def check_data_section(self):
        if self.pdatashdr is not None:
            return

        # if this is the first time, add a section for RW data
        sh_name = self.strtab.add('.pdata', STRTAB_SH)
        self.pdatashdr = ElfPatch_Shdr(sh_name=sh_name,
                                       sh_type=SHT_PROGBITS,
                                       sh_flags=SHF_WRITE | SHF_ALLOC,
                                       sh_addralign=ALIGN_DATA,
                                       permtype='w',
                                       elf=self)
        self.shdr.add(self.pdatashdr)

    def check_code_section(self):
        if self.pcodeshdr is not None:
            return

        # if this is the first time, add a section for RX code
        sh_name = self.strtab.add('.pcode', STRTAB_SH)
        self.pcodeshdr = ElfPatch_Shdr(sh_name=sh_name,
                                       sh_type=SHT_PROGBITS,
                                       sh_flags=SHF_EXECINSTR | SHF_ALLOC,
                                       sh_addralign=ALIGN_CODE,
                                       permtype='x',
                                       elf=self)
        self.shdr.add(self.pcodeshdr)

    def check_patch_label(self, label):
        if type(label) is not str:
            raise ValueError('Label "%s" should be string' % str(label))
        if self.pcodeshdr and label in self.pcodeshdr.items:
            raise ValueError('Label "%s" already exists in code' % label)
        if self.pdatashdr and label in self.pdatashdr.items:
            raise ValueError('Label "%s" already exists in data' % label)
        if label in self.exlabel:
            raise ValueError('Label "%s" already exists in exlabel' % label)
        if label in self.relative_labels:
            raise ValueError('Label "%s" already exists in relative_label' % label)
        if not re.match(r'^[a-zA-Z_]\w*$', label):
            raise ValueError('Label "%s" does not match "^[a-zA-Z_]\w*$"' % label)
        return True

    # check if vaddr belongs to one of SHF_EXECINSTR sections
    def check_code_vaddr(self, vaddr):
        if type(vaddr) is not int:
            raise ValueError('Patch target "%s" should be an integer' % str(vaddr))
        if vaddr in self.updateinfos:
            raise ValueError('Patch code already exists for address %#x' % vaddr)
        for shdr in self.codeshdrs:
            if vaddr < shdr.sh_addr or vaddr >= shdr.sh_addr + shdr.sh_size:
                continue
            return shdr, (vaddr - shdr.sh_addr)
        raise ValueError('Patch target %#x does not belong to a SHF_EXECINSTR section'
                         % vaddr)

    def check_imported_library(self, libfile):
        for dyn in self.dynamic.find_by_type(DT_NEEDED):
            if self.strtab.get(dyn.d_val, STRTAB_SYM) == libfile:
                return True
        return False

    def add_imported_symbol(self, name, label, libfile='libc.so.6'):
        """
        add an imported symbol(etc. functions), store relocated symbol pointer
        in data area, which can be referenced through label.

        :param name:    symbol name
        :param label:   label to reference this symbol
        :param libfile: library that symbol belongs to
        :return:        True
        """
        self.check_data_section()
        self.check_patch_label(label)

        # add symbol to dynsym section
        st_name = self.strtab.add(name, STRTAB_SYM)
        symndx = self.dynsym.add(packer=self.packer, st_name=st_name,
                                 st_bind=STB_GLOBAL, st_type=STT_FUNC)

        # add relocation, but we cannot determine r_offset right now
        self.reloc.add_global_symbol(label=label, r_sym=symndx)

        # find version for library
        if not self.check_imported_library(libfile):
            self.add_imported_library(libfile)

        # add to versym array if exists
        if self.gnuver:
            self.gnuver.add(self.gnuver.find_version(libfile))

        # chain does not matter for import symbol, use 0
        self.hash.add_chain(STN_UNDEF)

        # finally set a pointer in this section we can reference
        self.add_data(label, self.packer.pack(0, self.Elf_Addr))
        return True

    def add_imported_library(self, libfile):
        """
        add imported library

        :param libfile: library file name
        :return:        True or False
        """
        if self.check_imported_library(libfile):
            raise ValueError('Library "%s" already imported' % libfile)
        dt_needed_str = self.strtab.add(libfile, STRTAB_SYM)
        self.dynamic.add(DT_NEEDED, dt_needed_str, offset=0)
        return True

    def add_data(self, label, data, align=ALIGN_DATA):
        """
        add independent data

        :param label:   label for this data, referenced elsewhere
        :param data:    data itself, type: string
        :param align:   alignment for data
        :return:        True
        """
        self.check_data_section()
        self.check_patch_label(label)

        self.pdatashdr.add(label, data, align)
        self.relocatable_labels.add(label)
        return True

    def add_pointer(self, label, target_label):
        """
        add a pointer referenced by label, who points to target_label

        :param label:           label for this pointer
        :param target_label:    target label
        :return:                True or False
        """
        self.pointers.append((label, target_label))
        self.add_data(label, self.packer.pack(0, self.Elf_Addr))

        # add relocation for the pointer if PIE
        if self.pie:
            self.reloc.add_relative(label=label)

        return True

    def add_code(self, label, code, disp=None, align=ALIGN_CODE):
        """
        add independent code

        :param label:   label for this code, referenced elsewhere
        :param code:    assembly code
        :param disp:    consts replacements
        :param align:   alignment for code
        :return:        True or False
        """
        self.check_code_section()
        self.check_patch_label(label)

        # generate actual code, vaddr set to 0
        asm, count = self.assembler.generate_code(code=code, vaddr=0, disp=disp)
        self.pcodes[label] = (code, asm)
        self.pcodeshdr.add(label, asm, align)

        # label to code is also relocatable
        self.relocatable_labels.add(label)

        return True

    def insert_code(self, where, label, code, nbound=None, align=ALIGN_CODE):
        """
        insert code before some instruction in binary, the inserted code will execute
        before this instruction, and this address should be a virtual address belongs
        to sections with SHF_EXECINSTR permission.

        :param where:   where the instruction is
        :param label:   label for this code
        :param code:    assembly code
        :param nbound:  where the next block is(or None for not care)
        :param align:   alignment for code
        :return:        how many bytes patched
        """
        self.check_patch_label(label)

        ishdr, ioffset = self.check_code_vaddr(where)
        wrapper, rlabels, size, disp = self.assembler.wrap_insert_code(sdata=ishdr.data,
                                                                       offset=ioffset,
                                                                       vaddr=where,
                                                                       nbound=nbound)

        if rlabels is not None:
            for rlabel, value in rlabels.iteritems():
                self.add_exlabel(rlabel, value, reloc=True)

        # append code with wrapper, add to new code section
        self.add_code(label=label, code=code + '\n' + wrapper,
                      disp=(disp, 0xdeadbeef) if disp else None, align=align)

        # record displacement information if any, note that the original code does not
        # have displacements(disp).
        if disp is not None:
            asm, _ = self.assembler.generate_code(code=code, vaddr=0)
            self.displacements[disp] = {
                'patch_label': label,
                'insert_addr': where,
                'wrap_offset': len(asm)     # offset from patch code head to wrapper
            }

        self.updateinfos[where] = {
            'code': self.assembler.make_branch(label),
            'shdr': ishdr,
            'offset': ioffset
        }
        return size

    def patch_code(self, fromwhere, towhere, label, code, align=ALIGN_CODE):
        """
        patch code from *fromwhere* to *towhere*, the code in between will be skipped,
        two endpoints currently shall be within the same section.

        :param fromwhere:   jump to patched code from here
        :param towhere:     return from patched code to here
        :param label:       label for this code
        :param code:        assembly code
        :param align:       alignment for code
        :return:            True or False
        """
        self.check_patch_label(label)

        fshdr, foffset = self.check_code_vaddr(fromwhere)
        tshdr, toffset = self.check_code_vaddr(towhere)
        if fshdr is not tshdr:
            raise ValueError('Patch code "%s" should range within one section' % label)

        if towhere < fromwhere:
            raise ValueError('Patch code "%s" has illegal endpoints' % label)

        # lets pretend it will jump to label, just for calculating the length
        jumper = self.assembler.make_branch(label)
        asm, _ = self.assembler.generate_code(jumper, vaddr=fromwhere)
        if toffset - foffset < len(asm):
            raise ValueError('Patch code "%s" does not have enough space for jumper' % label)

        # append code with branch back to *towhere*
        code = code + '\n' + self.assembler.make_branch(towhere)
        self.add_code(label, code, align=align)

        # record where to update at *fromwhere*
        self.updateinfos[fromwhere] = {
            'code': jumper,
            'shdr': fshdr,
            'offset': foffset
        }
        return True

    def add_exlabel(self, label, value, reloc=False):
        """
        add additional label other than code & data

        :param label:   extra label
        :param value:   label value
        :param reloc:   if this label stands for relocatable address
        :return:        True or False
        """
        self.check_patch_label(label)

        if type(value) is not int and type(value) is not long:
            raise ValueError('Value of label "%s" should be integer' % label)

        self.exlabel[label] = value

        if reloc:
            self.relocatable_labels.add(label)

        return True

    def add_relative_label(self, label, target, offset):
        """
        add label points to target label plus offset

        :param label:   extra label
        :param target:  target label
        :param offset:  offset from target label
        :return:        True or False
        """
        self.check_patch_label(label)

        if type(offset) is not int and type(offset) is not long:
            raise ValueError('Offset from target label "%s" should be integer' % target)

        self.relative_labels[label] = (target, offset)
        return True

    def add_init_function(self, label):
        """
        add a function entry into .init_array

        :param label:   the label for target function entry
        :return:        True or False
        """
        self.initarray.add(label)  # dummy entry with label added
        return True

    def add_tls_bss_data(self, name, size, offset_label):
        """
        add uninitialized(zero) thread-local-storage data, access with offset

        :param name:            label for the data
        :param size:            the size of the data
        :param offset_label:    label to access the offset from tls head
        :return:                True or False
        """
        self.check_patch_label(offset_label)

        if type(size) is not int and type(size) is not long:
            raise ValueError('Size of TLS data "%s" should be integer' % name)

        self.tlsdata.add_bss(name, size, offset_label)

        # pointer for tls offset will be added when finalize, but we may need this before
        # finalization, we can do it here in advance
        self.relocatable_labels.add(offset_label)

        return True

    def change_interp(self, new_interp):
        """
        change program interpreter to new interpreter path

        :param new_interp:  path of the new interpreter
        :return:            True or False
        """
        shdrs = self.shdr.find_by_name('.interp')
        if not shdrs:
            return False

        interp = shdrs[0]
        interp.data = new_interp + '\x00'
        return True
