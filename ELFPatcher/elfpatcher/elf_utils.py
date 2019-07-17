#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Himyth / AAA """

import struct
from copy import copy
import datetime

from elf_consts import *


def alignment(value, align):
    align = 1 if align <= 0 else align
    return (value + align - 1) / align * align


def merge_alignment(aligna, alignb):
    def gcd(a, b):
        while b > 0:
            a, b = b, a % b
        return a

    def lcm(a, b):
        return a * b / gcd(a, b)

    if aligna == 0 or alignb == 0:
        return max(aligna, alignb)
    return lcm(aligna, alignb)


def swrite(stream, offset, data=''):
    stream.seek(0, 2)           # seek to the end first
    if offset < stream.tell():
        stream.seek(offset, 0)  # going back
    else:
        stream.write((offset - stream.tell()) * '\x00')     # enlarge file
    stream.write(data)          # now the real data


def choose(elf, arch32, arch64):
    return {ELFCLASS32: arch32,
            ELFCLASS64: arch64}[elf.ehdr.e_ident.ei_class]


def verbose_log(msg, verbose):
    if not verbose:
        return
    print '%s %s' % (str(datetime.datetime.now()), msg)


class Packer(object):

    def __init__(self, ei_data):
        opts = {ELFDATA2LSB: '<',
                ELFDATA2MSB: '>'}
        if ei_data not in opts:
            raise ValueError("ELF data endianness should be either LSB or MSB")
        self.endianness = opts[ei_data]

    def unpack(self, data):
        opts = {8: 'Q', 4: 'I', 2: 'H', 1: 'B'}
        assert(len(data) in opts)
        return struct.unpack(self.endianness + opts[len(data)], data)[0]

    def pack(self, value, size):
        opts = {8: 'Q', 4: 'I', 2: 'H', 1: 'B'}
        assert(size in opts)
        return struct.pack(self.endianness + opts[size], value)


class Pointer(object):

    def __init__(self, offset, vaddr):
        self.offset = offset
        self.vaddr = vaddr

    def grow(self, size):
        offset, vaddr = (self.offset, self.vaddr)
        self.offset += size
        self.vaddr += size
        return offset, vaddr

    def keep_align(self, align):
        self.offset = alignment(self.offset, align)
        self.vaddr = alignment(self.vaddr, align)


# had to assume only adding in x/r/w order,
# otherwise the sections may overlap
class Injector(object):

    def __init__(self, offset, vaddr, page_align, packer):
        self.pointer = Pointer(offset, vaddr)
        self.page_align = page_align
        self.status = ' '
        self.maps = dict()
        self.packer = packer

    def add_rx_data(self, size, align):
        if self.status in [' ']:
            self.page_up('x')
        assert(self.status == 'x')
        return self.do_add_data(size, align)

    def add_ro_data(self, size, align):
        if self.status in [' ', 'x']:
            self.page_up('r')
        assert(self.status == 'r')
        return self.do_add_data(size, align)

    def add_rw_data(self, size, align):
        if self.status in [' ', 'x', 'r']:
            self.page_up('w')
        assert(self.status == 'w')
        return self.do_add_data(size, align)

    def page_up(self, status):
        self.status = status

        # if we already have some pages, then we should page up
        do_page_up = self.do_end_segment()

        # if going up and we are not at edge of pages
        if do_page_up and self.pointer.vaddr % self.page_align != 0:
            self.pointer.vaddr += self.page_align

        self.maps[status] = [copy(self.pointer)]

    def do_end_segment(self):
        if not self.maps:
            return False

        for perm in self.maps:
            if len(self.maps[perm]) == 2:   # full paired
                continue
            self.maps[perm].append(copy(self.pointer))
            return True

        return False

    def do_add_data(self, size, align):
        self.pointer.keep_align(align)
        return self.pointer.grow(size)

    # Elf_Phdr is the fix for recursive import
    def finalize(self, Elf_Phdr):
        self.status = '-'       # no more add
        self.do_end_segment()   # feed the tail

        # see if we should return program headers for new sections
        if not Elf_Phdr:
            return

        # X/R/W order, make program headers
        privileges = {
            'x': PF_R + PF_X,
            'r': PF_R,
            'w': PF_R + PF_W
        }
        phdrs = []
        for _type in 'xrw':
            if _type not in self.maps:
                continue

            head = self.maps[_type][0]
            tail = self.maps[_type][1]
            phdr = Elf_Phdr(p_type=PT_LOAD,
                            p_offset=head.offset,
                            p_vaddr=head.vaddr,
                            p_paddr=head.vaddr,
                            p_filesz=tail.offset - head.offset,
                            p_memsz=tail.vaddr - head.vaddr,
                            p_flags=privileges[_type],
                            p_align=self.page_align,
                            packer=self.packer)
            phdrs.append(phdr)
        return phdrs

    def is_finalized(self):
        return self.status == '-'

    def rebase(self, offset, vaddr):
        self.pointer.offset = offset
        self.pointer.vaddr = vaddr


class Record(object):

    def __init__(self, size, align, index, vaddr=0, offset=0):
        self.size = size
        self.align = align
        self.vaddr = vaddr
        self.offset = offset
        self.index = index


class Recorder(object):

    def __init__(self, offset, vaddr, page_align, packer):
        self.packer = packer
        self.recorders = dict()
        for _type in 'xrw':
            self.recorders[_type] = dict()
        self.injector = Injector(offset, vaddr, page_align, self.packer)
        self.resolved = dict()
        self.counter = 0

    def add(self, label, size, align, _type):
        assert(_type in 'xrw')

        # label shall not duplicate
        if label in self.resolved:
            raise ValueError("Duplicate label '%s' added to recorder." % label)

        # store new record with growing index
        record = Record(size=size, align=align, index=self.counter)
        self.recorders[_type][label] = record
        self.counter += 1

        # for now it is not resolved, but we only use resolved
        # information after finalization, so it is not an issue
        self.resolved[label] = record

    def remove(self, label):
        if label in self.resolved:
            del self.resolved[label]
        for _type in 'xrw':
            if label in self.recorders[_type]:
                del self.recorders[_type][label]

    def finalize(self, Elf_Phdr=None):
        handlers = {
            'x': self.injector.add_rx_data,
            'r': self.injector.add_ro_data,
            'w': self.injector.add_rw_data
        }

        # sorting makes it `looks` more stable
        for _type in 'xrw':
            for r in sorted(self.recorders[_type].values(), key=lambda x: x.index):
                r.offset, r.vaddr = handlers[_type](r.size, r.align)

        # now we have already aquire the information about
        # + the segments to be added
        # + all records with label, offset, vaddr, which can be
        #   used in real data construction
        return self.injector.finalize(Elf_Phdr)

    def get(self, label):
        if not self.is_finalized():
            return None

        if label not in self.resolved:
            return None

        return self.resolved[label].offset, self.resolved[label].vaddr

    def fetch_all_vaddr(self):
        if not self.is_finalized():
            return None

        return {label: record.vaddr for label, record in self.resolved.iteritems()}

    def is_finalized(self):
        return self.injector.is_finalized()

    def rebase(self, offset, vaddr):
        self.injector.rebase(offset, vaddr)


# override read function, check length after return
class ExactFile(file):

    # make pycharm happy
    def next(self):
        return super(ExactFile, self).next()

    def read(self, *args):
        if len(list(args)) != 1:
            return super(ExactFile, self).read(*args)
        excepted_length = int(list(args)[0])
        data = ''
        while excepted_length > len(data):  # make a loop to avoid data loss
            part = super(ExactFile, self).read(excepted_length - len(data))
            if part == '':
                raise ValueError("Data less than needed, check if beyond the end of file")
            data += part
        return data
