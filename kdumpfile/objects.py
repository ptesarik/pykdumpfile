'''kdumpfile.objects
'''

from collections.abc import MutableMapping

from _kdumpfile import ffi, lib as C

from .constants import *
from .exceptions import *
from . import utils

import addrxlat

###
### kdump_ctx_t
###

class Context(object):
    '''Context() -> context'''
    def __init__(self, ptr=None):
        if ptr is None:
            ptr = C.kdump_new()
            if not ptr:
                raise MemoryError('Could not allocate kdump_ctx_t')
        self._cdata = ptr

    def __del__(self):
        C.kdump_free(self._cdata)

    def clone(self, flags):
        '''CTX.clone() -> cloned context'''
        clone = C.kdump_clone(self._cdata, flags)
        if not clone:
            raise MemoryError('Could not allocate kdump_ctx_t')
        return Context(clone)

    def err(self, status, msg):
        '''CTX.err(status, msg) -> status

        Set the error message.'''
        s = utils.to_bytes(msg)
        return C.kdump_err(self._cdata, status, b'%s', ffi.from_buffer(s))

    def clear_err(self):
        '''CTX.clear_err()

        Clear the error message.'''
        C.kdump_clear_err(self._cdata)

    def get_err(self):
        '''CTX.get_err() -> error string

        Return a detailed error description of the last error condition.'''
        err = C.kdump_get_err(self._cdata)
        if not err:
            return None
        else:
            return utils.to_unicode(ffi.string(err))

    def get_addrxlat(self):
        '''CTX.get_addrxlat() -> (addrxlat context, addrxlat system)

        Get the associated address translation data structures.'''
        axctx = ffi.new('addrxlat_ctx_t **')
        axsys = ffi.new('addrxlat_sys_t **')
        status = C.kdump_get_addrxlat(self._cdata, axctx, axsys)
        if status != OK:
            raise get_exception(status, self.get_err())
        return (addrxlat.Context(addrxlat.ffi.cast('addrxlat_ctx_t *', axctx[0])),
                addrxlat.System(addrxlat.ffi.cast('addrxlat_sys_t *', axsys[0])))

    def d16toh(self, val):
        '''CTX.d16toh(val) -> 16-bit value in host byte order'''
        return C.kdump_d16toh(self._cdata, val)

    def d32toh(self, val):
        '''CTX.d32toh(val) -> 32-bit value in host byte order'''
        return C.kdump_d32toh(self._cdata, val)

    def d64toh(self, val):
        '''CTX.d64toh(val) -> 64-bit value in host byte order'''
        return C.kdump_d64toh(self._cdata, val)

    def set_filename(self, name):
        '''CTX.set_filename(name)

        Provide a descriptive name for a single-file dump.'''
        status = C.kdump_set_filename(self._cdata, utils.to_bytes(name))
        if status != OK:
            raise get_exception(status, self.get_err())

    def set_filenames(self, *names):
        '''CTX.set_filenames(name...)

        Provide descriptive names for each file in a set of dump files.'''
        names = tuple(ffi.new('char[]', utils.to_bytes(n)) for n in names)
        array = ffi.new('char*[]', names)
        status = C.kdump_set_filenames(self._cdata, len(names), array)
        if status != OK:
            raise get_exception(status, self.get_err())

    def open_fd(self, fd):
        '''CTX.open_fd(fd)

        Associate this context with a dump file using its file descriptor.'''
        status = C.kdump_open_fd(self._cdata, fd)
        if status != OK:
            raise get_exception(status, self.get_err())

    def open_fdset(self, *fdset):
        '''CTX.open_fdset(fd...)

        Associate this context with a set of dump files using their file descriptors.'''
        fds = ffi.new('int[]', fdset)
        status = C.kdump_open_fdset(self._cdata, len(fdset), fds)
        if status != OK:
            raise get_exception(status, self.get_err())

    def open(self, path):
        '''CTX.open(path)

        Open a dump file and associate this context with it.'''
        self._file = open(path)
        status = C.kdump_set_number_attr(self._cdata, b'file.fd', self._file.fileno())
        if status != OK:
            raise get_exception(status, self.get_err())

    def read(self, addrspace, address, size):
        '''CTX.read(addrspace, address, size) -> buffer

        Read decoded binary data from a starting address.'''
        buf = ffi.new('char[]', size)
        rd = ffi.new('size_t*')
        rd[0] = size
        status = C.kdump_read(self._cdata, addrspace, address, buf, rd)
        if status != OK:
                raise get_exception(status, self.get_err())
        return ffi.buffer(buf)

    def read_string(self, addrspace, addr):
        '''CTX.read(addrspace, address, size) -> bytes

        Read a NUL-terminated string from an address.'''
        pstr = ffi.new('char**')
        status = C.kdump_read_string(self._cdata, addrspace, addr, pstr)
        if status != OK:
                raise get_exception(status, self.get_err())
        ret = ffi.string(pstr[0])
        C.free(pstr[0])
        return ret

    def vmcoreinfo_raw(self):
        '''CTX.vmcoreinfo_raw() -> raw bytes

        Get the raw VMCOREINFO string.'''
        raw = ffi.new('char**')
        status = C.kdump_vmcoreinfo_raw(self._cdata, raw)
        if status != OK:
                raise get_exception(status, self.get_err())
        ret = ffi.string(raw[0])
        C.free(raw[0])
        return ret

    def vmcoreinfo_line(self, key):
        '''CTX.vmcoreinfo_line(key) -> bytes

        Get the raw VMCOREINFO value by full key name.'''
        val = ffi.new('char**')
        status = C.kdump_vmcoreinfo_line(self._cdata, utils.to_bytes(key), val)
        if status != OK:
                raise get_exception(status, self.get_err())
        ret = ffi.string(val[0])
        C.free(val[0])
        return ret

    def vmcoreinfo_symbol(self, name):
        '''CTX.vmcoreinfo_symbol(name) -> value

        Get SYMBOL value from VMCOREINFO.'''
        val = ffi.new('kdump_addr_t*')
        status = C.kdump_vmcoreinfo_symbol(self._cdata, utils.to_bytes(name), val)
        if status != OK:
                raise get_exception(status, self.get_err())
        return val[0]

    @property
    def attr(self):
        '''Access to libkdumpfile attributes'''
        return attr_dir(self, None)

class attr_ref(object):
    '''Attribute reference'''

    def __init__(self, ctx, key, base=None):
        self._ctx = ctx
        if key is None:
            if base is not None:
                self._cdata = base._cdata
                return
            key = ffi.NULL
        else:
            key = utils.to_bytes(key)
        self._cdata = ffi.new('kdump_attr_ref_t *')
        if base is None:
            status = C.kdump_attr_ref(self._ctx._cdata, key, self._cdata)
        else:
            status = C.kdump_sub_attr_ref(self._ctx._cdata, base._cdata, key, self._cdata)
        if status != OK:
            raise get_exception(status, self._ctx.get_err())

    def __del__(self):
        C.kdump_attr_unref(self._ctx._cdata, self._cdata)

class attr_dir(attr_ref, MutableMapping):
    '''Attribute directory'''

    # After initialization, this object's attributes become frozen
    # and further accesses are aliased to libkdumpfile attributes.
    __frozen = False

    def __init__(self, ctx, key, base=None):
        attr_ref.__init__(self, ctx, key, base)
        MutableMapping.__init__(self)
        self.__frozen = True

    def __contains__(self, k):
        try:
            ref = attr_ref(self._ctx, k, self)
            return True
        except NoKeyError:
            return False

    def __getitem__(self, k):
        try:
            ref = attr_ref(self._ctx, k, self)
        except NoKeyError:
            raise KeyError(k)
        if C.kdump_attr_ref_type(ref._cdata) == DIRECTORY:
            return attr_dir(self._ctx, None, ref)
        v = ffi.new('kdump_attr_t *')
        status = C.kdump_attr_ref_get(self._ctx._cdata, ref._cdata, v)
        if status == ERR_NODATA:
            raise KeyError(k)
        elif status != OK:
            raise get_exception(status, self._ctx.get_err())
        try:
            t = v[0].type
            if t == NUMBER:
                return v[0].val.number
            elif t == ADDRESS:
                return v[0].val.address
            elif t == STRING:
                return utils.to_unicode(ffi.string(v[0].val.string))
            elif t == BITMAP:
                return Bitmap(v[0].val.bitmap)
            elif t == BLOB:
                return Blob(v[0].val.blob)
            else:
                raise NotImplementedError('Unknown attribute type: {}'.format(t))
        finally:
            C.kdump_attr_discard(self._ctx._cdata, v)

    def __setitem__(self, k, v):
        ref = attr_ref(self._ctx, k, self)
        attr = ffi.new('kdump_attr_t *')
        if v is None:
            attr.type = NIL
        else:
            t = C.kdump_attr_ref_type(ref._cdata)
            if t == NUMBER:
                attr.val.number = v
            elif t == ADDRESS:
                attr.val.address = v
            elif t == STRING:
                s = utils.to_bytes(v)
                attr.val.string = ffi.from_buffer(s)
            else:
                raise NotImplementedError('Unknown attribute type: {}'.format(t))
            attr.type = t
        status = C.kdump_attr_ref_set(self._ctx._cdata, ref._cdata, attr)
        if status != OK:
            raise get_exception(status, self._ctx.get_err())

    def __delitem__(self, k):
        self.__setitem(k, None)

    def __getattr__(self, k):
        try:
            return self[k]
        except KeyError:
            raise AttributeError("'{}' object has no attribute '{}'".format(type(self).__name__, k)) from None

    def __setattr__(self, k, v):
        if self.__frozen:
            try:
                self[k] = v
            except NoKeyError:
                raise AttributeError(k) from None
        else:
            super().__setattr__(k, v)

    def __delattr__(self, k):
        self.__setattr__(k, None)

    def __iter__(self):
        it = ffi.new('kdump_attr_iter_t *')
        status = C.kdump_attr_ref_iter_start(self._ctx._cdata, self._cdata, it)
        if status != OK:
            raise get_exception(status, self._ctx.get_err())
        while it[0].key:
            yield utils.to_unicode(ffi.string(it[0].key))
            status = C.kdump_attr_iter_next(self._ctx._cdata, it)
            if status != OK:
                raise get_exception(status, self._ctx.get_err())

    def __len__(self):
        it = ffi.new('kdump_attr_iter_t *')
        status = C.kdump_attr_ref_iter_start(self._ctx._cdata, self._cdata, it);
        if status != OK:
            raise get_exception(status, self._ctx.get_err())
        length = 0
        while it[0].key:
            length += 1
            status = C.kdump_attr_iter_next(self._ctx._cdata, it)
            if status != OK:
                raise get_exception(status, self._ctx.get_err())
        return length

###
### kdump_bmp_t
###

class Bitmap(object):
    '''Bitmap() -> dump bitmap'''

    def __init__(self, ptr):
        C.kdump_bmp_incref(ptr)
        self._cdata = ptr

    def __del__(self):
        C.kdump_bmp_decref(self._cdata)

    def get_bits(self, first, last):
        '''BMP.get_bits(first, last) -> byte array

        Get bitmap bits as a raw bitmap.'''

        raw = bytearray((((last - first) | 7) + 1) >> 3)
        status = C.kdump_bmp_get_bits(self._cdata, first, last, ffi.from_buffer(raw))
        if status != OK:
            raise get_exception(status)
        return raw

    def find_set(self, idx):
        '''BMP.find_set(idx) -> index

        Find the closest set bit in a bitmapm, starting at idx.'''

        idx = ffi.new('kdump_addr_t*', idx)
        status = C.kdump_bmp_find_set(self._cdata, idx)
        if status != OK:
            raise get_exception(status)
        return idx[0]

    def find_clear(self, idx):
        '''BMP.find_clear(idx) -> index

        Find the closest zero bit in a bitmapm, starting at idx.'''

        idx = ffi.new('kdump_addr_t*', idx)
        status = C.kdump_bmp_find_clear(self._cdata, idx)
        if status != OK:
            raise get_exception(status)
        return idx[0]

###
### kdump_blob_t
###

class Blob(object):
    '''Blob() -> dump blob'''

    def __init__(self, ptr=None):
        if ptr is None:
            ptr = C.kdump_blob_new(ffi.NULL, 0)
            if not ptr:
                raise MemoryError('Could not allocate kdump_blob_t')
        else:
            C.kdump_blob_incref(ptr)
        self._cdata = ptr

    def __del__(self):
        C.kdump_blob_decref(self._cdata)

    def get(self):
        '''BLOB.get() -> buffer'''

        buffer = C.kdump_blob_pin(self._cdata)
        buffer = bytes(ffi.buffer(buffer, C.kdump_blob_size(self._cdata)))
        C.kdump_blob_unpin(self._cdata)
        return buffer

    def set(self, buffer):
        '''BLOB.set(buffer)

        Replace blob contents with a new value. The object given as
        argument must implement the buffer protocol.'''

        p = C.malloc(len(buffer))
        if not p:
            raise MemoryError('Could not allocate blob buffer')
        ffi.memmove(p, buffer, len(buffer))
        status = C.kdump_blob_set(self._cdata, p, len(buffer))
        if status != OK:
            C.free(p)
            raise get_exception(status)
