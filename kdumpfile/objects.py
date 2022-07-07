'''kdumpfile.objects
'''

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

    def open(self, path):
        '''CTX.open(path)

        Open a dump file and associate this context with it.'''
        self._file = open(path)
        status = C.kdump_set_number_attr(self._cdata, b'file.fd', self._file.fileno())
        if status != OK:
            raise get_exception(status, self.get_err())

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

class attr_dir(attr_ref):
    '''Attribute directory'''

    # After initialization, this object's attributes become frozen
    # and further accesses are aliased to libkdumpfile attributes.
    __frozen = False

    def __init__(self, ctx, key, base=None):
        super().__init__(ctx, key, base)
        self.__frozen = True

    def __contains__(self, k):
        try:
            ref = attr_ref(self._ctx, k, self)
            return True
        except NoKeyError:
            return False

    def get(self, k, d=None):
        '''D.get(k[,d]) -> D[k] if k in D, else d.  d defaults to None.'''
        try:
            ref = attr_ref(self._ctx, k, self)
        except NoKeyError:
            return d
        if C.kdump_attr_ref_type(ref._cdata) == DIRECTORY:
            return attr_dir(self._ctx, None, ref)
        v = ffi.new('kdump_attr_t *')
        status = C.kdump_attr_ref_get(self._ctx._cdata, ref._cdata, v)
        if status == ERR_NODATA:
            return None
        elif status != OK:
            raise get_exception(status, self._ctx.get_err())
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

    def __getitem__(self, k):
        v = self.get(k)
        if v is None:
            raise KeyError(k)
        return v

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
