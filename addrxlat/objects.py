'''addrxlat.objects

There are two types of objects in libaddrxlat:

- simple value
- reference-counted

'''

from _addrxlat import ffi, lib as C

from .constants import *
from .exceptions import *
from . import utils

###
### Helper constants
###

_ADDR_MAX_HALF = ADDR_MAX // 2

###
### Common property setters
###

def _cdata_or_null(value):
    if value is None:
        return ffi.NULL
    else:
        return value._cdata

###
### Callback functions
###

ERR_PYEXC = ERR_CUSTOM_BASE
ERR_CFFI_CONV = ERR_CUSTOM_BASE - 1

def _status_result(ctx, status, result):
    if status == OK:
        ctx._set_exception()
        return result
    exc, val, tb = ctx._set_exception()
    if exc is not None:
        utils.restore_exception(exc, val, tb)
    elif status == ERR_CFFI_CONV:
        raise TypeError('CFFI could not convert callback return value')
    else:
        raise get_exception(status, ctx.get_err())

def _ctx_error(ctx, exc, val, tb):
    ctx._set_exception(exc, val, tb)
    if issubclass(exc, AddrxlatError):
        status = exc.status
    else:
        status = ERR_PYEXC
    return ctx.err(status, str(val))

def _cb_ctx_error(exc, val, tb):
    if tb is None:
        # happens if there was an error converting the return value
        return ERR_CFFI_CONV
    ctx = ffi.from_handle(tb.tb_frame.f_locals['cb'].priv)
    return _ctx_error(ctx, exc, val, tb)

@ffi.def_extern(onerror=_cb_ctx_error, error=ERR_PYEXC)
def _cb_reg_value(cb, name, val):
    return ffi.from_handle(cb.priv)._cb_reg_value(name, val)

@ffi.def_extern(onerror=_cb_ctx_error, error=ERR_PYEXC)
def _cb_sym_value(cb, name, val):
    return ffi.from_handle(cb.priv)._cb_sym_value(name, val)

@ffi.def_extern(onerror=_cb_ctx_error, error=ERR_PYEXC)
def _cb_sym_sizeof(cb, name, val):
    return ffi.from_handle(cb.priv)._cb_sym_sizeof(name, val)

@ffi.def_extern(onerror=_cb_ctx_error, error=ERR_PYEXC)
def _cb_sym_offsetof(cb, obj, elem, val):
    return ffi.from_handle(cb.priv)._cb_sym_offsetof(obj, elem, val)

@ffi.def_extern(onerror=_cb_ctx_error, error=ERR_PYEXC)
def _cb_num_value(cb, name, val):
    return ffi.from_handle(cb.priv)._cb_num_value(name, val)

@ffi.def_extern(onerror=_cb_ctx_error, error=ERR_PYEXC)
def _cb_get_page(cb, buf):
    return ffi.from_handle(cb.priv)._cb_get_page(buf)

@ffi.def_extern(onerror=_cb_ctx_error, error=0)
def _cb_read_caps(cb):
    return ffi.from_handle(cb.priv)._cb_read_caps()

@ffi.def_extern()
def _cb_put_page(buf):
    ffi.from_handle(buf.priv)._cb_put_page()

def _cb_meth_error(exc, val, tb):
    if tb is None:
        # happens if there was an error converting the return value
        return ERR_CFFI_CONV
    ctx = Context(tb.tb_frame.f_locals['step'].ctx)
    return _ctx_error(ctx, exc, val, tb)

@ffi.def_extern(onerror=_cb_meth_error, error=ERR_PYEXC)
def _cb_first_step(step, addr):
    return ffi.from_handle(step.meth.param.custom.data)._cb_first_step(step, addr)

@ffi.def_extern(onerror=_cb_meth_error, error=ERR_PYEXC)
def _cb_next_step(step):
    return ffi.from_handle(step.meth.param.custom.data)._cb_next_step(step)

def _cb_op_error(exc, val, tb):
    if tb is None:
        # happens if there was an error converting the return value
        return ERR_CFFI_CONV
    op = ffi.from_handle(tb.tb_frame.f_locals['op'])
    return _ctx_error(op.ctx, exc, val, tb)

@ffi.def_extern(onerror=_cb_op_error, error=ERR_PYEXC)
def _cb_op(op, addr):
    return ffi.from_handle(op)._cb_op(addr)

###
### addrxlat_ctx_t
###

class Context(object):
    '''Context([ptr]) -> ctx

    Wrapper for cdata addrxlat_ctx_t *.
    If ptr is omitted, allocate a new translation context.'''

    def __init__(self, ptr=None):
        if ptr is None:
            ptr = C.addrxlat_ctx_new()
            if not ptr:
                raise MemoryError('Could not allocate addrxlat_ctx_t')
        else:
            C.addrxlat_ctx_incref(ptr)

        self._cdata = ptr
        self._exc = None
        self._exc_val = None
        self._exc_tb = None
        self._handle = ffi.new_handle(self)
        self._cb = C.addrxlat_ctx_add_cb(self._cdata)
        self._cb.priv = self._handle
        self._cb.get_page = C._cb_get_page
        self._cb.read_caps = C._cb_read_caps
        self._cb.reg_value = C._cb_reg_value
        self._cb.sym_value = C._cb_sym_value
        self._cb.sym_sizeof = C._cb_sym_sizeof
        self._cb.sym_offsetof = C._cb_sym_offsetof
        self._cb.num_value = C._cb_num_value
        self.read_caps = None

    def __del__(self):
        ctx = self._cdata
        self._cdata = ffi.NULL
        C.addrxlat_ctx_del_cb(ctx, self._cb)
        C.addrxlat_ctx_decref(ctx)

    def __eq__(self, other):
        return self._cdata == other._cdata

    def __ne__(self, other):
        return not self == other

    def err(self, status, str):
        '''CTX.err(status, str) -> status

        Set the error message.'''
        return C.addrxlat_ctx_err(self._cdata, status, utils.to_bytes(str))

    def clear_err(self):
        '''CTX.clear_err()

        Clear the error message.'''
        C.addrxlat_ctx_clear_err(self._cdata)

    def get_err(self):
        '''CTX.get_err() -> error string

        Return a detailed error description of the last error condition.'''
        err = C.addrxlat_ctx_get_err(self._cdata)
        if not err:
            return None
        else:
            return utils.to_unicode(ffi.string(err))

    def _set_exception(self, exc=None, exc_val=None, exc_tb=None):
        '''Save an exception, returning the old value.

        With no arguments, clear the saved exception.'''
        result = (self._exc, self._exc_val, self._exc_tb)
        self._exc = exc
        self._exc_val = exc_val
        self._exc_tb = exc_tb
        return result

    def _cb_reg_value(self, name, val):
        val[0] = self.cb_reg_value(ffi.string(name))
        return OK

    def cb_reg_value(self, name):
        '''CTX.cb_reg_value(name) -> val

        Callback function to get register value by name.'''
        return self.next_cb_reg_value(name)

    def next_cb_reg_value(self, name):
        '''CTX.next_cb_reg_value(name) -> val

        Call the next callback to get register value.'''
        val = ffi.new('addrxlat_addr_t*')
        status = self._cb.next.reg_value(self._cb.next, utils.to_bytes(name), val)
        return _status_result(self, status, val[0])

    def _cb_sym_value(self, name, val):
        val[0] = self.cb_sym_value(ffi.string(name))
        return OK

    def cb_sym_value(self, name):
        '''CTX.cb_sym_value(name) -> val

        Callback function to get symbol value by name.'''
        return self.next_cb_sym_value(name)

    def next_cb_sym_value(self, name):
        '''CTX.next_cb_sym_value(name) -> val

        Call the next callback to get symbol value.'''
        val = ffi.new('addrxlat_addr_t*')
        status = self._cb.next.sym_value(self._cb.next, utils.to_bytes(name), val)
        return _status_result(self, status, val[0])

    def _cb_sym_sizeof(self, name, val):
        val[0] = self.cb_sym_sizeof(ffi.string(name))
        return OK

    def cb_sym_sizeof(self, name):
        '''CTX.cb_sym_sizeof(name) -> val

        Callback function to get symbol size by name.'''
        return self.next_cb_sym_sizeof(name)

    def next_cb_sym_sizeof(self, name):
        '''CTX.next_cb_sym_sizeof(name) -> val

        Call the next callback to get symbol size.'''
        val = ffi.new('addrxlat_addr_t*')
        status = self._cb.next.sym_sizeof(self._cb.next, utils.to_bytes(name), val)
        return _status_result(self, status, val[0])

    def _cb_sym_offsetof(self, obj, elem, val):
        val[0] = self.cb_sym_offsetof(ffi.string(obj), ffi.string(elem))
        return OK

    def cb_sym_offsetof(self, obj, elem):
        '''CTX.cb_sym_offsetof(obj, elem) -> val

        Callback function to get element offset within object.'''
        return self.next_cb_sym_offsetof(obj, elem)

    def next_cb_sym_offsetof(self, obj, elem):
        '''CTX.next_cb_sym_offsetof(obj, elem) -> val

        Call the next callback to get element offset within object.'''
        val = ffi.new('addrxlat_addr_t*')
        status = self._cb.next.sym_offsetof(self._cb.next, utils.to_bytes(obj),
                                            utils.to_bytes(elem), val)
        return _status_result(self, status, val[0])

    def _cb_num_value(self, name, val):
        val[0] = self.cb_num_value(ffi.string(name))
        return OK

    def cb_num_value(self, name):
        '''CTX.cb_num_value(name) -> val

        Callback function to get number value by name.'''
        return self.next_cb_num_value(name)

    def next_cb_num_value(self, name):
        '''CTX.next_cb_num_value(name) -> val

        Call the next callback to get number value.'''
        val = ffi.new('addrxlat_addr_t*')
        status = self._cb.next.num_value(self._cb.next, utils.to_bytes(name), val)
        return _status_result(self, status, val[0])

    def _cb_get_page(self, buf):
        self.cb_get_page(Buffer(buf))
        return OK

    def cb_get_page(self, buf):
        '''CTX.cb_get_page(buf)

        Callback function to read a page at a given address. Update the Buffer
        object passed as parameter.'''
        return self.next_cb_get_page(buf)

    def next_cb_get_page(self, buf):
        '''CTX.next_cb_get_page(buf)

        Call the next callback to read a page.'''
        status = self._cb.next.get_page(self._cb.next, buf._cdata)
        return _status_result(self, status, None)

    def _cb_read_caps(self):
        return self.cb_read_caps()

    def cb_read_caps(self):
        '''CTX.cb_read_caps() -> read_caps

        Callback function to get a bitmask of address spaces accepted by
        CTX.cb_read_page(). Returns CTX.read_caps if not None, otherwise
        calls CTX.next_cb_read_caps().'''
        if self.read_caps is not None:
            return self.read_caps
        return self.next_cb_read_caps()

    def next_cb_read_caps(self):
        '''CTX.next_cb_read_caps()

        Call the next read capabilities callback.'''
        return self._cb.next.read_caps(self._cb.next)

###
### addrxlat_buffer_t
###

class Buffer(object):
    '''Buffer([ptr]) -> buf

    Wrapper for cdata addrxlat_buffer_t *.
    If ptr is omitted, allocate a new buffer.'''

    def __init__(self, ptr=None):
        if ptr is None:
            ptr = ffi.new('addrxlat_buffer_t*')
            if not ptr:
                raise MemoryError('Could not allocate addrxlat_buffer_t')

        self._cdata = ptr
        self._handle = ffi.new_handle(self)
        self._cdata.put_page = C._cb_put_page
        self._cdata.priv = self._handle
        self._data = None

    @property
    def addr(self):
        '''address (FullAddress)'''
        return FullAddressFromCData(self._cdata.addr)

    @addr.setter
    def addr(self, value):
        self._cdata.addr = value._cdata[0]

    @property
    def data(self):
        '''raw binary data'''
        if self._cdata.ptr == ffi.NULL:
            return None
        return ffi.buffer(self._cdata.ptr, self._cdata.size)

    @data.setter
    def data(self, value):
        self._data = value
        if value is None:
            self._cdata.ptr = ffi.NULL
            self._cdata.size = 0
        else:
            cdata = ffi.from_buffer(value)
            self._cdata.ptr = cdata
            self._cdata.size = len(cdata)

    @property
    def byte_order(self):
        '''byte order'''
        return self._cdata.byte_order

    @byte_order.setter
    def byte_order(self, value):
        self._cdata.byte_order = value

    def _cb_put_page(self):
        self.cb_put_page()

    def cb_put_page(self):
        '''BUF.cb_put_page()

        Callback function to release a page data object that was previously
        returned by CTX.cb_get_page().'''
        self.data = None

###
### addrxlat_fulladdr_t
###

class FullAddress(object):
    '''FullAddress(ptr) -> fulladdr

    Construct a full address, that is an address within a given
    address space (xxxADDR).'''

    def __init__(self, addrspace=NOADDR, addr=0):
        self._cdata = ffi.new('addrxlat_fulladdr_t*', {
            'as': addrspace,
            'addr': addr,
        })

    def __repr__(self):
        return '%s(%r, %r)' % (
            self.__class__.__name__,
            self.addrspace,
            self.addr)

    @property
    def addr(self):
        '''address (unsigned)'''
        return self._cdata.addr

    @addr.setter
    def addr(self, value):
        self._cdata.addr = value

    @property
    def addrspace(self):
        '''address space'''
        return getattr(self._cdata, 'as')

    @addrspace.setter
    def addrspace(self, value):
        setattr(self._cdata, 'as', value)

    def __eq__(self, other):
        return (self.addr == other.addr and
                self.addrspace == other.addrspace)

    def __ne__(self, other):
        return not self == other

    def conv(self, addrspace, ctx, sys):
        '''FULLADDR.conv(addrspace, ctx, sys) -> status

        Convert a full address to a given target address space.'''
        status = C.addrxlat_fulladdr_conv(self._cdata, addrspace, ctx._cdata, sys._cdata)
        return _status_result(ctx, status, None)

    def copy(self):
        "make a copy of self"
        return type(self)(addrspace=self.addrspace, addr=self.addr)

def FullAddressFromCData(ptr):
    '''FullAddressFromCData(ptr) -> FullAddress

    Initialize a FullAddress from a cdata addrxlat_fulladdr_t *.'''
    return FullAddress(getattr(ptr, 'as'), ptr.addr)

no_address = FullAddress(NOADDR, 0)

###
### addrxlat_meth_t
###

class Method(object):
    '''Method(kind) -> address translation method

    This is a generic base class for all translation desriptions.
    Use a subclass to get a more suitable interface to the parameters
    of a specific translation kind.'''

    def __init__(self, kind, target_as=NOADDR, param=None):
        self.__cdata = ffi.new('addrxlat_meth_t*', {
            'kind': kind,
            'target_as': target_as,
        })
        sz = ffi.sizeof(self.__cdata.param)
        self._param = ffi.cast('unsigned char[{}]'.format(sz),
                               ffi.addressof(self.__cdata.param))
        if param is not None:
            self.param = param

    def __eq__(self, other):
        return ffi.buffer(self._cdata) == ffi.buffer(other._cdata)

    def __ne__(self, other):
        return not self == other

    @property
    def _cdata(self):
        '''raw cdata representation of the Method object'''
        return self.__cdata

    @property
    def kind(self):
        '''translation kind'''
        return self.__cdata.kind

    @property
    def target_as(self):
        '''target address space'''
        return self.__cdata.target_as

    @target_as.setter
    def target_as(self, value):
        self.__cdata.target_as = value

    @property
    def param(self):
        '''method parameters as a raw byte buffer'''
        return self._param

    @param.setter
    def param(self, value):
        self._param[0:len(value)] = value

# ADDRXLAT_CUSTOM
class CustomMethod(Method):
    '''CustomMethod() -> custom address translation method

    This is an abstract base class for translation methods based on
    callback. Change the cb_first_step and cb_next_step methods to
    get a working instance.'''

    def __init__(self, target_as=NOADDR):
        super(CustomMethod, self).__init__(CUSTOM, target_as)
        self._handle = ffi.new_handle(self)
        param = ffi.addressof(self._cdata.param.custom)
        param.first_step = C._cb_first_step
        param.next_step = C._cb_next_step
        param.data = self._handle

    def _cb_first_step(self, step, addr):
        '''raw first_step callback'''
        stepobj = StepFromCData(step)
        self.cb_first_step(stepobj, addr)
        step[0] = stepobj._cdata[0]
        return OK

    def cb_first_step(self, step, addr):
        '''METH.cb_first_step(step, addr)

        Callback to perform the initial translation step.'''
        raise NotImplementedError('NULL callback')

    def _cb_next_step(self, step):
        '''raw next_step callback'''
        stepobj = StepFromCData(step)
        self.cb_next_step(stepobj)
        step[0] = stepobj._cdata[0]
        return OK

    def cb_next_step(self, step):
        '''METH.cb_next_step(step)

        Callback to perform further translation steps.'''
        raise NotImplementedError('NULL callback')

class ForwardCustomMethod(CustomMethod):
    '''ForwardCustomMethod(ptr) -> custom address translation method.

    Wrapper around an existing custom translation method. Callbacks are
    forwarded to that object's implementation. Instances of this class
    are created by MethodFromCData.'''

    def __init__(self, ptr):
        super(ForwardCustomMethod, self).__init__(ptr.target_as)
        self._forward = ptr[0]

    def cb_first_step(self, step, addr):
        '''Forward the first step callback to the wrapped method.'''
        try:
            step._cdata.meth = ffi.addressof(self._forward)
            cdata = step._cdata
            status = self._forward.param.custom.first_step(cdata, addr)
            step.base = FullAddressFromCData(cdata.base)
            return status
        finally:
            step._cdata.meth = self._cdata

    def cb_next_step(self, step):
        '''Forward the next step callback to the wrapped method.'''
        try:
            step._cdata.meth = ffi.addressof(self._forward)
            cdata = step._cdata
            status = self._forward.param.custom.next_step(cdata)
            step.base = FullAddressFromCData(cdata.base)
            return status
        finally:
            step._cdata.meth = self._cdata

# ADDRXLAT_LINEAR
class LinearMethod(Method):
    '''LinearMethod() -> linear address translation method'''

    def __init__(self, target_as=NOADDR, off=0):
        super(LinearMethod, self).__init__(LINEAR, target_as)
        self.off = off

    def __repr__(self):
        return '%s(%r, %r)' % (
            self.__class__.__name__,
            self.target_as,
            self.off)

    @property
    def off(self):
        '''target linear offset from source'''
        return self._cdata.param.linear.off

    @off.setter
    def off(self, value):
        # Clip large numbers to addrxlat_off_t
        self._cdata.param.linear.off = ((value + _ADDR_MAX_HALF) & ADDR_MAX) - _ADDR_MAX_HALF

# ADDRXLAT_PGT
class PageTableMethod(Method):
    '''PageTableMethod() -> page table address translation method'''

    def __init__(self, target_as=NOADDR, root=no_address, pte_format=PTE_NONE, fields=()):
        super(PageTableMethod, self).__init__(PGT, target_as)
        self.root = root
        self.pte_format = pte_format
        self.fields = fields

    def __repr__(self):
        return '%s(%r, %r, %r, %r)' % (
            self.__class__.__name__,
            self.target_as,
            self.root,
            self.pte_format,
            self.fields)

    @property
    def _cdata(self):
        '''raw cdata representation of the PageTableMethod object'''
        super()._cdata.param.pgt.root = self._root._cdata[0]
        return super()._cdata

    @property
    def root(self):
        '''root page table address'''
        return self._root

    @root.setter
    def root(self, value):
        self._root = value

    @property
    def pte_mask(self):
        '''page table entry mask'''
        return super()._cdata.param.pgt.pte_mask

    @pte_mask.setter
    def pte_mask(self, value):
        super()._cdata.param.pgt.pte_mask = value

    @property
    def pte_format(self):
        '''format of a page tabe entry (PTE_xxx)'''
        return super()._cdata.param.pgt.pf.pte_format

    @pte_format.setter
    def pte_format(self, value):
        super()._cdata.param.pgt.pf.pte_format = value

    @property
    def fields(self):
        '''size of address fields in bits'''
        pf = ffi.addressof(super()._cdata.param.pgt.pf)
        return tuple(pf.fieldsz[0:pf.nfields])

    @fields.setter
    def fields(self, value):
        pf = ffi.addressof(super()._cdata.param.pgt.pf)
        pf.fieldsz = value
        pf.nfields = len(value)

# ADDRXLAT_LOOKUP
class LookupMethod(Method):
    '''LookupMethod() -> table lookup address translation method'''

    def __init__(self, target_as=NOADDR, endoff=0, tbl=()):
        super(LookupMethod, self).__init__(LOOKUP, target_as)
        self.endoff = endoff
        self.tbl = tbl

    def __repr__(self):
        return '%s(%r, %r, %r)' % (
            self.__class__.__name__,
            self.target_as,
            self.endoff,
            self.tbl)

    @property
    def endoff(self):
        '''max address offset inside each object'''
        return self._cdata.param.lookup.endoff

    @endoff.setter
    def endoff(self, value):
        self._cdata.param.lookup.endoff = value

    @property
    def tbl(self):
        'lookup table'
        return self._tbl

    @tbl.setter
    def tbl(self, value):
        nelem = len(value)
        p = C.malloc(nelem * ffi.sizeof('addrxlat_lookup_elem_t'))
        if not p:
            raise MemoryError('Could not allocate addrxlat_lookup_elem_t*')
        try:
            p = ffi.cast('addrxlat_lookup_elem_t*', p)
            for idx, (orig, dest) in enumerate(value):
                p[idx] = { 'orig': orig, 'dest': dest }
        except:
            C.free(p)
            raise
        param = ffi.addressof(self._cdata.param.lookup)
        C.free(param.tbl)
        param.tbl = p
        param.nelem = nelem
        self._tbl = value

# ADDRXLAT_MEMARR
class MemoryArrayMethod(Method):
    '''MemoryArrayMethod() -> memory array address translation method'''

    def __init__(self, target_as=NOADDR, base=no_address, shift=0, elemsz=0, valsz=0):
        super(MemoryArrayMethod, self).__init__(MEMARR, target_as)
        self.base = base
        self.shift = shift
        self.elemsz = elemsz
        self.valsz = valsz

    def __repr__(self):
        return '%s(%r, %r, %r, %r, %r)' % (
            self.__class__.__name__,
            self.target_as,
            self.base,
            self.shift,
            self.elemsz,
            self.valsz)

    @property
    def base(self):
        '''base address of the translation array'''
        return self._base

    @base.setter
    def base(self, value):
        self._base = value
        self._cdata.param.memarr.base = value._cdata[0]

    @property
    def shift(self):
        '''address bit shift'''
        return self._cdata.param.memarr.shift

    @shift.setter
    def shift(self, value):
        self._cdata.param.memarr.shift = value

    @property
    def elemsz(self):
        '''size of each array element'''
        return self._cdata.param.memarr.elemsz

    @elemsz.setter
    def elemsz(self, value):
        self._cdata.param.memarr.elemsz = value

    @property
    def valsz(self):
        '''size of the value'''
        return self._cdata.param.memarr.valsz

    @valsz.setter
    def valsz(self, value):
        self._cdata.param.memarr.valsz = value

def MethodFromCData(ptr):
    '''MethodFromCData(ptr) -> method

    Initialize a Method from a cdata addrxlat_meth_t *.'''

    if not ptr:
        return None

    kind = ptr.kind
    target_as = ptr.target_as

    if kind == CUSTOM:
        return ForwardCustomMethod(ptr)
    elif kind == LINEAR:
        return LinearMethod(target_as, ptr.param.linear.off)
    elif kind == PGT:
        pgt = ffi.addressof(ptr.param.pgt)
        return PageTableMethod(target_as, pgt.root, pgt.pf.pte_format)
    elif kind == LOOKUP:
        return LookupMethod(target_as, ptr.param.lookup.endoff)
    elif kind == MEMARR:
        memarr = ffi.addressof(ptr.param.memarr)
        return MemoryArrayMethod(target_as, memarr.base, memarr.shift, memarr.elemsz, memarr.valsz)
    else:
        sz = ffi.sizeof(ptr.param)
        p = ffi.cast('unsigned char[{}]'.format(sz), ffi.addressof(ptr.param))
        return Method(kind, target_as, p)

###
### addrxlat_range_t
###

class Range(object):
    '''Range() -> range

    Construct an address range.'''

    def __init__(self, endoff=0, meth=SYS_METH_NONE):
        self._cdata = ffi.new('addrxlat_range_t*', {
            'endoff': endoff,
            'meth': meth,
        })

    def __repr__(self):
        return '%s(%r, %r)' % (
            self.__class__.__name__,
            self.endoff,
            self.meth)

    @property
    def endoff(self):
        '''maximum offset contained in the range'''
        return self._cdata.endoff

    @endoff.setter
    def endoff(self, value):
        self._cdata.endoff = value

    @property
    def meth(self):
        '''translation method for this range'''
        return self._cdata.meth

    @meth.setter
    def meth(self, value):
        self._cdata.meth = value

    def copy(self):
        "make a copy of self"
        return type(self)(endoff=self.endoff, meth=self.meth)

def RangeFromCData(ptr):
    '''RangeFromCData(ptr) -> Range

    Initialize a Range from a cdata addrxlat_range_t *.'''
    return Range(ptr.endoff, ptr.meth)

###
### addrxlat_map_t
###

class Map(object):
    '''Map([ptr]) -> map

    Wrapper for cdata addrxlat_map_t *.
    If ptr is omitted, allocate a new translation map.'''

    def __init__(self, ptr=None):
        if ptr is None:
            ptr = C.addrxlat_map_new()
            if not ptr:
                raise MemoryError('Could not allocate addrxlat_map_t')
        else:
            C.addrxlat_map_incref(ptr)
        self._cdata = ptr

    def __del__(self):
        C.addrxlat_map_decref(self._cdata)

    def __eq__(self, other):
        return self._cdata == other._cdata

    def __ne__(self, other):
        return not self == other

    def __len__(self):
        return C.addrxlat_map_len(self._cdata)

    def __getitem__(self, index):
        n = len(self)
        if index < 0:
            index = n + index
        if index >= n:
            raise IndexError('map index out of range')

        ranges = C.addrxlat_map_ranges(self._cdata)
        return RangeFromCData(ranges + index)

    def set(self, addr, range):
        '''MAP.set(addr, range) -> status\n\

        Modify map so that addresses between addr and addr+range.off
        (inclusive) are mapped using range.meth.'''
        status = C.addrxlat_map_set(self._cdata, addr, range._cdata)
        if status != OK:
            raise get_exception(status)

    def search(self, addr):
        '''MAP.search(addr) -> meth

        Find the translation method for the given address.'''
        return C.addrxlat_map_search(self._cdata, addr)

    def copy(self):
        '''M.copy() -> map

        Return a shallow copy of a translation map.'''
        map = C.addrxlat_map_copy(self._cdata)
        if not map:
            raise MemoryError('Could not copy map')
        result = Map(map)
        C.addrxlat_map_decref(map)
        return result

###
### addrxlat_sys_t
###

_options = {
    'arch': (C.addrxlat_opt_arch, utils.to_bytes),
    'os_type': (C.addrxlat_opt_os_type, utils.to_bytes),
    'version_code': (C.addrxlat_opt_version_code, None),
    'phys_bits': (C.addrxlat_opt_phys_bits, None),
    'virt_bits': (C.addrxlat_opt_virt_bits, None),
    'page_shift': (C.addrxlat_opt_page_shift, None),
    'phys_base': (C.addrxlat_opt_phys_base, None),
    'rootpgt': (C.addrxlat_opt_rootpgt, lambda a: a._cdata),
    'xen_p2m_mfn': (C.addrxlat_opt_xen_p2m_mfn, None),
    'xen_xlat': (C.addrxlat_opt_xen_xlat, None),
}

class System(object):
    '''SystemBase([ptr]) -> sys

    Wrapper for cdata addrxlat_sys_t *.
    If ptr is omitted, allocate a new translation system.'''

    def __init__(self, ptr=None):
        if ptr is None:
            ptr = C.addrxlat_sys_new()
            if not ptr:
                raise MemoryError('Could not allocate addrxlat_sys_t')
        else:
            C.addrxlat_sys_incref(ptr)
        self._cdata = ptr

    def __del__(self):
        C.addrxlat_sys_decref(self._cdata)

    def __repr__(self):
        return '%s()' % (self.__class__.__name__)

    def __eq__(self, other):
        return self._cdata == other._cdata

    def __ne__(self, other):
        return not self == other

    def os_init(self, ctx, **kwargs):
        '''SYS.os_init(...) -> status

        Set up a translation system for a pre-defined operating system.'''

        opts = ffi.new('addrxlat_opt_t[]', len(kwargs))
        num = 0

        tmp_values = []
        for opt, value in kwargs.items():
            func, conv = _options[opt]
            if conv is not None:
                value = conv(value)
                tmp_values.append(value)
            func(opts + num, value)
            num += 1

        status = C.addrxlat_sys_os_init(self._cdata, ctx._cdata, num, opts)
        return _status_result(ctx, status, None)

    def set_map(self, idx, map):
        '''SYS.set_map(idx, map)

        Explicitly set the given translation map of a translation system.
        See SYS_MAP_xxx for valid values of idx.'''
        if idx >= SYS_MAP_NUM:
            raise IndexError('system map index out of range')

        C.addrxlat_sys_set_map(self._cdata, idx, map._cdata);

    def get_map(self, idx):
        '''SYS.get_map(idx) -> Map or None

        Get the given translation map of a translation system.
        See SYS_MAP_xxx for valid values of idx.'''

        if idx >= SYS_MAP_NUM:
            raise IndexError('system map index out of range')

        map = C.addrxlat_sys_get_map(self._cdata, idx)
        if not map:
            return None
        else:
            return Map(map)

    def set_meth(self, idx, meth):
        '''SYS.set_meth(idx, meth)

        Explicitly set a pre-defined translation method of a translation
        system.
        See SYS_METH_xxx for valid values of idx.'''

        if idx >= SYS_METH_NUM:
            raise IndexError('system meth index out of range')

        C.addrxlat_sys_set_meth(self._cdata, idx, meth._cdata)

    def get_meth(self, idx):
        '''SYS.get_meth(idx) -> Method

        Get the given translation method of a translation system.
        See SYS_METH_xxx for valid values of idx.'''

        if idx >= SYS_METH_NUM:
            raise IndexError('system method index out of range')

        meth = C.addrxlat_sys_get_meth(self._cdata, idx)
        return MethodFromCData(meth)

class Step(object):
    '''Step(ctx) -> step'''

    def __init__(self, ctx=None, sys=None, meth=None, remain=0, elemsz=0, base=no_address, raw=None, idx=()):
        self.__cdata = ffi.new('addrxlat_step_t*')
        self.ctx = ctx
        self.sys = sys
        self.meth = meth
        self.remain = remain
        self.elemsz = elemsz
        self.base = base
        if raw is not None:
            self.raw = raw
        if idx is not None:
            self.idx = idx

    def __repr__(self):
        return '%s(%r, %r, %r, %r, %r, %r, %r, %r)' % (
            self.__class__.__name__,
            self.ctx,
            self.sys,
            self.meth,
            self.remain,
            self.elemsz,
            self.base,
            self.raw,
            self.idx)

    @property
    def _cdata(self):
        '''raw cdata representation of the Step object'''
        self.__cdata.base = self._base._cdata[0]
        return self.__cdata

    @property
    def ctx(self):
        '''translation context for the next step'''
        return self._ctx

    @ctx.setter
    def ctx(self, value):
        self._ctx = value
        self.__cdata.ctx = _cdata_or_null(value)

    @property
    def sys(self):
        '''translation system for the next step'''
        return self._sys

    @sys.setter
    def sys(self, value):
        self._sys = value
        self.__cdata.sys = _cdata_or_null(value)

    @property
    def meth(self):
        '''translation method for the next step'''
        return self._meth

    @meth.setter
    def meth(self, value):
        self._meth = value
        self.__cdata.meth = _cdata_or_null(value)

    @property
    def remain(self):
        '''remaining steps'''
        return self._cdata.remain

    @remain.setter
    def remain(self, value):
        self.__cdata.remain = value

    @property
    def elemsz(self):
        '''size of the indexed element'''
        return self.__cdata.elemsz

    @elemsz.setter
    def elemsz(self, value):
        self.__cdata.elemsz = value

    @property
    def base(self):
        '''base address for next translation step'''
        return self._base

    @base.setter
    def base(self, value):
        self._base = value
        self.__cdata.base = value._cdata[0]

    @property
    def raw(self):
        '''raw value from last step'''
        if not self.__cdata.meth:
            return None
        kind = self.__cdata.meth.kind
        if kind == CUSTOM:
            return self.__cdata.raw.data
        elif kind == PGT:
            return self.__cdata.raw.pte
        elif kind == LOOKUP:
            elem = self.__cdata.raw.elem
            return (elem.orig, elem.dest)
        elif kind == MEMARR:
            return self.__cdata.raw.addr
        else:
            return None

    @raw.setter
    def raw(self, value):
        cdata = self.__cdata
        if not cdata.meth:
            raise AttributeError()
        kind = self.__cdata.meth.kind
        if kind == CUSTOM:
            cdata.raw.data = value
        elif kind == PGT:
            cdata.raw.pte = value
        elif kind == LOOKUP:
            elem = cffi.addressof(cdata.raw.elem)
            elem.orig, elem.dest = value
        elif kind == MEMARR:
            cdata.raw.addr = value
        else:
            raise TypeError('attribute cannot be changed for this method')

    @property
    def idx(self):
        '''sizes of address parts in bits'''
        cdata = self.__cdata
        return tuple(i for i in cdata.idx)

    @idx.setter
    def idx(self, value):
        self.__cdata.idx = value

    def launch(self, addr):
        '''STEP.launch(addr) -> status

        Make the first translation step (launch a translation).'''
        status = C.addrxlat_launch(self.__cdata, addr)
        return _status_result(self.ctx, status, None)

    def step(self):
        '''STEP.step() -> status

        Perform one translation step.'''
        status = C.addrxlat_step(self.__cdata)
        return _status_result(self.ctx, status, None)

    def walk(self):
        '''STEP.walk() -> status\n\

        Perform one complete address translation.'''
        status = C.addrxlat_walk(self._cdata)
        return _status_result(self.ctx, status, None)

def StepFromCData(ptr):
    '''StepFromCData(ptr) -> Step

    Initialize a Step from a cdata addrxlat_step_t *.'''
    ctx = Context(ptr.ctx)
    if not ptr.sys:
        sys = None
    else:
        sys = System(ptr.sys)
    raw = None
    if not ptr.meth:
        meth = None
    else:
        meth = MethodFromCData(ptr.meth)
        if meth.kind == CUSTOM:
            raw = ptr.raw.data
        elif meth.kind == PGT:
            raw = ptr.raw.pte
        elif meth.kind == LOOKUP:
            raw = ptr.raw.elem
        elif meth.kind == MEMARR:
            raw = ptr.raw.addr
    base = FullAddressFromCData(ptr.base)
    return Step(ctx, sys, meth, ptr.remain, ptr.elemsz, base, raw, ptr.idx)

class Operator(object):
    '''Operator(ctx) -> op

    Base class for generic addrxlat operations.'''

    def __init__(self, ctx=None, sys=None, caps=0):
        self._cdata = ffi.new('addrxlat_op_ctl_t*')
        self._handle = ffi.new_handle(self)
        self._cdata.data = self._handle
        self._cdata.op = C._cb_op
        self.ctx = ctx
        self.sys = sys
        self.caps = caps
        self.result = None

    def __repr__(self):
        return '%s(%r, %r)' % (
            self.__class__.__name__,
            self.ctx,
            self.sys,
            self.caps)

    def __call__(self, addr):
        status = C.addrxlat_op(self._cdata, addr._cdata)
        return _status_result(self.ctx, status, self.result)

    @property
    def ctx(self):
        '''translation context'''
        return self._ctx

    @ctx.setter
    def ctx(self, value):
        self._ctx = value
        self._cdata.ctx = _cdata_or_null(value)

    @property
    def sys(self):
        '''translation system'''
        return self._sys

    @sys.setter
    def sys(self, value):
        self._sys = value
        self._cdata.sys = _cdata_or_null(value)

    @property
    def caps(self):
        '''operation capabilities'''
        return self._cdata.caps

    @caps.setter
    def caps(self, value):
        self._cdata.caps = value

    def _cb_op(self, addr):
        addr = FullAddressFromCData(addr)
        self.result = self.callback(addr)
        return OK

    def callback(self, addr):
        '''operation callback'''
        pass
