'''addrxlat.exceptions
'''

from .constants import *
from .utils import to_unicode
from _addrxlat import ffi, lib as C

def strerror(status):
    '''strerror(status) -> error message

    Return the string describing a given error status.'''
    return to_unicode(ffi.string(C.addrxlat_strerror(status)))

class AddrxlatError(Exception):
    '''Common base for all addrxlat exceptions.

    AddrxlatError(status[, message])

    If message is not specified, use addrxlat_strerror(status).

    Attributes:
      status   addrxlat status code, see ERR_xxx
      message  verbose error message'''

    def __init__(self, status, message=None):
        if message is None:
            message = strerror(status)
        super(AddrxlatError, self).__init__(message)
        self.status = status
        self.message = message

def _def_exception(name, status, addbases=()):
    '''Create an addrxlat exception for a given status code.
    The new exception is derived from AddrxlatError, but you may specify
    additional base classes with addbases.
    '''

    def __init__(self, *args, **kwargs):
        super(cls, self).__init__(status, *args, **kwargs)

    def __repr__(self):
        "x.__repr__() <==> repr(x)"
        return "%s%r" % (self.__class__.__name__, self.args[1:])

    di = {
        '__doc__' : name + '([message])' + '''

        If message is not specified, use the default error message.
        ''',
        'status' : status,
        '__init__' : __init__,
        '__repr__' : __repr__,
    }

    cls = type(name, (AddrxlatError,) + addbases, di)
    return cls

_exceptions = {
    ('NotImplementedError', ERR_NOTIMPL, (NotImplementedError,)),
    ('NotPresentError', ERR_NOTPRESENT),
    ('InvalidError', ERR_INVALID),
    ('MemoryError', ERR_NOMEM, (MemoryError,)),
    ('NoDataError', ERR_NODATA),
    ('NoMethodError', ERR_NOMETH),
}

_exc_map = {}
for _exc in _exceptions:
    _cls = _def_exception(*_exc)
    globals()[_cls.__name__] = _cls
    _exc_map[_cls.status] = _cls

# Free up init-time variables
del _exc, _cls, _exceptions, _def_exception

def get_exception(status, *args, **kwargs):
    '''get_exception(status[, message])

    Get an appropriate exception for the given status. If there is no
    specific exception, make an instance of AddrxlatError.
    '''
    exc = _exc_map.get(status)
    if exc is not None:
        return exc(*args, **kwargs)
    return AddrxlatError(status, *args, **kwargs)

