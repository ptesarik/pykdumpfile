'''kdumpfile.exceptions
'''

from .constants import *
from .utils import to_unicode
from _kdumpfile import ffi, lib as C

def strerror(status):
    '''strerror(status) -> error message

    Return the string describing a given error status.'''
    return to_unicode(ffi.string(C.kdump_strerror(status)))

class KdumpfileError(Exception):
    '''Common base for all kdumpfile exceptions.

    KdumpfileError(status[, message])

    If message is not specified, use kdumpfile_strerror(status).

    Attributes:
      status   kdumpfile status code, see ERR_xxx
      message  verbose error message'''

    def __init__(self, status, message=None):
        if message is None:
            message = strerror(status)
        super(KdumpfileError, self).__init__(message)
        self.status = status
        self.message = message

def _def_exception(name, status, addbases=()):
    '''Create an kdumpfile exception for a given status code.
    The new exception is derived from KdumpfileError, but you may specify
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

    cls = type(name, (KdumpfileError,) + addbases, di)
    return cls

_exceptions = {
    ('SystemError', ERR_SYSTEM,	(OSError,)),
    ('NotImplementedError', ERR_NOTIMPL, (NotImplementedError,)),
    ('NoDataError', ERR_NODATA),
    ('CorruptError', ERR_CORRUPT),
    ('InvalidError', ERR_INVALID),
    ('NoKeyError', ERR_NOKEY, (KeyError,)),
    ('EOFError', ERR_EOF, (EOFError,)),
    ('BusyError', ERR_BUSY),
    ('AddressTranslationError', ERR_ADDRXLAT),
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
    specific exception, make an instance of KdumpfileError.
    '''
    exc = _exc_map.get(status)
    if exc is not None:
        return exc(*args, **kwargs)
    return KdumpfileError(status, *args, **kwargs)
