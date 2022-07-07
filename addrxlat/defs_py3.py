'''addrxlat.defs_py3
'''

unicode_type = str
binary_type = bytes

def restore_exception(exc, val, tb):
    raise exc(val).with_traceback(tb)
