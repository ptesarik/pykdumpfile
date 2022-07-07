'''addrxlat.defs_py2
'''

unicode_type = unicode
binary_type = str

def restore_exception(exc, val, tb):
    raise exc, val, tb
