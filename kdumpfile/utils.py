'''kdumpfile.utils
'''

import sys

if sys.version_info[0] == 3:
    from .defs_py3 import *
else:
    from .defs_py2 import *

def to_bytes(s):
    if isinstance(s, binary_type):
        return s
    return unicode_type(s).encode("utf-8")

def to_unicode(s):
    if isinstance(s, unicode_type):
        return s
    return binary_type(s).decode("utf-8")
