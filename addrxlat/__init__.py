'''addrxlat
'''

from _addrxlat import ffi, lib as C

from .constants import *
from .exceptions import *
from .objects import *
from . import utils

###
### Version codes
###

def VER_LINUX(a, b, c):
    '''VER_LINUX(a, b, c) -> version code

    Calculate the Linux kernel version code.'''
    return C.ADDRXLAT_VER_LINUX(a, b, c)

def VER_XEN(major, minor):
    '''VER_XEN(major, minor) -> version code

    Calculate the Xen hypervisor version code.'''
    return C.ADDRXLAT_VER_XEN(major, minor)

###
### Other static functions
###

def addrspace_name(addrspace):
    '''addrspace_name(addrspace) -> name

    Return the name of an address space constant.'''
    return utils.to_unicode(ffi.string(C.addrxlat_addrspace_name(addrspace)))

def CAPS(addrspace):
    '''CAPS(addrspace) -> capability bitmask

    Translate an address space constant into a capability bitmask.'''
    return C.ADDRXLAT_CAPS(addrspace)

def pteval_shift(fmt):
    '''pteval_shift(fmt) -> bit shift

    Get the pteval shift for a PTE format.
    See PTE_xxx for valid values of fmt.'''
    return C.addrxlat_pteval_shift(fmt)

def sym_argc(type):
    '''sym_argc(type) -> number of arguments

    Get the number of arguments for a given type of symbolic info.
    See SYM_xxx for valid values of type.'''
    return C.addrxlat_sym_argc(type)
