'''kdumpfile.const
'''

###
### Constants
###

from _kdumpfile import lib as C

# versioning
VER_MAJOR = C.KDUMPFILE_VER_MAJOR
VER_MINOR = C.KDUMPFILE_VER_MINOR
VER_MICRO = C.KDUMPFILE_VER_MICRO
VERSION = C.KDUMPFILE_VERSION

#kdump_status
OK = C.KDUMP_OK
ERR_SYSTEM = C.KDUMP_ERR_SYSTEM
ERR_NOTIMPL = C.KDUMP_ERR_NOTIMPL
ERR_NODATA = C.KDUMP_ERR_NODATA
ERR_CORRUPT = C.KDUMP_ERR_CORRUPT
ERR_INVALID = C.KDUMP_ERR_INVALID
ERR_NOKEY = C.KDUMP_ERR_NOKEY
ERR_EOF = C.KDUMP_ERR_EOF
ERR_BUSY = C.KDUMP_ERR_BUSY
ERR_ADDRXLAT = C.KDUMP_ERR_ADDRXLAT

# kdump_addr_t
ADDR_MAX = C.KDUMP_ADDR_MAX

# kdump_byte_order_t
BIG_ENDIAN = C.KDUMP_BIG_ENDIAN
LITTLE_ENDIAN = C.KDUMP_LITTLE_ENDIAN

# kdump_mmap_policy_t
MMAP_NEVER = C.KDUMP_MMAP_NEVER
MMAP_ALWAYS = C.KDUMP_MMAP_ALWAYS
MMAP_TRY = C.KDUMP_MMAP_TRY
MMAP_TRY_ONCE = C.KDUMP_MMAP_TRY_ONCE

# kdump_xen_type_t
XEN_NONE = C.KDUMP_XEN_NONE
XEN_SYSTEM = C.KDUMP_XEN_SYSTEM
XEN_DOMAIN = C.KDUMP_XEN_DOMAIN

# kdump_xen_xlat_t
XEN_AUTO = C.KDUMP_XEN_AUTO
XEN_NONAUTO = C.KDUMP_XEN_NONAUTO

# enum kdump_clone_bits
CLONE_BIT_XLAT = C.KDUMP_CLONE_BIT_XLAT

CLONE_XLAT = C.KDUMP_CLONE_XLAT

# kdump_addrspace_t
KPHYSADDR = C.KDUMP_KPHYSADDR
MACHPHYSADDR = C.KDUMP_MACHPHYSADDR
KVADDR = C.KDUMP_KVADDR
NOADDR = C.KDUMP_NOADDR

# kdump_attr_type_t
NIL = C.KDUMP_NIL
DIRECTORY = C.KDUMP_DIRECTORY
NUMBER = C.KDUMP_NUMBER
ADDRESS = C.KDUMP_ADDRESS
STRING = C.KDUMP_STRING
BITMAP = C.KDUMP_BITMAP
BLOB = C.KDUMP_BLOB

# well-known attributes
ATTR_FILE_FD = "file.fd"
ATTR_FILE_FORMAT = "file.format"
ATTR_FILE_PAGEMAP = "file.pagemap"
ATTR_ARCH_NAME = "arch.name"
ATTR_BYTE_ORDER = "arch.byte_order"
ATTR_PTR_SIZE = "arch.ptr_size"
ATTR_PAGE_SIZE = "arch.page_size"
ATTR_PAGE_SHIFT = "arch.page_shift"
ATTR_NUM_CPUS = "cpu.number"
ATTR_OSTYPE = "addrxlat.ostype"
ATTR_XLAT_DEFAULT = "addrxlat.default"
ATTR_XLAT_FORCE = "addrxlat.force"
ATTR_XEN_TYPE = "xen.type"
ATTR_XEN_XLAT = "xen.xlat"
ATTR_LINUX_VERSION_CODE = "linux.version_code"
ATTR_XEN_VERSION_CODE = "xen.version_code"
ATTR_XEN_PHYS_START = "xen.phys_start"
ATTR_ZERO_EXCLUDED = "file.zero_excluded"
ATTR_FILE_MMAP_POLICY = "file.mmap_policy"

# canonical architecture names
ARCH_AARCH64 = "aarch64"
ARCH_ALPHA = "alpha"
ARCH_ARM = "arm"
ARCH_IA32 = "ia32"
ARCH_IA64 = "ia64"
ARCH_MIPS = "mips"
ARCH_PPC = "ppc"
ARCH_PPC64 = "ppc64"
ARCH_S390 = "s390"
ARCH_S390X = "s390x"
ARCH_X86_64 = "x86_64"
