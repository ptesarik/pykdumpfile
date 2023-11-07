'''addrxlat.const
'''

###
### Constants
###

from _addrxlat import lib as C

# versioning
VER_MAJOR = C.ADDRXLAT_VER_MAJOR
VER_MINOR = C.ADDRXLAT_VER_MINOR
VER_MICRO = C.ADDRXLAT_VER_MICRO
VERSION = C.ADDRXLAT_VERSION

# addrxlat_status
OK = C.ADDRXLAT_OK
ERR_NOTIMPL = C.ADDRXLAT_ERR_NOTIMPL
ERR_NOTPRESENT = C.ADDRXLAT_ERR_NOTPRESENT
ERR_INVALID = C.ADDRXLAT_ERR_INVALID
ERR_NOMEM = C.ADDRXLAT_ERR_NOMEM
ERR_NODATA = C.ADDRXLAT_ERR_NODATA
ERR_NOMETH = C.ADDRXLAT_ERR_NOMETH
ERR_CUSTOM_BASE = C.ADDRXLAT_ERR_CUSTOM_BASE

# addrxlat_addr_t
ADDR_MAX = C.ADDRXLAT_ADDR_MAX

# addrxlat_addrspace_t
KPHYSADDR = C.ADDRXLAT_KPHYSADDR
MACHPHYSADDR = C.ADDRXLAT_MACHPHYSADDR
KVADDR = C.ADDRXLAT_KVADDR
NOADDR = C.ADDRXLAT_NOADDR

# addrxlat_byte_order_t
BIG_ENDIAN = C.ADDRXLAT_BIG_ENDIAN
LITTLE_ENDIAN = C.ADDRXLAT_LITTLE_ENDIAN
HOST_ENDIAN = C.ADDRXLAT_HOST_ENDIAN

# addrxlat_kind_t
NOMETH = C.ADDRXLAT_NOMETH
CUSTOM = C.ADDRXLAT_CUSTOM
LINEAR = C.ADDRXLAT_LINEAR
PGT = C.ADDRXLAT_PGT
LOOKUP = C.ADDRXLAT_LOOKUP
MEMARR = C.ADDRXLAT_MEMARR

# addrxlat_pte_format_t
PTE_INVALID = C.ADDRXLAT_PTE_INVALID
PTE_NONE = C.ADDRXLAT_PTE_NONE
PTE_PFN32 = C.ADDRXLAT_PTE_PFN32
PTE_PFN64 = C.ADDRXLAT_PTE_PFN64
PTE_AARCH64 = C.ADDRXLAT_PTE_AARCH64
PTE_IA32 = C.ADDRXLAT_PTE_IA32
PTE_IA32_PAE = C.ADDRXLAT_PTE_IA32_PAE
PTE_X86_64 = C.ADDRXLAT_PTE_X86_64
PTE_S390X = C.ADDRXLAT_PTE_S390X
PTE_PPC64_LINUX_RPN30 = C.ADDRXLAT_PTE_PPC64_LINUX_RPN30
PTE_AARCH64_LPA = C.ADDRXLAT_PTE_AARCH64_LPA
PTE_AARCH64_LPA2 = C.ADDRXLAT_PTE_AARCH64_LPA2
PTE_ARM = C.ADDRXLAT_PTE_ARM

# other paging form constants
FIELDS_MAX = C.ADDRXLAT_FIELDS_MAX

# addrxlat_sys_meth_t
SYS_METH_NONE = C.ADDRXLAT_SYS_METH_NONE
SYS_METH_PGT = C.ADDRXLAT_SYS_METH_PGT
SYS_METH_UPGT = C.ADDRXLAT_SYS_METH_UPGT
SYS_METH_DIRECT = C.ADDRXLAT_SYS_METH_DIRECT
SYS_METH_KTEXT = C.ADDRXLAT_SYS_METH_KTEXT
SYS_METH_VMEMMAP = C.ADDRXLAT_SYS_METH_VMEMMAP
SYS_METH_RDIRECT = C.ADDRXLAT_SYS_METH_RDIRECT
SYS_METH_MACHPHYS_KPHYS = C.ADDRXLAT_SYS_METH_MACHPHYS_KPHYS
SYS_METH_KPHYS_MACHPHYS = C.ADDRXLAT_SYS_METH_KPHYS_MACHPHYS
SYS_METH_CUSTOM = C.ADDRXLAT_SYS_METH_CUSTOM
SYS_METH_CUSTOM_NUM = C.ADDRXLAT_SYS_METH_CUSTOM_NUM
SYS_METH_NUM = C.ADDRXLAT_SYS_METH_NUM

# addrxlat_optidx_t
OPT_NULL = C.ADDRXLAT_OPT_NULL
OPT_arch = C.ADDRXLAT_OPT_arch
OPT_os_type = C.ADDRXLAT_OPT_os_type
OPT_version_code = C.ADDRXLAT_OPT_version_code
OPT_phys_bits = C.ADDRXLAT_OPT_phys_bits
OPT_virt_bits = C.ADDRXLAT_OPT_virt_bits
OPT_page_shift = C.ADDRXLAT_OPT_page_shift
OPT_phys_base = C.ADDRXLAT_OPT_phys_base
OPT_rootpgt = C.ADDRXLAT_OPT_rootpgt
OPT_xen_p2m_mfn = C.ADDRXLAT_OPT_xen_p2m_mfn
OPT_xen_xlat = C.ADDRXLAT_OPT_xen_xlat
OPT_NUM = C.ADDRXLAT_OPT_NUM

# addrxlat_sys_map_t
SYS_MAP_HW = C.ADDRXLAT_SYS_MAP_HW
SYS_MAP_KV_PHYS = C.ADDRXLAT_SYS_MAP_KV_PHYS
SYS_MAP_KPHYS_DIRECT = C.ADDRXLAT_SYS_MAP_KPHYS_DIRECT
SYS_MAP_MACHPHYS_KPHYS = C.ADDRXLAT_SYS_MAP_MACHPHYS_KPHYS
SYS_MAP_KPHYS_MACHPHYS = C.ADDRXLAT_SYS_MAP_KPHYS_MACHPHYS
SYS_MAP_NUM = C.ADDRXLAT_SYS_MAP_NUM
