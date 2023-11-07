from os import path
from cffi import FFI

ffi = FFI()

header_file = path.join(path.dirname(__file__), "addrxlat.h")
with open(header_file) as f:
    ffi.cdef(f.read())
ffi.cdef("""
/* The lookup table must be allocated by libc allocators.
 * Expose them here.
 */
void *malloc(size_t size);
void free(void *ptr);

/* Callbacks. */
extern "Python" {
    addrxlat_cb_reg_value_fn _cb_reg_value;
    addrxlat_cb_sym_value_fn _cb_sym_value;
    addrxlat_cb_sym_sizeof_fn _cb_sym_sizeof;
    addrxlat_cb_sym_offsetof_fn _cb_sym_offsetof;
    addrxlat_cb_num_value_fn _cb_num_value;
    addrxlat_get_page_fn _cb_get_page;
    addrxlat_put_page_fn _cb_put_page;
    addrxlat_read_caps_fn _cb_read_caps;
    addrxlat_first_step_fn _cb_first_step;
    addrxlat_next_step_fn _cb_next_step;
    addrxlat_op_fn _cb_op;
}
""")
ffi.set_source(
    '_addrxlat',
    '''
#include <libkdumpfile/kdumpfile.h>
#include <stdlib.h>
''',
    libraries = [
        'addrxlat',
    ],
)

if __name__ == '__main__':
    ffi.compile()
