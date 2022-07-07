from os import path
from cffi import FFI

ffi = FFI()

for header in ('addrxlat.h', 'kdumpfile.h'):
    header_file = path.join(path.dirname(__file__), header)
    with open(header_file) as f:
        ffi.cdef(f.read())

ffi.cdef("""
/* Blob data must be allocated by libc allocators.
 * Expose them here.
 */
void *malloc(size_t size);
void free(void *ptr);

extern "Python" {
}
""")
ffi.set_source(
    '_kdumpfile',
    '''
#include <libkdumpfile/kdumpfile.h>
#include <stdlib.h>
''',
    libraries = [
        'kdumpfile',
    ],
)

if __name__ == '__main__':
    ffi.compile()
