from setuptools import Extension, setup

import sys
sys.path.append('')
import ffi_addrxlat
import ffi_kdumpfile

setup(
    ext_modules=[
        ffi_addrxlat.ffi.distutils_extension(),
        ffi_kdumpfile.ffi.distutils_extension(),
    ],
)
