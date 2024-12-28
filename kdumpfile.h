/* Copyright (C) 2022 Petr Tesarik <ptesarik@suse.com>

   This file is free software; you can redistribute it and/or modify
   it under the terms of either

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at
       your option) any later version

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at
       your option) any later version

   or both in parallel, as here.

   pykdumpfile is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see <http://www.gnu.org/licenses/>.
*/

/* The rest of this file is adapted from the public header.
 * Matching libkdumpfile commit:
 * 5b044292abe9cbfed0d33f2acf1ed1f43e1364f8
 */

#define KDUMPFILE_VER_MAJOR	...
#define KDUMPFILE_VER_MINOR	...
#define KDUMPFILE_VER_MICRO	...

#define KDUMPFILE_VERSION	...

typedef uint_fast64_t kdump_num_t;

typedef addrxlat_addr_t kdump_addr_t;
#define KDUMP_ADDR_MAX	...

typedef kdump_addr_t kdump_paddr_t;
typedef kdump_addr_t kdump_vaddr_t;

typedef struct _kdump_ctx kdump_ctx_t;

typedef enum _kdump_status {
	KDUMP_OK = 0,
	KDUMP_ERR_SYSTEM,
	KDUMP_ERR_NOTIMPL,
	KDUMP_ERR_NODATA,
	KDUMP_ERR_CORRUPT,
	KDUMP_ERR_INVALID,
	KDUMP_ERR_NOKEY,
	KDUMP_ERR_EOF,
	KDUMP_ERR_BUSY,
	KDUMP_ERR_ADDRXLAT,
} kdump_status;

typedef enum _kdump_byte_order {
	KDUMP_BIG_ENDIAN = ADDRXLAT_BIG_ENDIAN,
	KDUMP_LITTLE_ENDIAN = ADDRXLAT_LITTLE_ENDIAN,
} kdump_byte_order_t;

typedef enum _kdump_mmap_policy {
	KDUMP_MMAP_NEVER,
	KDUMP_MMAP_ALWAYS,
	KDUMP_MMAP_TRY,

	KDUMP_MMAP_TRY_ONCE,
} kdump_mmap_policy_t;

typedef enum _kdump_xen_type {
	KDUMP_XEN_NONE,
	KDUMP_XEN_SYSTEM,
	KDUMP_XEN_DOMAIN,
} kdump_xen_type_t;

typedef enum _kdump_xen_xlat {
	KDUMP_XEN_AUTO,
	KDUMP_XEN_NONAUTO,
} kdump_xen_xlat_t;

kdump_ctx_t *kdump_new(void);

enum kdump_clone_bits {
	KDUMP_CLONE_BIT_XLAT,
};
#define KDUMP_CLONE_XLAT	...
kdump_ctx_t *kdump_clone(const kdump_ctx_t *orig, unsigned long flags);

void kdump_free(kdump_ctx_t *ctx);

kdump_status kdump_err(kdump_ctx_t *ctx, kdump_status status, const char *msgfmt, ...);
void kdump_clear_err(kdump_ctx_t *ctx);
const char *kdump_get_err(kdump_ctx_t *ctx);

kdump_status kdump_get_addrxlat(kdump_ctx_t *ctx,
				addrxlat_ctx_t **axctx,
				addrxlat_sys_t **axsys);

uint_fast16_t kdump_d16toh(kdump_ctx_t *ctx, uint_fast16_t val);
uint_fast32_t kdump_d32toh(kdump_ctx_t *ctx, uint_fast32_t val);
uint_fast64_t kdump_d64toh(kdump_ctx_t *ctx, uint_fast64_t val);

kdump_status kdump_set_filenames(kdump_ctx_t *ctx, unsigned n,
				 const char *const *names);
kdump_status kdump_set_filename(kdump_ctx_t *ctx, const char *name);

kdump_status kdump_open_fdset(kdump_ctx_t *ctx, unsigned nfds, const int *fds);
kdump_status kdump_open_fd(kdump_ctx_t *ctx, int fd);

typedef enum _kdump_addrspace {
	KDUMP_KPHYSADDR = ADDRXLAT_KPHYSADDR,
	KDUMP_MACHPHYSADDR = ADDRXLAT_MACHPHYSADDR,
	KDUMP_KVADDR = ADDRXLAT_KVADDR,
	KDUMP_NOADDR = ADDRXLAT_NOADDR,
} kdump_addrspace_t;

kdump_status kdump_read(kdump_ctx_t *ctx,
			 kdump_addrspace_t as, kdump_addr_t addr,
			 void *buffer, size_t *plength);
kdump_status kdump_read_string(kdump_ctx_t *ctx,
			       kdump_addrspace_t as, kdump_addr_t addr,
			       char **pstr);

typedef struct _kdump_bmp kdump_bmp_t;
unsigned long kdump_bmp_incref(kdump_bmp_t *bmp);
unsigned long kdump_bmp_decref(kdump_bmp_t *bmp);
const char *kdump_bmp_get_err(const kdump_bmp_t *bmp);
kdump_status kdump_bmp_get_bits(
	kdump_bmp_t *bmp,
	kdump_addr_t first, kdump_addr_t last, unsigned char *raw);
kdump_status kdump_bmp_find_set(
	kdump_bmp_t *bmp, kdump_addr_t *idx);
kdump_status kdump_bmp_find_clear(
	kdump_bmp_t *bmp, kdump_addr_t *idx);

typedef struct _kdump_blob kdump_blob_t;
kdump_blob_t *kdump_blob_new(void *data, size_t size);
kdump_blob_t *kdump_blob_new_dup(const void *data, size_t size);
unsigned long kdump_blob_incref(kdump_blob_t *blob);
unsigned long kdump_blob_decref(kdump_blob_t *blob);
void *kdump_blob_pin(kdump_blob_t *blob);
unsigned long kdump_blob_unpin(kdump_blob_t *blob);
size_t kdump_blob_size(const kdump_blob_t *blob);
kdump_status kdump_blob_set(kdump_blob_t *blob, void *data, size_t size);

typedef enum _kdump_attr_type {
	KDUMP_NIL,
	KDUMP_DIRECTORY,
	KDUMP_NUMBER,
	KDUMP_ADDRESS,
	KDUMP_STRING,
	KDUMP_BITMAP,
	KDUMP_BLOB,
} kdump_attr_type_t;

typedef union _kdump_attr_value {
	kdump_num_t number;
	kdump_addr_t address;
	const char *string;
	kdump_bmp_t *bitmap;
	kdump_blob_t *blob;
} kdump_attr_value_t;

typedef struct _kdump_attr {
	kdump_attr_type_t type;
	kdump_attr_value_t val;
} kdump_attr_t;

typedef struct _kdump_attr_ref {
	void *_ptr;
} kdump_attr_ref_t;

typedef struct _kdump_attr_iter {
	const char *key;
	kdump_attr_ref_t pos;
} kdump_attr_iter_t;

kdump_status kdump_set_attr(kdump_ctx_t *ctx, const char *key,
			    const kdump_attr_t *valp);
kdump_status kdump_set_number_attr(kdump_ctx_t *ctx, const char *key, kdump_num_t num);
kdump_status kdump_set_address_attr(kdump_ctx_t *ctx, const char *key, kdump_addr_t addr);
kdump_status kdump_set_string_attr(kdump_ctx_t *ctx, const char *key, const char *str);
kdump_status kdump_clear_attr(kdump_ctx_t *ctx, const char *key);
kdump_status kdump_get_attr(kdump_ctx_t *ctx, const char *key,
			    kdump_attr_t *valp);
kdump_status kdump_get_typed_attr(kdump_ctx_t *ctx, const char *key,
				  kdump_attr_type_t type,
				  kdump_attr_value_t *valp);
kdump_status kdump_get_number_attr(kdump_ctx_t *ctx, const char *key, kdump_num_t *num);
kdump_status kdump_get_address_attr(kdump_ctx_t *ctx, const char *key, kdump_addr_t *addr);
kdump_status kdump_get_string_attr(kdump_ctx_t *ctx, const char *key, const char **str);
kdump_status kdump_attr_ref(kdump_ctx_t *ctx, const char *key,
			    kdump_attr_ref_t *ref);
kdump_status kdump_sub_attr_ref(kdump_ctx_t *ctx, const kdump_attr_ref_t *base,
				const char *subkey, kdump_attr_ref_t *ref);
void kdump_attr_unref(kdump_ctx_t *ctx, kdump_attr_ref_t *ref);
kdump_attr_type_t kdump_attr_ref_type(kdump_attr_ref_t *ref);
int kdump_attr_ref_isset(kdump_attr_ref_t *ref);
kdump_status kdump_attr_ref_get(kdump_ctx_t *ctx, const kdump_attr_ref_t *ref,
				kdump_attr_t *valp);
void kdump_attr_discard(kdump_ctx_t *ctx, kdump_attr_t *attr);
kdump_status kdump_attr_ref_set(kdump_ctx_t *ctx, kdump_attr_ref_t *ref,
				const kdump_attr_t *valp);
kdump_status kdump_set_sub_attr(kdump_ctx_t *ctx, const kdump_attr_ref_t *base,
				const char *subkey, const kdump_attr_t *valp);
kdump_status kdump_attr_iter_start(kdump_ctx_t *ctx, const char *path,
				   kdump_attr_iter_t *iter);
kdump_status kdump_attr_ref_iter_start(kdump_ctx_t *ctx,
				       const kdump_attr_ref_t *ref,
				       kdump_attr_iter_t *iter);
kdump_status kdump_attr_iter_next(kdump_ctx_t *ctx, kdump_attr_iter_t *iter);
void kdump_attr_iter_end(kdump_ctx_t *ctx, kdump_attr_iter_t *iter);

kdump_status kdump_vmcoreinfo_raw(kdump_ctx_t *ctx, char **raw);
kdump_status kdump_vmcoreinfo_line(kdump_ctx_t *ctx, const char *key,
				   char **val);
kdump_status kdump_vmcoreinfo_symbol(kdump_ctx_t *ctx, const char *symname,
				     kdump_addr_t *symvalue);

const char *kdump_strerror(kdump_status status);
