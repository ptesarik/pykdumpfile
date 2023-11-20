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
 * 82f1795d9589706b1b8df338eb4a7dbd8180daba
 */

#define ADDRXLAT_VER_MAJOR	...
#define ADDRXLAT_VER_MINOR	...
#define ADDRXLAT_VER_MICRO	...

#define ADDRXLAT_VERSION	...

typedef enum _addrxlat_status {
	ADDRXLAT_OK = 0,
	ADDRXLAT_ERR_NOTIMPL,
	ADDRXLAT_ERR_NOTPRESENT,
	ADDRXLAT_ERR_INVALID,
	ADDRXLAT_ERR_NOMEM,
	ADDRXLAT_ERR_NODATA,
	ADDRXLAT_ERR_NOMETH,

	ADDRXLAT_ERR_CUSTOM_BASE = -1
} addrxlat_status;

const char *addrxlat_strerror(addrxlat_status status);

typedef uint_fast64_t addrxlat_addr_t;
#define ADDRXLAT_ADDR_MAX	...

typedef int_fast64_t addrxlat_off_t;
typedef uint_fast64_t addrxlat_pte_t;

typedef enum _addrxlat_addrspace {
	ADDRXLAT_KPHYSADDR,
	ADDRXLAT_MACHPHYSADDR,
	ADDRXLAT_KVADDR,

	ADDRXLAT_NOADDR = -1,
} addrxlat_addrspace_t;

const char *addrxlat_addrspace_name(addrxlat_addrspace_t as);

typedef struct _addrxlat_fulladdr {
	addrxlat_addr_t addr;
	addrxlat_addrspace_t as;
} addrxlat_fulladdr_t;

typedef struct _addrxlat_ctx addrxlat_ctx_t;

addrxlat_ctx_t *addrxlat_ctx_new(void);
unsigned long addrxlat_ctx_incref(addrxlat_ctx_t *ctx);
unsigned long addrxlat_ctx_decref(addrxlat_ctx_t *ctx);

addrxlat_status addrxlat_ctx_err(
	addrxlat_ctx_t *ctx, addrxlat_status status,
	const char *msgfmt, ...);
void addrxlat_ctx_clear_err(addrxlat_ctx_t *ctx);
const char *addrxlat_ctx_get_err(const addrxlat_ctx_t *ctx);

typedef struct _addrxlat_cb addrxlat_cb_t;

typedef addrxlat_status addrxlat_cb_reg_value_fn(
	const addrxlat_cb_t *cb, const char *name, addrxlat_addr_t *val);
typedef addrxlat_status addrxlat_cb_sym_value_fn(
	const addrxlat_cb_t *cb, const char *name, addrxlat_addr_t *val);
typedef addrxlat_status addrxlat_cb_sym_sizeof_fn(
	const addrxlat_cb_t *cb, const char *name, addrxlat_addr_t *val);
typedef addrxlat_status addrxlat_cb_sym_offsetof_fn(
	const addrxlat_cb_t *cb, const char *obj, const char *elem,
	addrxlat_addr_t *val);
typedef addrxlat_status addrxlat_cb_num_value_fn(
	const addrxlat_cb_t *cb, const char *name, addrxlat_addr_t *val);

typedef enum _addrxlat_byte_order {
	ADDRXLAT_BIG_ENDIAN,
	ADDRXLAT_LITTLE_ENDIAN,

	ADDRXLAT_HOST_ENDIAN = -1
} addrxlat_byte_order_t;

typedef struct _addrxlat_buffer addrxlat_buffer_t;

typedef void addrxlat_put_page_fn(const addrxlat_buffer_t *buf);

struct _addrxlat_buffer {
	addrxlat_fulladdr_t addr;
	const void *ptr;
	size_t size;
	addrxlat_byte_order_t byte_order;
	addrxlat_put_page_fn *put_page;
	void *priv;
};

typedef addrxlat_status addrxlat_get_page_fn(
	const addrxlat_cb_t *cb, addrxlat_buffer_t *buf);

typedef unsigned long addrxlat_read_caps_fn(const addrxlat_cb_t *cb);

unsigned long ADDRXLAT_CAPS(unsigned val);

struct _addrxlat_cb {
	const addrxlat_cb_t *next;
	void *priv;
	addrxlat_get_page_fn *get_page;
	addrxlat_read_caps_fn *read_caps;
	addrxlat_cb_reg_value_fn *reg_value;
	addrxlat_cb_sym_value_fn *sym_value;
	addrxlat_cb_sym_sizeof_fn *sym_sizeof;
	addrxlat_cb_sym_offsetof_fn *sym_offsetof;
	addrxlat_cb_num_value_fn *num_value;
};

addrxlat_cb_t *addrxlat_ctx_add_cb(addrxlat_ctx_t *ctx);
void addrxlat_ctx_del_cb(addrxlat_ctx_t *ctx, addrxlat_cb_t *cb);
const addrxlat_cb_t *addrxlat_ctx_get_cb(const addrxlat_ctx_t *ctx);

typedef enum _addrxlat_kind {
	ADDRXLAT_NOMETH,
	ADDRXLAT_CUSTOM,
	ADDRXLAT_LINEAR,
	ADDRXLAT_PGT,
	ADDRXLAT_LOOKUP,
	ADDRXLAT_MEMARR,
} addrxlat_kind_t;

typedef struct _addrxlat_step addrxlat_step_t;

typedef addrxlat_status addrxlat_first_step_fn(
	addrxlat_step_t *step, addrxlat_addr_t addr);

typedef addrxlat_status addrxlat_next_step_fn(addrxlat_step_t *step);

typedef struct _addrxlat_param_custom {
	addrxlat_first_step_fn *first_step;
	addrxlat_next_step_fn *next_step;
	void *data;
} addrxlat_param_custom_t;

typedef struct _addrxlat_param_linear {
	addrxlat_off_t off;
} addrxlat_param_linear_t;

typedef enum _addrxlat_pte_format {
	ADDRXLAT_PTE_INVALID = -1,
	ADDRXLAT_PTE_NONE,
	ADDRXLAT_PTE_PFN32,
	ADDRXLAT_PTE_PFN64,
	ADDRXLAT_PTE_AARCH64,
	ADDRXLAT_PTE_IA32,
	ADDRXLAT_PTE_IA32_PAE,
	ADDRXLAT_PTE_X86_64,
	ADDRXLAT_PTE_S390X,
	ADDRXLAT_PTE_PPC64_LINUX_RPN30,
	ADDRXLAT_PTE_AARCH64_LPA,
	ADDRXLAT_PTE_AARCH64_LPA2,
	ADDRXLAT_PTE_ARM,
	ADDRXLAT_PTE_RISCV32,
	ADDRXLAT_PTE_RISCV64,
} addrxlat_pte_format_t;

const char *addrxlat_pte_format_name(addrxlat_pte_format_t fmt);
addrxlat_pte_format_t addrxlat_pte_format(const char *name);

int addrxlat_pteval_shift(addrxlat_pte_format_t fmt);

#define ADDRXLAT_FIELDS_MAX	8

typedef struct _addrxlat_paging_form {
	addrxlat_pte_format_t pte_format;
	unsigned short nfields;
	unsigned short fieldsz[ADDRXLAT_FIELDS_MAX];
} addrxlat_paging_form_t;

typedef struct _addrxlat_param_pgt {
	addrxlat_fulladdr_t root;
	addrxlat_pte_t pte_mask;
	addrxlat_paging_form_t pf;
} addrxlat_param_pgt_t;

typedef struct _addrxlat_lookup_elem {
	addrxlat_addr_t orig;
	addrxlat_addr_t dest;
} addrxlat_lookup_elem_t;

typedef struct _addrxlat_param_lookup {
	addrxlat_addr_t endoff;
	size_t nelem;
	addrxlat_lookup_elem_t *tbl;
} addrxlat_param_lookup_t;

typedef struct _addrxlat_param_memarr {
	addrxlat_fulladdr_t base;
	unsigned shift;
	unsigned elemsz;
	unsigned valsz;
} addrxlat_param_memarr_t;

typedef union _addrxlat_param {
	addrxlat_param_custom_t custom;
	addrxlat_param_linear_t linear;
	addrxlat_param_pgt_t pgt;
	addrxlat_param_lookup_t lookup;
	addrxlat_param_memarr_t memarr;
} addrxlat_param_t;

typedef struct _addrxlat_meth {
	addrxlat_kind_t kind;
	addrxlat_addrspace_t target_as;
	addrxlat_param_t param;
} addrxlat_meth_t;

typedef enum _addrxlat_sys_meth {
	ADDRXLAT_SYS_METH_NONE = -1,

	ADDRXLAT_SYS_METH_PGT,
	ADDRXLAT_SYS_METH_UPGT,
	ADDRXLAT_SYS_METH_DIRECT,
	ADDRXLAT_SYS_METH_KTEXT,
	ADDRXLAT_SYS_METH_VMEMMAP,
	ADDRXLAT_SYS_METH_RDIRECT,
	ADDRXLAT_SYS_METH_MACHPHYS_KPHYS,
	ADDRXLAT_SYS_METH_KPHYS_MACHPHYS,
	ADDRXLAT_SYS_METH_CUSTOM
} addrxlat_sys_meth_t;

#define ADDRXLAT_SYS_METH_CUSTOM_NUM	...
#define ADDRXLAT_SYS_METH_NUM		...

typedef struct _addrxlat_range {
	addrxlat_addr_t endoff;
	addrxlat_sys_meth_t meth;
} addrxlat_range_t;

typedef struct _addrxlat_map addrxlat_map_t;

addrxlat_map_t *addrxlat_map_new(void);
unsigned long addrxlat_map_incref(addrxlat_map_t *map);
unsigned long addrxlat_map_decref(addrxlat_map_t *map);
size_t addrxlat_map_len(const addrxlat_map_t *map);
const addrxlat_range_t *addrxlat_map_ranges(const addrxlat_map_t *map);
addrxlat_status addrxlat_map_set(
	addrxlat_map_t *map, addrxlat_addr_t addr,
	const addrxlat_range_t *range);
addrxlat_sys_meth_t addrxlat_map_search(
	const addrxlat_map_t *map, addrxlat_addr_t addr);
addrxlat_map_t *addrxlat_map_copy(const addrxlat_map_t *map);

typedef enum _addrxlat_optidx {
	ADDRXLAT_OPT_NULL,
	ADDRXLAT_OPT_arch,
	ADDRXLAT_OPT_os_type,
	ADDRXLAT_OPT_version_code,
	ADDRXLAT_OPT_phys_bits,
	ADDRXLAT_OPT_virt_bits,
	ADDRXLAT_OPT_page_shift,
	ADDRXLAT_OPT_phys_base,
	ADDRXLAT_OPT_rootpgt,
	ADDRXLAT_OPT_xen_p2m_mfn,
	ADDRXLAT_OPT_xen_xlat,
	ADDRXLAT_OPT_NUM
} addrxlat_optidx_t;

typedef union _addrxlat_optval {
	const char *str;
	unsigned long num;
	addrxlat_addr_t addr;
	addrxlat_fulladdr_t fulladdr;
} addrxlat_optval_t;

typedef struct _addrxlat_opt {
	addrxlat_optidx_t idx;
	addrxlat_optval_t val;
} addrxlat_opt_t;

void addrxlat_opt_arch(addrxlat_opt_t *opt, const char *val);
void addrxlat_opt_os_type(addrxlat_opt_t *opt, const char *val);
void addrxlat_opt_version_code(addrxlat_opt_t *opt, unsigned long val);
void addrxlat_opt_phys_bits(addrxlat_opt_t *opt, unsigned long val);
void addrxlat_opt_virt_bits(addrxlat_opt_t *opt, unsigned long val);
void addrxlat_opt_page_shift(addrxlat_opt_t *opt, unsigned long val);
void addrxlat_opt_phys_base(addrxlat_opt_t *opt, addrxlat_addr_t val);
void addrxlat_opt_rootpgt(addrxlat_opt_t *opt, const addrxlat_fulladdr_t *val);
void addrxlat_opt_xen_p2m_mfn(addrxlat_opt_t *opt, unsigned long val);
void addrxlat_opt_xen_xlat(addrxlat_opt_t *opt, unsigned long val);

unsigned long ADDRXLAT_VER_LINUX(unsigned a, unsigned b, unsigned c);
unsigned long ADDRXLAT_VER_XEN(unsigned major, unsigned minor);

typedef struct _addrxlat_sys addrxlat_sys_t;

addrxlat_sys_t *addrxlat_sys_new(void);
unsigned long addrxlat_sys_incref(addrxlat_sys_t *sys);
unsigned long addrxlat_sys_decref(addrxlat_sys_t *sys);
addrxlat_status addrxlat_sys_os_init(
	addrxlat_sys_t *sys, addrxlat_ctx_t *ctx,
	unsigned optc, const addrxlat_opt_t *opts);

typedef enum _addrxlat_sys_map {
	ADDRXLAT_SYS_MAP_HW,
	ADDRXLAT_SYS_MAP_KV_PHYS,
	ADDRXLAT_SYS_MAP_KPHYS_DIRECT,
	ADDRXLAT_SYS_MAP_MACHPHYS_KPHYS,
	ADDRXLAT_SYS_MAP_KPHYS_MACHPHYS,

	ADDRXLAT_SYS_MAP_NUM,
} addrxlat_sys_map_t;

void addrxlat_sys_set_map(
	addrxlat_sys_t *sys, addrxlat_sys_map_t idx,
	addrxlat_map_t *map);
addrxlat_map_t *addrxlat_sys_get_map(
	const addrxlat_sys_t *sys, addrxlat_sys_map_t idx);
void addrxlat_sys_set_meth(
	addrxlat_sys_t *sys, addrxlat_sys_meth_t idx,
	const addrxlat_meth_t *meth);
const addrxlat_meth_t *addrxlat_sys_get_meth(
	const addrxlat_sys_t *sys, addrxlat_sys_meth_t idx);

struct _addrxlat_step {
	addrxlat_ctx_t *ctx;
	addrxlat_sys_t *sys;
	const addrxlat_meth_t *meth;
	unsigned short remain;
	unsigned elemsz;
	addrxlat_fulladdr_t base;
	union {
		void *data;
		addrxlat_pte_t pte;
		const addrxlat_lookup_elem_t *elem;
		addrxlat_addr_t addr;
	} raw;
	addrxlat_addr_t idx[ADDRXLAT_FIELDS_MAX + 1];
};

addrxlat_status addrxlat_launch(addrxlat_step_t *step, addrxlat_addr_t addr);
addrxlat_status addrxlat_step(addrxlat_step_t *step);
addrxlat_status addrxlat_walk(addrxlat_step_t *step);

typedef addrxlat_status addrxlat_op_fn(void *data,
				       const addrxlat_fulladdr_t *addr);

typedef struct _addrxlat_op_ctl {
	addrxlat_ctx_t *ctx;
	addrxlat_sys_t *sys;
	addrxlat_op_fn *op;
	void *data;
	unsigned long caps;
} addrxlat_op_ctl_t;

addrxlat_status addrxlat_op(const addrxlat_op_ctl_t *ctl,
			    const addrxlat_fulladdr_t *addr);

addrxlat_status addrxlat_fulladdr_conv(
	addrxlat_fulladdr_t *faddr, addrxlat_addrspace_t as,
	addrxlat_ctx_t *ctx, addrxlat_sys_t *sys);
