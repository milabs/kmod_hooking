#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/moduleloader.h>
#include <linux/kallsyms.h>
#include <linux/sort.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/stop_machine.h>

#include "udis86.h"

#define debug(fmt...)			\
	pr_info("[" KBUILD_MODNAME "] " fmt)

typedef typeof(module_free) module_free_t;
module_free_t * pfnModuleFree = NULL;

typedef typeof(module_alloc) module_alloc_t;
module_alloc_t * pfnModuleAlloc = NULL;

/*
 * Hooking structure
 */
typedef struct {
	/* tagret's name */
	char * name;

 	/* target's insn length */
	int length;

	/* target's handler address */
	void * handler;

	/* target's address and rw-mapping */
	void * target;
	void * target_map;

	/* origin's address and rw-mapping */
	void * origin;
	void * origin_map;

	atomic_t usage;
} khookstr_t;

extern khookstr_t __khook_start[], __khook_finish[];

#define khook_for_each(item)			\
	for (item = __khook_start; item < __khook_finish; item++)

#define __DECLARE_TARGET_ALIAS(t)		\
	void __attribute__((alias("khook_"#t))) khook_alias_##t(void)

#define __DECLARE_TARGET_ORIGIN(t)		\
	void notrace khook_origin_##t(void) {	\
		asm volatile (			\
			".rept 0x20\n"		\
			".byte 0x90\n"		\
			".endr\n"		\
		);				\
	}

#define __DECLARE_TARGET_STRUCT(t)		\
	khookstr_t __attribute__((unused,section(".khook"),aligned(1))) __khook_##t

#define DECLARE_KHOOK(t)			\
	__DECLARE_TARGET_ALIAS(t);		\
	__DECLARE_TARGET_ORIGIN(t);		\
	__DECLARE_TARGET_STRUCT(t) = {		\
		.name = #t,			\
		.target = NULL,			\
		.handler = khook_alias_##t,	\
		.origin = khook_origin_##t,	\
		.usage = ATOMIC_INIT(0),	\
	}

#define KHOOK_ORIGIN(t, ...)			\
	((typeof(t) *)__khook_##t.origin)(__VA_ARGS__)

#define KHOOK_USAGE_INC(t)			\
	atomic_inc(&__khook_##t.usage)

#define KHOOK_USAGE_DEC(t)			\
	atomic_dec(&__khook_##t.usage)

/*
 * Kernel symbol address interface
 */

typedef struct {
	const char * name;
	void * address;
} ksymstr_t;

static int on_each_symbol(void * data, const char * name, struct module * module, unsigned long address)
{
	ksymstr_t * sym = (void *)data;

	if (strcmp(name, sym->name) == 0) {
		sym->address = (void *)address;
		debug("Symbol \"%s\" found @ %pK\n", sym->name, sym->address);
		return 1;
	}

	return 0;
}

void * get_symbol_address(const char * name)
{
	ksymstr_t sym = {
		.name = name, .address = NULL,
	};

	kallsyms_on_each_symbol(on_each_symbol, &sym);

	return sym.address;
}

/*
 * extable helpers
 */

static void extable_make_insn(struct exception_table_entry * entry, unsigned long addr)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
	entry->insn = (unsigned int)((addr - (unsigned long)&entry->insn));
#else
	entry->insn = addr;
#endif
}

static void extable_make_fixup(struct exception_table_entry * entry, unsigned long addr)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
	entry->fixup = (unsigned int)((addr - (unsigned long)&entry->fixup));
#else
	entry->fixup = addr;
#endif
}

/* See lib/extable.c for details */
static int cmp_ex(const void * a, const void * b)
{
	const struct exception_table_entry * x = a, * y = b;

	/* avoid overflow */
	if (x->insn > y->insn)
		return 1;
	if (x->insn < y->insn)
		return -1;
	return 0;
}

static void flush_extable(void)
{
	THIS_MODULE->num_exentries = 0;
	pfnModuleFree(THIS_MODULE, THIS_MODULE->extable);
	THIS_MODULE->extable = NULL;
}

/*
 * map_writable creates a shadow page mapping of the range
 * [addr, addr + len) so that we can write to code mapped read-only.
 *
 * It is similar to a generalized version of x86's text_poke.  But
 * because one cannot use vmalloc/vfree() inside stop_machine, we use
 * map_writable to map the pages before stop_machine, then use the
 * mapping inside stop_machine, and unmap the pages afterwards.
 *
 * STOLEN from: https://github.com/jirislaby/ksplice
 */

static void *map_writable(void *addr, size_t len)
{
	void *vaddr;
	int nr_pages = DIV_ROUND_UP(offset_in_page(addr) + len, PAGE_SIZE);
	struct page **pages = kmalloc(nr_pages * sizeof(*pages), GFP_KERNEL);
	void *page_addr = (void *)((unsigned long)addr & PAGE_MASK);
	int i;

	if (pages == NULL)
		return NULL;

	for (i = 0; i < nr_pages; i++) {
		if (__module_address((unsigned long)page_addr) == NULL) {
			pages[i] = virt_to_page(page_addr);
			WARN_ON(!PageReserved(pages[i]));
		} else {
			pages[i] = vmalloc_to_page(page_addr);
		}
		if (pages[i] == NULL) {
			kfree(pages);
			return NULL;
		}
		page_addr += PAGE_SIZE;
	}
	vaddr = vmap(pages, nr_pages, VM_MAP, PAGE_KERNEL);
	kfree(pages);
	if (vaddr == NULL)
		return NULL;
	return vaddr + offset_in_page(addr);
}

/*
 * Kernel function hooking example
 */

DECLARE_KHOOK(inode_permission);
int khook_inode_permission(struct inode * inode, int mode)
{
	int result;

	KHOOK_USAGE_INC(inode_permission);

	debug("%s(%p,%08x)\n", __func__, inode, mode);

	result = KHOOK_ORIGIN(inode_permission, inode, mode);

	debug("%s(%p,%08x) = %d\n", __func__, inode, mode, result);

	KHOOK_USAGE_DEC(inode_permission);

	return result;
}

/*
 * Module init/cleanup parts
 */

static inline void x86_put_ud2(void * a)
{
	/* UD2 opcode -- 0F.0B */

	*((short *)a) = 0x0B0F;
}

static inline void x86_put_jmp(void * a, void * t)
{
	/* JMP opcode -- E9.xx.xx.xx.xx */

	*((char *)(a + 0)) = 0xE9;
	*(( int *)(a + 1)) = (long)(t - (a + 5));
}

static int init_origin_stub(khookstr_t * s)
{
	ud_t ud;

	ud_initialize(&ud, BITS_PER_LONG, \
		      UD_VENDOR_ANY, (void *)s->target, 32);

	while (ud_disassemble(&ud) && ud.mnemonic != UD_Iret) {
		if (ud.mnemonic == UD_Iud2 || ud.mnemonic == UD_Iint3) {
			debug("It seems that \"%s\" is not a hooking virgin\n", s->name);
			return -EINVAL;
		}

#define UD2_INSN_LEN	2

		s->length += ud_insn_len(&ud);
		if (s->length >= UD2_INSN_LEN) {
			memcpy(s->origin_map, s->target, s->length);
			x86_put_jmp(s->origin_map + s->length, s->target + s->length);
			break;
		}
	}

	return 0;
}

static int do_init_hooks(void * arg)
{
	khookstr_t * s;

	khook_for_each(s) {
		if (atomic_read(&s->usage) == 1)
			x86_put_ud2(s->target_map);
	}

	return 0;
}

static int init_hooks(void)
{
	khookstr_t * s;
	int num_exentries = 0;
	struct exception_table_entry * extable;

	extable = (void *)pfnModuleAlloc(sizeof(*extable) * (__khook_finish - __khook_start));
	if (extable == NULL) {
		debug("Memory allocation failed\n");
		return -ENOMEM;
	}

	khook_for_each(s) {
		s->target = get_symbol_address(s->name);
		if (s->target) {
			s->target_map = map_writable(s->target, 32);
			s->origin_map = map_writable(s->origin, 32);

			if (s->target_map && s->origin_map) {
				if (init_origin_stub(s) == 0) {
					struct exception_table_entry * entry = &extable[num_exentries++];

					/* OK, the stub is initialized */

					atomic_inc(&s->usage);

					extable_make_insn(entry, (unsigned long)s->target);
					extable_make_fixup(entry, (unsigned long)s->handler);

					continue;
				}
			}
		}

		debug("Failed to initalize \"%s\" hook", s->name);
	}

	sort(extable, num_exentries, sizeof(*extable), cmp_ex, NULL);

	THIS_MODULE->extable = extable;
	THIS_MODULE->num_exentries = num_exentries;

	/* apply patches */
	stop_machine(do_init_hooks, NULL, NULL);

	return 0;
}

static int do_clenup_hooks(void * arg)
{
	khookstr_t * s;

	khook_for_each(s) {
		if (atomic_read(&s->usage))
			memcpy(s->target_map, s->origin, s->length);
	}

	return 0;
}

static void cleanup_hooks(void)
{
	khookstr_t * s;

	/* restore patches */
	stop_machine(do_clenup_hooks, NULL, NULL);

	khook_for_each(s) {
		while (atomic_read(&s->usage) != 1) {
			msleep_interruptible(500);
		}

		vunmap((void *)((unsigned long)s->target_map & PAGE_MASK));
		vunmap((void *)((unsigned long)s->origin_map & PAGE_MASK));
	}

	flush_extable();
}

int init_module(void)
{
	pfnModuleFree = get_symbol_address("module_free");
	pfnModuleAlloc = get_symbol_address("module_alloc");

	if (!pfnModuleFree || !pfnModuleAlloc) {
		return -EINVAL;
	}

	return init_hooks();
}

void cleanup_module(void)
{
	cleanup_hooks();
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ilya V. Matveychikov <i.matveychikov@milabs.ru>");
MODULE_DESCRIPTION("Linux kernel function hooking example");
