#include <stdint.h>
#include <string.h>
#include <lib.h>
#include <console/console.h>

// Adapted from https://lwn.net/Articles/612266/

#include "asan.h"

#define unlikely(x) (x)
#define likely(x) (x)
#define _RET_IP_ (unsigned long)__builtin_return_address(0)
#define PAGE_OFFSET 0xc0000ull

static const uint64_t KASAN_SHADOW_START=0xc000000ull;
static const uint64_t KASAN_SHADOW_SCALE_SHIFT=3;

static const uint64_t KASAN_SHADOW_SCALE_SIZE=(1UL << 3);
static const uint64_t KASAN_SHADOW_MASK       = ((1UL << 3) - 1);

// static const uint64_t KASAN_SHADOW_GAP=       0xF9; /* address belongs to shadow memory */

struct access_info {
	unsigned long access_addr;
	unsigned long first_bad_addr;
	size_t access_size;
	bool is_write;
	unsigned long ip;
};

static unsigned long kasan_mem_to_shadow(unsigned long addr)
{
	return ((addr - KASAN_SHADOW_START) >> KASAN_SHADOW_SCALE_SHIFT)
		+ KASAN_SHADOW_START;
}

static unsigned long find_first_bad_addr(unsigned long addr, size_t size)
{
	u8 shadow_val = *(u8 *)kasan_mem_to_shadow(addr);
	unsigned long first_bad_addr = addr;

	while (!shadow_val && first_bad_addr < addr + size) {
		first_bad_addr += KASAN_SHADOW_SCALE_SIZE;
		shadow_val = *(u8 *)kasan_mem_to_shadow(first_bad_addr);
	}
	return first_bad_addr;
}

static void print_error_description(struct access_info *info)
{
	const char *bug_type = "unknown crash";
	u8 shadow_val;

	info->first_bad_addr = find_first_bad_addr(info->access_addr,
		info->access_size);

	shadow_val = *(u8 *)kasan_mem_to_shadow(info->first_bad_addr);

	switch (shadow_val) {
	case 0 ... KASAN_SHADOW_SCALE_SIZE - 1:
		bug_type = "out of bounds access";
		break;
	case 8:
		bug_type = "wild memory access";
		break;
	}

	printk(BIOS_ERR, "BUG: AddressSanitizer: %s in %pS at addr %p\n",
		bug_type, (void *)info->ip,
		(void *)info->access_addr);
}

static void print_address_description(struct access_info *info)
{
	// void *object;
	// struct kmem_cache *cache;
	// void *slab_start;
	struct page *page;
	u8 shadow_val = *(u8 *)kasan_mem_to_shadow(info->first_bad_addr);

	page = ((void *)(info->access_addr & (~0xfff)));

	switch (shadow_val) {
	case 8:
		printk(BIOS_ERR, "No metainfo is available for this access.\n");
		// dump_stack();
		break;
	default:
		// WARN_ON(1);
		break;
	}

	printk(BIOS_ERR, "%s of size %zu:\n",
		info->is_write ? "Write" : "Read",
		info->access_size);
}

static void kasan_report_error(struct access_info *info)
{
	// unsigned long flags;
	
	// if (likely(!kasan_enabled()))
		// return;

	// spin_lock_irqsave(&report_lock, flags);
	printk(BIOS_ERR, "================================="
		"=================================\n");
	print_error_description(info);
	print_address_description(info);
	// print_shadow_for_address(info->first_bad_addr);
	printk(BIOS_ERR, "================================="
		"=================================\n");
	// spin_unlock_irqrestore(&report_lock, flags);
}

/*
 * Poisons the shadow memory for 'size' bytes starting from 'addr'.
 * Memory addresses should be aligned to KASAN_SHADOW_SCALE_SIZE.
 */
void kasan_poison_shadow(const void *address, size_t size, u8 value)
{
	unsigned long shadow_start, shadow_end;
	unsigned long addr = (unsigned long)address;

	shadow_start = kasan_mem_to_shadow(addr);
	shadow_end = kasan_mem_to_shadow(addr + size);

	memset((void *)shadow_start, value, shadow_end - shadow_start);
}

void kasan_unpoison_shadow(const void *address, size_t size)
{
	kasan_poison_shadow(address, size, 0);

	if (size & KASAN_SHADOW_MASK) {
		u8 *shadow = (u8 *)kasan_mem_to_shadow((unsigned long)address
			+ size);
		*shadow = size & KASAN_SHADOW_MASK;
	}
}
	
static __inline bool address_is_poisoned(unsigned long addr)
{
	s8 shadow_value = *(s8 *)kasan_mem_to_shadow(addr);

	if (shadow_value != 0) {
		s8 last_byte = addr & KASAN_SHADOW_MASK;
		return last_byte >= shadow_value;
	}
	return false;
}

static __inline unsigned long memory_is_poisoned(unsigned long addr,
	size_t size)
{
	unsigned long end = addr + size;

	for (; addr < end; addr++)
		if (address_is_poisoned(addr))
		{
			return addr;
		}
	return 0;
}

static __inline void check_memory_region(unsigned long addr,
	size_t size, bool write)
{
	unsigned long access_addr;
	struct access_info info;

	if (unlikely(size == 0))
		return;

	// if (unlikely(addr < PAGE_OFFSET)) {
	// 	info.access_addr = addr;
	// 	info.access_size = size;
	// 	info.is_write = write;
	// 	info.ip = _RET_IP_;
	// 	kasan_report_user_access(&info);
	// 	return;
	// }

	access_addr = memory_is_poisoned(addr, size);
	if (likely(access_addr == 0))
		return;

	info.access_addr = access_addr;
	info.access_size = size;
	info.is_write = write;
	info.ip = _RET_IP_;
	kasan_report_error(&info);
}

void __asan_load1(unsigned long addr)
{
	check_memory_region(addr, 1, false);
}

void __asan_load2(unsigned long addr)
{
	check_memory_region(addr, 2, false);
}

void __asan_load4(unsigned long addr)
{
	check_memory_region(addr, 4, false);
}

void __asan_load8(unsigned long addr)
{
	check_memory_region(addr, 8, false);
}

void __asan_load16(unsigned long addr)
{
	check_memory_region(addr, 16, false);
}

void __asan_loadN(unsigned long addr, size_t size)
{
	check_memory_region(addr, size, false);
}

void __asan_store1(unsigned long addr)
{
	check_memory_region(addr, 1, true);
}

void __asan_store2(unsigned long addr)
{
	check_memory_region(addr, 2, true);
}

void __asan_store4(unsigned long addr)
{
	check_memory_region(addr, 4, true);
}

void __asan_store8(unsigned long addr)
{
	check_memory_region(addr, 8, true);
}

void __asan_store16(unsigned long addr)
{
	check_memory_region(addr, 16, true);
}

void __asan_storeN(unsigned long addr, size_t size)
{
	check_memory_region(addr, size, true);
}

void __attribute__((noreturn)) __asan_handle_no_return(void)
{
	die("AddressSanitizer\n");
}

// noabort
void __asan_load1_noabort(unsigned long addr)
{
	check_memory_region(addr, 1, false);
}

void __asan_load2_noabort(unsigned long addr)
{
	check_memory_region(addr, 2, false);
}

void __asan_load4_noabort(unsigned long addr)
{
	check_memory_region(addr, 4, false);
}

void __asan_load8_noabort(unsigned long addr)
{
	check_memory_region(addr, 8, false);
}

void __asan_load16_noabort(unsigned long addr)
{
	check_memory_region(addr, 16, false);
}

void __asan_loadN_noabort(unsigned long addr, size_t size)
{
	check_memory_region(addr, size, false);
}

void __asan_store1_noabort(unsigned long addr)
{
	check_memory_region(addr, 1, true);
}

void __asan_store2_noabort(unsigned long addr)
{
	check_memory_region(addr, 2, true);
}

void __asan_store4_noabort(unsigned long addr)
{
	check_memory_region(addr, 4, true);
}

void __asan_store8_noabort(unsigned long addr)
{
	check_memory_region(addr, 8, true);
}

void __asan_store16_noabort(unsigned long addr)
{
	check_memory_region(addr, 16, true);
}

void __asan_storeN_noabort(unsigned long addr, size_t size)
{
	check_memory_region(addr, size, true);
}

