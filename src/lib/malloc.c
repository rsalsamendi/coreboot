#include <stdlib.h>
#include <console/console.h>
#include <cpu/x86/smm.h>

#include "asan.h"

#if IS_ENABLED(CONFIG_DEBUG_MALLOC)
#define MALLOCDBG(x...) printk(BIOS_SPEW, x)
#else
#define MALLOCDBG(x...)
#endif

extern unsigned char _heap, _eheap;
static void *free_mem_ptr = &_heap;		/* Start of heap */
static void *free_mem_end_ptr = &_eheap;	/* End of heap */

// static size_t optimal_redzone(size_t object_size)
// {
// 	int rz =
// 		object_size <= 64        - 16   ? 16 :
// 		object_size <= 128       - 32   ? 32 :
// 		object_size <= 512       - 64   ? 64 :
// 		object_size <= 4096      - 128  ? 128 :
// 		object_size <= (1 << 14) - 256  ? 256 :
// 		object_size <= (1 << 15) - 512  ? 512 :
// 		object_size <= (1 << 16) - 1024 ? 1024 : 2048;
// 	return rz;
// }

/* We don't restrict the boundary. This is firmware,
 * you are supposed to know what you are doing.
 */

static const uint64_t KASAN_SHADOW_SCALE_SIZE=(1UL << 3);
void *memalign(size_t boundary, size_t size)
{
	void *p;
	unsigned long redzone_start;
	unsigned long redzone_end;

	MALLOCDBG("%s Enter, boundary %zu, size %zu, free_mem_ptr %p\n",
		__func__, boundary, size, free_mem_ptr);

	free_mem_ptr = (void *)ALIGN((unsigned long)free_mem_ptr, boundary);

	p = free_mem_ptr;
	free_mem_ptr += size;

	if (free_mem_ptr >= free_mem_end_ptr) {
		printk(BIOS_ERR, "memalign(boundary=%zu, size=%zu): failed: ",
				boundary, size);
		printk(BIOS_ERR, "Tried to round up free_mem_ptr %p to %p\n",
				p, free_mem_ptr);
		printk(BIOS_ERR, "but free_mem_end_ptr is %p\n",
				free_mem_end_ptr);
		die("Error! memalign: Out of memory (free_mem_ptr >= free_mem_end_ptr)");
	}

	MALLOCDBG("memalign %p\n", p);
	kasan_unpoison_shadow(p, size);

	redzone_start = round_up((unsigned long)(p + size), KASAN_SHADOW_SCALE_SIZE);
	redzone_end = round_up((unsigned long)(p + size), KASAN_SHADOW_SCALE_SIZE);

	kasan_poison_shadow((void*)redzone_start, redzone_end - redzone_start,
		KASAN_KMALLOC_REDZONE);

	return p;
}

void *malloc(size_t size)
{
	return memalign(sizeof(u64), size);
}
