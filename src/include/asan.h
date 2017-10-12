#ifndef __ASAN_H__
#define __ASAN_H__


#define KASAN_FREE_PAGE         0xFF  /* page was freed */
#define KASAN_PAGE_REDZONE      0xFE  /* redzone for kmalloc_large allocations */
#define KASAN_KMALLOC_REDZONE   0xFC  /* redzone inside slub object */
#define KASAN_KMALLOC_FREE      0xFB  /* object was freed (kmem_cache_free/kfree) */
#define KASAN_GLOBAL_REDZONE    0xFA  /* redzone for global variable */

/*
 *  * Stack redzone shadow values
 *   * (Those are compiler's ABI, don't change them)
 *    */
#define KASAN_STACK_LEFT        0xF1
#define KASAN_STACK_MID         0xF2
#define KASAN_STACK_RIGHT       0xF3
#define KASAN_STACK_PARTIAL     0xF4
#define KASAN_USE_AFTER_SCOPE   0xF8

#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))

void kasan_poison_shadow(const void *address, size_t size, u8 value);
void kasan_unpoison_shadow(const void *address, size_t size);

void __asan_load1(unsigned long addr);
void __asan_load2(unsigned long addr);
void __asan_load4(unsigned long addr);
void __asan_load8(unsigned long addr);
void __asan_load16(unsigned long addr);
void __asan_loadN(unsigned long addr, size_t size);

void __asan_store1(unsigned long addr);
void __asan_store2(unsigned long addr);
void __asan_store4(unsigned long addr);
void __asan_store8(unsigned long addr);
void __asan_store16(unsigned long addr);
void __asan_storeN(unsigned long addr, size_t size);

void __attribute__((noreturn)) __asan_handle_no_return(void);

// noabort
void __asan_load1_noabort(unsigned long addr);
void __asan_load2_noabort(unsigned long addr);
void __asan_load4_noabort(unsigned long addr);
void __asan_load8_noabort(unsigned long addr);
void __asan_load16_noabort(unsigned long addr);
void __asan_loadN_noabort(unsigned long addr, size_t size);

void __asan_store1_noabort(unsigned long addr);
void __asan_store2_noabort(unsigned long addr);
void __asan_store4_noabort(unsigned long addr);
void __asan_store8_noabort(unsigned long addr);
void __asan_store16_noabort(unsigned long addr);
void __asan_storeN_noabort(unsigned long addr, size_t size);



#endif /* __ASAN__H__ */
