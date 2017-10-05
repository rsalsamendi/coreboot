#ifndef __ASAN_H__
#define __ASAN_H__

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
