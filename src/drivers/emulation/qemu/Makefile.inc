romstage-$(CONFIG_CONSOLE_QEMU_DEBUGCON) += qemu_debugcon.c
ramstage-$(CONFIG_CONSOLE_QEMU_DEBUGCON) += qemu_debugcon.c

ifeq ($(CONFIG_ASAN),y)
CFLAGS_REMOVE_qemu_debugcon.o := $(KASAN_FLAGS)
endif

ramstage-$(CONFIG_DRIVERS_EMULATION_QEMU_BOCHS) += bochs.c
ramstage-$(CONFIG_DRIVERS_EMULATION_QEMU_BOCHS) += cirrus.c
ramstage-$(CONFIG_DRIVERS_EMULATION_QEMU_BOCHS) += ../../pc80/vga/vga_io.c
