# Makefile made with help from http://www.hsrl.rutgers.edu/ug/make_help.html
# $@ is the name of the file to be made.
# $? is the names of the changed dependents.
# $< the name of the related file that caused the action.
# $* the prefix shared by target and dependent files.

CC=gcc
RM=rm -f
AS=as
AR=ar
LD=ld
OBJCOPY=objcopy

CFLAGS := -Wall -Werror -O2 -std=gnu99 -m32 -march=i686
CFLAGS += -ffreestanding -nostdlib 
CFLAGS += -fno-builtin -fno-common -fno-strict-aliasing
CFLAGS += -fomit-frame-pointer
CFLAGS += -I$(CURDIR)/libtommath
CFLAGS += -I$(CURDIR)/../../include
CFLAGS += -I$(CURDIR)/../../pal
CFLAGS += -msoft-float
CFLAGS += -fno-jump-tables
CFLAGS += -fno-stack-protector

CFLAGS += -DnotPERFCRIT
CFLAGS += -DMIN_LOG_LEVEL=2

AFLAGS += -D__ASSEMBLY__

# necessary to support gcc 64-bit "built-ins" in 32-bit build
# e.g., undefined reference errors re: __udivdi3 or __umoddi3
GCC_LIBS := $(shell $(CC) -m32 --print-file-name=libgcc.a)

LDFLAGS	+= -melf_i386

PALDIR := $(CURDIR)/../../pal
LINKFILE := $(PALDIR)/pal.ld

PAL_OBJS := $(wildcard $(PALDIR)/*.o)

BUILD_DEPS := $(CURDIR)/Makefile


# Put projects here

all: tpal.bin tctr.bin rlimit.bin bitcoin.bin

#Put obj files and build commands here

TPAL_OBJS := tpal.o
tpal.elf: $(PAL_OBJS) $(LINKFILE) $(TPAL_OBJS)
	$(LD) $(LDFLAGS) -T $(LINKFILE) -N $(PAL_OBJS) $(TPAL_OBJS) $(GCC_LIBS) \
	    -o $(@D)/$(@F)

TCTR_OBJS := tctr.o
tctr.elf: $(PAL_OBJS) $(LINKFILE) $(TCTR_OBJS)
	$(LD) $(LDFLAGS) -T $(LINKFILE) -N $(PAL_OBJS) $(TCTR_OBJS) $(GCC_LIBS) \
	    -o $(@D)/$(@F)

RLIMIT_OBJS := rlimit.o
rlimit.elf: $(PAL_OBJS) $(LINKFILE) $(RLIMIT_OBJS)
	$(LD) $(LDFLAGS) -T $(LINKFILE) -N $(PAL_OBJS) $(RLIMIT_OBJS) $(GCC_LIBS) \
	    -o $(@D)/$(@F)

BITCOIN_OBJS := bitcoin.o aes.o cbcmode.o bcmath.o libtommath/libtommath.a
bitcoin.elf: $(PAL_OBJS) $(LINKFILE) $(BITCOIN_OBJS)
	$(LD) $(LDFLAGS) -T $(LINKFILE) -N $(PAL_OBJS) $(BITCOIN_OBJS) $(GCC_LIBS) \
	    -o $(@D)/$(@F) -M -Map=bitcoin.map

%.bin: %.elf
	$(OBJCOPY) -O binary $< $@

clean:
	$(RM) *.bin *elf *.o

%.o : %.c $(HDRS) $(BUILD_DEPS)
	$(CC) $(CFLAGS) -c $< -o $@

%.o : %.S $(HDRS) $(BUILD_DEPS)
	$(CC) $(AFLAGS) $(CFLAGS) -c $< -o $@

%.i : %.c $(HDRS) $(BUILD_DEPS)
	$(CPP) $(CFLAGS) $< -o $@

# -std=gnu{89,99} gets confused by # as an end-of-line comment marker
%.s : %.S $(HDRS)  $(BUILD_DEPS)
	$(CPP) $(AFLAGS) $< -o $@
