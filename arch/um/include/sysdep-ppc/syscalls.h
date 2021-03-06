/* 
 * Copyright (C) 2000 Jeff Dike (jdike@karaya.com)
 * Licensed under the GPL
 */

typedef long syscall_handler_t(unsigned long arg1, unsigned long arg2,
			       unsigned long arg3, unsigned long arg4,
			       unsigned long arg5, unsigned long arg6);

#define EXECUTE_SYSCALL(syscall, regs) \
        (*sys_call_table[syscall])(UM_SYSCALL_ARG1(&regs), \
			           UM_SYSCALL_ARG2(&regs), \
				   UM_SYSCALL_ARG3(&regs), \
				   UM_SYSCALL_ARG4(&regs), \
				   UM_SYSCALL_ARG5(&regs), \
				   UM_SYSCALL_ARG6(&regs))

extern syscall_handler_t sys_mincore;
extern syscall_handler_t sys_madvise;

/* old_mmap needs the correct prototype since syscall_kern.c includes
 * this file.
 */
int old_mmap(unsigned long addr, unsigned long len,
	     unsigned long prot, unsigned long flags,
	     unsigned long fd, unsigned long offset);

#define ARCH_SYSCALLS \
	[ __NR_modify_ldt ] = sys_ni_syscall, \
	[ __NR_pciconfig_read ] = sys_ni_syscall, \
	[ __NR_pciconfig_write ] = sys_ni_syscall, \
	[ __NR_pciconfig_iobase ] = sys_ni_syscall, \
	[ __NR_pivot_root ] = sys_ni_syscall, \
	[ __NR_multiplexer ] = sys_ni_syscall, \
	[ __NR_mmap ] = old_mmap, \
	[ __NR_madvise ] = sys_madvise, \
	[ __NR_mincore ] = sys_mincore, 

#define LAST_ARCH_SYSCALL __NR_mincore

/*
 * Overrides for Emacs so that we follow Linus's tabbing style.
 * Emacs will notice this stuff at the end of the file and automatically
 * adjust the settings for this buffer only.  This must remain at the end
 * of the file.
 * ---------------------------------------------------------------------------
 * Local variables:
 * c-file-style: "linux"
 * End:
 */
