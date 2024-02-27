/* Copyright 2005 Andi Kleen, SuSE Labs.
 * Licensed under GPL, v.2
 */
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/random.h>
#include <asm/ia32.h>

/* Notebook: move the mmap code from sys_x86_64.c over here. */

void arch_pick_mmap_layout(struct mm_struct *mm)
{
#ifdef CONFIG_IA32_EMULATION
	/* 如果启用对32位应用程序的二进制仿真，任何以兼容模式运行
	 * 的进程都应该看到与原始计算机上相同的地址空间 */
	if (current_thread_info()->flags & _TIF_IA32)
		return ia32_pick_mmap_layout(mm);
#endif
	/* 64位机器，用经典布局就好了 */
	mm->mmap_base = TASK_UNMAPPED_BASE;
	/* 开启地址空间随机化，也还是需要变动一下mmap_base */
	if (current->flags & PF_RANDOMIZE) {
		/* Add 28bit randomness which is about 40bits of address space
		   because mmap base has to be page aligned.
 		   or ~1/128 of the total user VM
	   	   (total user address space is 47bits) */
		unsigned rnd = get_random_int() & 0xfffffff;
		mm->mmap_base += ((unsigned long)rnd) << PAGE_SHIFT;
	}
	mm->get_unmapped_area = arch_get_unmapped_area;
	mm->unmap_area = arch_unmap_area;
}

