#ifndef _LINUX_MM_TYPES_H
#define _LINUX_MM_TYPES_H

#include <linux/auxvec.h>
#include <linux/types.h>
#include <linux/threads.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/prio_tree.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/completion.h>
#include <asm/page.h>
#include <asm/mmu.h>

#ifndef AT_VECTOR_SIZE_ARCH
#define AT_VECTOR_SIZE_ARCH 0
#endif
#define AT_VECTOR_SIZE (2*(AT_VECTOR_SIZE_ARCH + AT_VECTOR_SIZE_BASE + 1))

struct address_space;

#if NR_CPUS >= CONFIG_SPLIT_PTLOCK_CPUS
typedef atomic_long_t mm_counter_t;
#else  /* NR_CPUS < CONFIG_SPLIT_PTLOCK_CPUS */
typedef unsigned long mm_counter_t;
#endif /* NR_CPUS < CONFIG_SPLIT_PTLOCK_CPUS */

/*
 * Each physical page in the system has a struct page associated with
 * it to keep track of whatever it is we are using the page for at the
 * moment. Note that we have no way to track which tasks are using
 * a page, though if it is a pagecache page, rmap structures can tell us
 * who is mapping it.
 */
struct page {
	/* 一些独立于体系结构的标志位，例如PG_locked */
	unsigned long flags;		/* Atomic flags, some possibly
					 * updated asynchronously */
	/* 是一个使用计数， 表示内核中引用该页的次数。 在其值到达0时，
	 * 内核就知道page实例当前不使用， 因此可以删除。 如果其值大于0，
	 * 该实例决不会从内存删除 */
	atomic_t _count;		/* Usage count, see below. */
	/* C语言的联合很适合于该问题， 尽管它未能增加struct page的清晰程度。 考虑一个例子：
	 * 一个物理内存页能够通过多个地方的不同页表映射到虚拟地址空间， 内核想要跟踪有多少地
	 * 方映射了该页。 为此， structpage中有一个计数器用于计算映射的数目。 如果一页用于slub
	 * 分配器（将整页细分为更小部分的一种方法，请参见3.6.1节） ， 那么可以确保只有内核会
	 * 使用该页， 而不会有其他地方使用， 因此映射计数信息就是多余的。
	 * 因此内核可以重新解释该字段， 用来表示该页被细分为多少个小的内存对象使用  */
	union {
		/* 内存管理子系统中映射的页表项计数，表示页表中有多少项指向该页
		 * 用于表示页是否已经映射， 还用于限制逆向映射搜索*/
		atomic_t _mapcount;	/* Count of ptes mapped in mms,
					 * to show when page is mapped
					 * & limit reverse map searches.
					 */
		/* 用于SLUB分配器： 对象的数目 */
		unsigned int inuse;	/* SLUB: Nr of objects */
	};
	union {
	    struct {
		/* 由映射私有， 不透明数据：
		 * 如果设置了PagePrivate， 通常用于buffer_heads；
		 * 如果设置了PageSwapCache， 则用于swp_entry_t；
		 * 如果设置了PG_buddy， 则用于表示伙伴系统中的阶 */
		unsigned long private;		/* Mapping-private opaque data:
					 	 * usually used for buffer_heads
						 * if PagePrivate set; used for
						 * swp_entry_t if PageSwapCache;
						 * indicates order in the buddy
						 * system if PG_buddy is set.
						 */
		/* 如果最低位为0， 则指向inode address_space， 或为NULL。
		 * 如果页映射为匿名内存， 最低位置位，而且该指针指向anon_vma对象：
		 * 参见下文的PAGE_MAPPING_ANON。(struct address_space)实例总是对齐
		 * 到sizeof(long)，故而指向它的指针最低位一定是0
		 * 地址空间是一个非常一般的概念，例如，可以用在向内存读取文件时，
		 * 地址空间用于将文件的数据与装载数据的内存区关联起来。通过最低位，
		 * mapping不仅能够保存一个指针，而且还能包含一些额外的信息，用于判断
		 * 是否属于未关联到地址空间的某个匿名内存区（anon_vma），该结构对实现
		 * 匿名页的逆向映射很重要，将在4.11.2 阐述，如果使用了最低位，内核使用
		 * 这样的代码来恢复指针：
		 * anon_vma = (strucr anon_vma *)(mapping - PAGE_MAPPING_ANON) */
		struct address_space *mapping;	/* If low bit clear, points to
						 * inode address_space, or NULL.
						 * If page mapped as anonymous
						 * memory, low bit is set, and
						 * it points to anon_vma object:
						 * see PAGE_MAPPING_ANON below.
						 */
	    };
#if NR_CPUS >= CONFIG_SPLIT_PTLOCK_CPUS
	    spinlock_t ptl;
#endif
	    /* 用于SLUB分配器： 指向slab的指针 */
	    struct kmem_cache *slab;	/* SLUB: Pointer to slab */
	    /* 用于复合页的尾页， 指向首页。内核可以将多个毗连的页合并为
	     * 较大的复合页（compound page） 。 分组中的第一个页称作首页（headpage），
	     * 而所有其余各页叫做尾页（tail page） 。 所有尾页对应的page实例中，
	     * 都将first_page设置为指向首页 */
	    struct page *first_page;	/* Compound tail pages */
	};
	union {
		/* index是页帧在映射内部的偏移量 */
		pgoff_t index;		/* Our offset within mapping. */
		void *freelist;		/* SLUB: freelist req. slab lock */
	};
	/* 换出页列表， 例如由zone->lru_lock保护的active_list!
	 * lru是一个表头，以便将页面按不同类别分组，最重要的类别就是
	 * 活动和不活动页*/
	struct list_head lru;		/* Pageout list, eg. active_list
					 * protected by zone->lru_lock !
					 */
	/*
	 * On machines where all RAM is mapped into kernel address space,
	 * we can simply calculate the virtual address. On machines with
	 * highmem some memory is mapped into kernel virtual memory
	 * dynamically, so we need a place to store that address.
	 * Note that this field could be 16 bits on x86 ... ;)
	 *
	 * Architectures with slow multiplication can define
	 * WANT_PAGE_VIRTUAL in asm/page.h
	 */
	/* 按照预处理器语句#if defined(WANT_PAGE_VIRTUAL)， 只有定义了对应的宏，
	 * ‘’virtual才能成为struct page的一部分。 当前只有几个体系结构是这样，
	 * 即摩托罗拉m68k、 FRV和Extensa。所有其他体系结构都采用了一种不同的方
	 * 案来寻址虚拟内存页。 其核心是用来查找所有高端内存页帧的散列表。
	 * 3.5.8节会更详细地研究该技术。 处理散列表需要一些数学运算， 在前述的
	 * 计算机上比较慢， 因此只能选择这种直接的方法。
	 * */
#if defined(WANT_PAGE_VIRTUAL)
	/* 用于高端内存域的页，换言之，即无法直接映射到内核内存中的页，virtual
	 * 用于存储该页的虚拟地址 */
	/* 内核虚拟地址（如果没有映射则为NULL， 即高端内存） */
	void *virtual;			/* Kernel virtual address (NULL if
					   not kmapped, ie. highmem) */
#endif /* WANT_PAGE_VIRTUAL */
};

/*
 * This struct defines a memory VMM memory area. There is one of these
 * per VM-area/task.  A VM area is any part of the process virtual memory
 * space that has a special rule for the page-fault handlers (ie a shared
 * library, the executable area etc).
 */
struct vm_area_struct {
	struct mm_struct * vm_mm;	/* The address space we belong to. */
	unsigned long vm_start;		/* Our start address within vm_mm. */
	unsigned long vm_end;		/* The first byte after our end address
					   within vm_mm. */

	/* linked list of VM areas per task, sorted by address */
	struct vm_area_struct *vm_next;

	pgprot_t vm_page_prot;		/* Access permissions of this VMA. */
	/* see include/linux/mm.h  */
	unsigned long vm_flags;		/* Flags, listed below. */

	struct rb_node vm_rb;

	/*
	 * For areas with an address space and backing store,
	 * linkage into the address_space->i_mmap prio tree, or
	 * linkage to the list of like vmas hanging off its node, or
	 * linkage of vma in the address_space->i_mmap_nonlinear list.
	 */
	/* 从文件到进程的虚拟地址空间中的映射，可通过文件中的区间和内存
	 * 中对应的区间唯一地确定。为跟踪与进程关联的所有区间，内核使用
	 * 了如上所述的链表和红黑树。但还必须能够反向查询：给出文件中的
	 * 一个区间， 内核有时需要知道该区间映射到的所有进程。这种映射称
	 * 作共享映射（shared mapping），至于这种映射的必要性，看看系统
	 * 中几乎每个进程都使用的C标准库，读者就知道了。为提供所需的信息，
	 * 所有的vm_area_struct实例都还通过一个优先树管理，包含在shared
	 * 成员中。
	 * */
	union {
		struct {
			struct list_head list;
			void *parent;	/* aligns with prio_tree_node parent */
			struct vm_area_struct *head;
		} vm_set;

		struct raw_prio_tree_node prio_tree_node;
	} shared;

	/*
	 * A file's MAP_PRIVATE vma can be in both i_mmap tree and anon_vma
	 * list, after a COW of one of the file pages.	A MAP_SHARED vma
	 * can only be in the i_mmap tree.  An anonymous MAP_PRIVATE, stack
	 * or brk vma (with NULL file) can only be in an anon_vma list.
	 */
	/* anon_vma_node和anon_vma用于管理源自匿名映射（anonymous mapping）的共
	 * 享页。指向相同页的映射都保存在一个双链表上，anon_vma_node充当链表元素
	 * 有若干此类链表，具体的数目取决于共享物理内存页的映射集合的数目。
	 *
	 * anon_vma成员是一个指向与各链表关联的管理结构的指针，该管理结构由一个
	 * 表头和相关的锁组成
	 * */
	struct list_head anon_vma_node;	/* Serialized by anon_vma->lock */
	struct anon_vma *anon_vma;	/* Serialized by page_table_lock */

	/* Function pointers to deal with this struct. */
	struct vm_operations_struct * vm_ops;

	/* Information about our backing store: */
	/* 指定了文件映射的偏移量，该值用于只映射了文件部分内容时
	 * （如果映射了整个文件，则偏移量为0）
	 * */
	unsigned long vm_pgoff;		/* Offset (within vm_file) in PAGE_SIZE
					   units, *not* PAGE_CACHE_SIZE */
	struct file * vm_file;		/* File we map to (can be NULL). */
	void * vm_private_data;		/* was vm_pte (shared mem) */
	unsigned long vm_truncate_count;/* truncate_count or restart_addr */

#ifndef CONFIG_MMU
	atomic_t vm_usage;		/* refcount (VMAs shared if !MMU) */
#endif
#ifdef CONFIG_NUMA
	struct mempolicy *vm_policy;	/* NUMA policy for the VMA */
#endif
};

struct mm_struct {
	/* VMA是个单链表 */
	struct vm_area_struct * mmap;		/* list of VMAs */
	/* VMA是个红黑树 */
	struct rb_root mm_rb;
	struct vm_area_struct * mmap_cache;	/* last find_vma result */
	unsigned long (*get_unmapped_area) (struct file *filp,
				unsigned long addr, unsigned long len,
				unsigned long pgoff, unsigned long flags);
	void (*unmap_area) (struct mm_struct *mm, unsigned long addr);
	unsigned long mmap_base;		/* base of mmap area */
	unsigned long task_size;		/* size of task vm space */
	unsigned long cached_hole_size; 	/* if non-zero, the largest hole below free_area_cache */
	unsigned long free_area_cache;		/* first hole of size cached_hole_size or larger */
	pgd_t * pgd;
	atomic_t mm_users;			/* How many users with user space? */
	atomic_t mm_count;			/* How many references to "struct mm_struct" (users count as 1) */
	int map_count;				/* number of VMAs */
	struct rw_semaphore mmap_sem;
	spinlock_t page_table_lock;		/* Protects page tables and some counters */

	struct list_head mmlist;		/* List of maybe swapped mm's.	These are globally strung
						 * together off init_mm.mmlist, and are protected
						 * by mmlist_lock
						 */

	/* Special counters, in some configurations protected by the
	 * page_table_lock, in other configurations by being atomic.
	 */
	mm_counter_t _file_rss;
	mm_counter_t _anon_rss;

	unsigned long hiwater_rss;	/* High-watermark of RSS usage */
	unsigned long hiwater_vm;	/* High-water virtual memory usage */

	unsigned long total_vm, locked_vm, shared_vm, exec_vm;
	unsigned long stack_vm, reserved_vm, def_flags, nr_ptes;
	unsigned long start_code, end_code, start_data, end_data;
	unsigned long start_brk, brk, start_stack;
	unsigned long arg_start, arg_end, env_start, env_end;

	unsigned long saved_auxv[AT_VECTOR_SIZE]; /* for /proc/PID/auxv */

	cpumask_t cpu_vm_mask;

	/* Architecture-specific MM context */
	mm_context_t context;

	/* Swap token stuff */
	/*
	 * Last value of global fault stamp as seen by this process.
	 * In other words, this value gives an indication of how long
	 * it has been since this task got the token.
	 * Look at mm/thrash.c
	 */
	unsigned int faultstamp;
	unsigned int token_priority;
	unsigned int last_interval;

	unsigned long flags; /* Must use atomic bitops to access the bits */

	/* coredumping support */
	int core_waiters;
	struct completion *core_startup_done, core_done;

	/* aio bits */
	rwlock_t		ioctx_list_lock;
	struct kioctx		*ioctx_list;
};

#endif /* _LINUX_MM_TYPES_H */
