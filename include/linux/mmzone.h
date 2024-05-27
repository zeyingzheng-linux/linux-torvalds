#ifndef _LINUX_MMZONE_H
#define _LINUX_MMZONE_H

#ifdef __KERNEL__
#ifndef __ASSEMBLY__

#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/bitops.h>
#include <linux/cache.h>
#include <linux/threads.h>
#include <linux/numa.h>
#include <linux/init.h>
#include <linux/seqlock.h>
#include <linux/nodemask.h>
#include <linux/pageblock-flags.h>
#include <asm/atomic.h>
#include <asm/page.h>

/* Free memory management - zoned buddy allocator.  */
#ifndef CONFIG_FORCE_MAX_ZONEORDER
#define MAX_ORDER 11
#else
#define MAX_ORDER CONFIG_FORCE_MAX_ZONEORDER
#endif
#define MAX_ORDER_NR_PAGES (1 << (MAX_ORDER - 1))

/*
 * PAGE_ALLOC_COSTLY_ORDER is the order at which allocations are deemed
 * costly to service.  That is between allocation orders which should
 * coelesce naturally under reasonable reclaim pressure and those which
 * will not.
 */
#define PAGE_ALLOC_COSTLY_ORDER 3

/* 类型MIGRATE_UNMOVABLE、 MIGRATE_RECLAIMABLE和MIGRATE_MOVABLE已经介绍过。
 * 如果向具有特定可移动性的列表请求分配内存失败， 这种紧急情况下可从
 * MIGRATE_RESERVE分配内存（对应的列表在内存子系统初始化期间用
 * setup_zone_migrate_reserve填充， 我不会详细讨论相关的细节） 。
 * MIGRATE_ISOLATE是一个特殊的虚拟区域， 用于跨越NUMA结点移动物理内存页。
 * 在大型系统上， 它有益于将物理内存页移动到接近于使用该页最频繁的CPU。
 * MIGRATE_TYPES只是表示迁移类型的数目， 也不代表具体的区域
 * */
#define MIGRATE_UNMOVABLE     0
#define MIGRATE_RECLAIMABLE   1
#define MIGRATE_MOVABLE       2
#define MIGRATE_RESERVE       3
#define MIGRATE_ISOLATE       4 /* can't allocate from here */
#define MIGRATE_TYPES         5

#define for_each_migratetype_order(order, type) \
	for (order = 0; order < MAX_ORDER; order++) \
		for (type = 0; type < MIGRATE_TYPES; type++)

extern int page_group_by_mobility_disabled;

static inline int get_pageblock_migratetype(struct page *page)
{
	if (unlikely(page_group_by_mobility_disabled))
		return MIGRATE_UNMOVABLE;

	return get_pageblock_flags_group(page, PB_migrate, PB_migrate_end);
}

struct free_area {
	/* 用于连接空闲页的链表，页链表包含大小相同的连续内存区 */
	struct list_head	free_list[MIGRATE_TYPES];
	/* 空闲页块的数量，单位是order次方 */
	unsigned long		nr_free;
};

struct pglist_data;

/*
 * zone->lock and zone->lru_lock are two of the hottest locks in the kernel.
 * So add a wild amount of padding here to ensure that they fall into separate
 * cachelines.  There are very few zone structures in the machine, so space
 * consumption is not a concern here.
 */
#if defined(CONFIG_SMP)
struct zone_padding {
	char x[0];
} ____cacheline_internodealigned_in_smp;
#define ZONE_PADDING(name)	struct zone_padding name;
#else
#define ZONE_PADDING(name)
#endif

enum zone_stat_item {
	/* First 128 byte cacheline (assuming 64 bit words) */
	NR_FREE_PAGES,
	NR_INACTIVE,
	NR_ACTIVE,
	NR_ANON_PAGES,	/* Mapped anonymous pages */
	NR_FILE_MAPPED,	/* pagecache pages mapped into pagetables.
			   only modified from process context */
	NR_FILE_PAGES,
	NR_FILE_DIRTY,
	NR_WRITEBACK,
	/* Second 128 byte cacheline */
	NR_SLAB_RECLAIMABLE,
	NR_SLAB_UNRECLAIMABLE,
	NR_PAGETABLE,		/* used for pagetables */
	NR_UNSTABLE_NFS,	/* NFS unstable pages */
	NR_BOUNCE,
	NR_VMSCAN_WRITE,
#ifdef CONFIG_NUMA
	NUMA_HIT,		/* allocated in intended node */
	NUMA_MISS,		/* allocated in non intended node */
	NUMA_FOREIGN,		/* was intended here, hit elsewhere */
	NUMA_INTERLEAVE_HIT,	/* interleaver preferred this zone */
	NUMA_LOCAL,		/* allocation from local node */
	NUMA_OTHER,		/* allocation from other node */
#endif
	NR_VM_ZONE_STAT_ITEMS };

/* count记录了与该列表相关的页的数目， high是一个水印。 如果count的值超出了high
 * 则表明列表中的页太多了。 对容量过低的状态没有显式使用水印：
 * 如果列表中没有成员， 则重新填充
 * 如有可能， CPU的高速缓存不是用单个页来填充的， 而是用多个页组成的块 */
struct per_cpu_pages {
	int count;		/* number of pages in the list */
	int high;		/* high watermark, emptying needed */
	int batch;		/* chunk size for buddy add/remove */
	struct list_head list;	/* the list of pages */
};

/*
 * struct zone的pageset成员用于实现冷热分配器（hot-n-cold allocator） 。
 * 内核说页是热的， 意味着页已经加载到CPU高速缓存， 与在内存中的页相比，
 * 其数据能够更快地访问。 相反， 冷页则不在高速缓存中。 在多处理器系统上
 * 每个CPU都有一个或多个高速缓存， 各个CPU的管理必须是独立的
 * struct zone的pageset成员用于实现冷热分配器（hot-n-cold allocator） 。
 * 内核说页是热的， 意味着页已经加载到CPU高速缓存， 与在内存中的页相比，
 * 其数据能够更快地访问。 相反， 冷页则不在高速缓存中。 在多处理器系统上
 * 每个CPU都有一个或多个高速缓存， 各个CPU的管理必须是独立的
 * 所以zone里面，pageset是一个数组， 其容量与系统能够容纳的CPU数目的最大值相同
 * */
struct per_cpu_pageset {
	struct per_cpu_pages pcp[2];	/* 0: hot.  1: cold */
#ifdef CONFIG_NUMA
	s8 expire;
#endif
#ifdef CONFIG_SMP
	s8 stat_threshold;
	s8 vm_stat_diff[NR_VM_ZONE_STAT_ITEMS];
#endif
} ____cacheline_aligned_in_smp;

#ifdef CONFIG_NUMA
#define zone_pcp(__z, __cpu) ((__z)->pageset[(__cpu)])
#else
#define zone_pcp(__z, __cpu) (&(__z)->pageset[(__cpu)])
#endif

enum zone_type {
#ifdef CONFIG_ZONE_DMA
	/*
	 * ZONE_DMA is used when there are devices that are not able
	 * to do DMA to all of addressable memory (ZONE_NORMAL). Then we
	 * carve out the portion of memory that is needed for these devices.
	 * The range is arch specific.
	 *
	 * Some examples
	 *
	 * Architecture		Limit
	 * ---------------------------
	 * parisc, ia64, sparc	<4G
	 * s390			<2G
	 * arm			Various
	 * alpha		Unlimited or 0-16MB.
	 *
	 * i386, x86_64 and multiple other arches
	 * 			<16M.
	 */
	/* 标记适合DMA的内存域。 该区域的长度依赖于处理器类型。 在IA-32计算机上，
	 * 一般的限制是16 MiB， 这是由古老的ISA设备强加的边界。 但更现代的计算机
	 * 也可能受这一限制的影响
	 * */
	ZONE_DMA,
#endif
#ifdef CONFIG_ZONE_DMA32
	/*
	 * x86_64 needs two ZONE_DMAs because it supports devices that are
	 * only able to do DMA to the lower 16M but also 32 bit devices that
	 * can only do DMA areas below 4G.
	 */
	/* 标记了使用32位地址字可寻址、 适合DMA的内存域。 显然， 只有在64位系统上，
	 * 两种DMA内存域才有差别。 在32位计算机上， 本内存域是空的， 即长度为0 MiB。
	 * 在Alpha和AMD64系统
	 * */
	ZONE_DMA32,
#endif
	/*
	 * Normal addressable memory is in ZONE_NORMAL. DMA operations can be
	 * performed on pages in ZONE_NORMAL if the DMA devices support
	 * transfers to all addressable memory.
	 */
	/* 标记了可直接映射到内核段的普通内存域。 这是在所有体系结构上保证都会
	 * 存在的唯一内存域， 但无法保证该地址范围对应了实际的物理内存。 例如，
	 * 如果AMD64系统有2 GiB内存， 那么所有内存都属于ZONE_DMA32范围， 而
	 * ZONE_NORMAL则为空
	 * */
	ZONE_NORMAL,
#ifdef CONFIG_HIGHMEM
	/*
	 * A memory area that is only addressable by the kernel through
	 * mapping portions into its own address space. This is for example
	 * used by i386 to allow the kernel to address the memory beyond
	 * 900MB. The kernel will set up special mappings (page
	 * table entries on i386) for each page that the kernel needs to
	 * access.
	 */
	ZONE_HIGHMEM,
#endif
	/* 在防止物理内存碎片的机制中需要使用 */
	ZONE_MOVABLE,
	MAX_NR_ZONES
};

/*
 * When a memory allocation must conform to specific limitations (such
 * as being suitable for DMA) the caller will pass in hints to the
 * allocator in the gfp_mask, in the zone modifier bits.  These bits
 * are used to select a priority ordered list of memory zones which
 * match the requested limits. See gfp_zone() in include/linux/gfp.h
 */

/*
 * Count the active zones.  Note that the use of defined(X) outside
 * #if and family is not necessarily defined so ensure we cannot use
 * it later.  Use __ZONE_COUNT to work out how many shift bits we need.
 */
#define __ZONE_COUNT (			\
	  defined(CONFIG_ZONE_DMA)	\
	+ defined(CONFIG_ZONE_DMA32)	\
	+ 1				\
	+ defined(CONFIG_HIGHMEM)	\
	+ 1				\
)
#if __ZONE_COUNT < 2
#define ZONES_SHIFT 0
#elif __ZONE_COUNT <= 2
#define ZONES_SHIFT 1
#elif __ZONE_COUNT <= 4
#define ZONES_SHIFT 2
#else
#error ZONES_SHIFT -- too many zones configured adjust calculation
#endif
#undef __ZONE_COUNT

struct zone {
	/* Fields commonly accessed by the page allocator */
	/* pages_min、 pages_high、 pages_low是页换出时使用的“水印”。 如果内存不足，
	 * 内核可以将页写到硬盘。 这3个成员会影响交换守护进程的行为。
	 * 1. 如果空闲页多于pages_high， 则内存域的状态是理想的
	 * 2. 如果空闲页的数目低于pages_low， 则内核开始将页换出到硬盘
	 * 3. 如果空闲页的数目低于pages_min， 那么页回收工作的压力就比较大，
	 *    因为内存域中急需空闲页*/
	unsigned long		pages_min, pages_low, pages_high;
	/*
	 * We don't know if the memory that we're going to allocate will be freeable
	 * or/and it will be released eventually, so to avoid totally wasting several
	 * GB of ram we must reserve some of the lower zone memory (otherwise we risk
	 * to run OOM on the lower zones despite there's tons of freeable ram
	 * on the higher zones). This array is recalculated at runtime if the
	 * sysctl_lowmem_reserve_ratio sysctl changes.
	 */
	/* lowmem_reserve数组分别为各种内存域指定了若干页， 用于一些无论如何都不能失败的
	 * 关键性内存分配。 各个内存域的份额根据重要性确定 init_per_zone_pages_min
	 * 这个值起始就是 /proc/sys/vm/min_free_kbytes
	 * pages_min即按页计算的min_free_kbytes P116
	 * */
	unsigned long		lowmem_reserve[MAX_NR_ZONES];

	/* pageset是一个数组， 用于实现每个CPU的热/冷页帧列表。 内核使用这些列表来保存可
	 * 用于满足实现的“新鲜”页。 但冷热页帧对应的高速缓存状态不同： 有些页帧也很可能仍然
	 * 在高速缓存中， 因此可以快速访问， 故称之为热的； 未缓存的页帧与此相对，
	 * 故称之为冷的 */
	/* NR_CPUS是一个可以在编译时间配置的宏常数。 在单处理器系统上其值总是1， 针对SMP
	 * 系统编译的内核中， 其值可能在2和32（在64位系统上是64） 之间。
	 * 该值并不是系统中实际存在的CPU数目， 而是内核支持的CPU的最大数目 */
#ifdef CONFIG_NUMA
	int node;
	/*
	 * zone reclaim becomes active if more unmapped pages exist.
	 */
	unsigned long		min_unmapped_pages;
	unsigned long		min_slab_pages;
	struct per_cpu_pageset	*pageset[NR_CPUS];
#else
	struct per_cpu_pageset	pageset[NR_CPUS];
#endif
	/*
	 * free areas of different sizes
	 */
	spinlock_t		lock;
#ifdef CONFIG_MEMORY_HOTPLUG
	/* see spanned/present_pages for more description */
	seqlock_t		span_seqlock;
#endif
	/* free_area是同名数据结构的数组， 用于实现伙伴系统。 每个数组元素都表示某种固定长度
	 * 的一些连续内存区。 对于包含在每个区域中的空闲内存页的管理， free_area是一个起点 */
	struct free_area	free_area[MAX_ORDER];

#ifndef CONFIG_SPARSEMEM
	/*
	 * Flags for a pageblock_nr_pages block. See pageblock-flags.h.
	 * In SPARSEMEM, this map is stored in struct mem_section
	 */
	/* 每个内存域都提供了一个特殊的字段， 可以跟踪包含pageblock_nr_pages个页
	 * 的内存区的属性 */
	unsigned long		*pageblock_flags;
#endif /* CONFIG_SPARSEMEM */


	ZONE_PADDING(_pad1_)
	/* 第二部分涉及的结构成员，用来根据活动情况对内存域中使用的页进行编目。如果页面
	 * 访问频繁，则内核认为它是活动的，而不活动则相反。在需要换出页面的时候，如果可
	 * 能，频繁使用的页应该保持不动，而多余的不活动的页面则可以换出而没什么损害 */

	/* Fields commonly accessed by the page reclaim scanner */
	spinlock_t		lru_lock;	
	/* active_list是活动页的集合， 而inactive_list则不活动页的集合（page实例） */
	struct list_head	active_list;
	struct list_head	inactive_list;
	/* 内核需要扫描活动列表和惰性列表来查找可以在二者之间移动的页， 或从惰性列表回
	 * 收的页。 但完整的链表不可能一遍扫描完成， 每次只能扫描活动链表上的
	 * nr_scan_active个和惰性链表上的nr_scan_inactive个链表元素。 由于内核使用了LRU
	 * 方案， 这个数目是从链表尾部开始计算的。 pages_scanned记录的是前一遍回收时扫
	 * 描的页数， 而vm_stat提供了关于当前内存域的统计信息， 例如当前活动和不活动页
	 * 的数目。回想前文， 可知用于统计的成员vm_stat可以用辅助函数zone_page_state访问
	 * */
	/* nr_scan_active和nr_scan_inactive指定在回收内存时需要扫描的活动和不活动页的数目 */
	unsigned long		nr_scan_active;
	unsigned long		nr_scan_inactive;
	/* pages_scanned指定了上次换出一页以来， 有多少页成功扫描 */
	unsigned long		pages_scanned;	   /* since last reclaim */
	/* flags描述内存域的当前状态。 允许使用下列标志 */
	unsigned long		flags;		   /* zone flags, see below */

	/* Zone statistics */
	/* vm_stat维护了大量有关该内存域的统计信息。 由于其中维护的大部分信息目前没有多大
	 * 意义， 对该结构的详细讨论则延迟到17.7.1节。 现在， 只要知道内核中很多地方都会
	 * 更新其中的信息即可。辅助函数zone_page_state用来读取vm_stat中的信息:
	 * 例如， 可以将item参数设置为NR_ACTIVE或NR_INACTIVE， 来查询存储在上文讨论的
	 * active_list和inactive_list中的活动和不活动页的数目。 而设置为NR_FREE_PAGES则可
	 * 以获得内存域中空闲页的数目
	 * zone_page_state(struct zone *zone, enum zone_stat_item item)
	 * */
	atomic_long_t		vm_stat[NR_VM_ZONE_STAT_ITEMS];

	/*
	 * prev_priority holds the scanning priority for this zone.  It is
	 * defined as the scanning priority at which we achieved our reclaim
	 * target at the previous try_to_free_pages() or balance_pgdat()
	 * invokation.
	 *
	 * We use prev_priority as a measure of how much stress page reclaim is
	 * under - it drives the swappiness decision: whether to unmap mapped
	 * pages.
	 *
	 * Access to both this field is quite racy even on uniprocessor.  But
	 * it is expected to average out OK.
	 */
	/* prev_priority存储了上一次扫描操作扫描该内存域的优先级， 扫描操作是由try_to_free_pages
	 * 进行的， 直至释放足够的页帧（参见3.5.5节和第18章） 。 读者在第18章会看到， 扫描会根据
	 * 该值判断是否换出映射的页 */
	int prev_priority;


	ZONE_PADDING(_pad2_)
	/* Rarely used or read-mostly fields */

	/*
	 * wait_table		-- the array holding the hash table
	 * wait_table_hash_nr_entries	-- the size of the hash table array
	 * wait_table_bits	-- wait_table_size == (1 << wait_table_bits)
	 *
	 * The purpose of all these is to keep track of the people
	 * waiting for a page to become available and make them
	 * runnable again when possible. The trouble is that this
	 * consumes a lot of space, especially when so few things
	 * wait on pages at a given time. So instead of using
	 * per-page waitqueues, we use a waitqueue hash table.
	 *
	 * The bucket discipline is to sleep on the same queue when
	 * colliding and wake all in that wait queue when removing.
	 * When something wakes, it must check to be sure its page is
	 * truly available, a la thundering herd. The cost of a
	 * collision is great, but given the expected load of the
	 * table, they should be so rare as to be outweighed by the
	 * benefits from the saved space.
	 *
	 * __wait_on_page_locked() and unlock_page() in mm/filemap.c, are the
	 * primary users of these fields, and in mm/page_alloc.c
	 * free_area_init_core() performs the initialization of them.
	 */
	/* wait_table、 wait_table_bits和wait_table_hash_nr_entries实现了一个等待队列， 可用于
	 * 等待某一页变为可用进程。 该机制的细节将在第14章给出， 直观的概念是很好理解的： 进程排
	 * 成一个队列， 等待某些条件。 在条件变为真时， 内核会通知进程恢复工作 */
	wait_queue_head_t	* wait_table;
	unsigned long		wait_table_hash_nr_entries;
	unsigned long		wait_table_bits;

	/*
	 * Discontig memory support fields.
	 */
	/* 内存域和父结点之间的关联由zone_pgdat建立， zone_pgdat指向对应的pg_list_data实例 */
	struct pglist_data	*zone_pgdat;
	/* zone_start_pfn == zone_start_paddr >> PAGE_SHIFT */
	/* zone_start_pfn是内存域第一个页帧的索引 */
	unsigned long		zone_start_pfn;

	/*
	 * zone_start_pfn, spanned_pages and present_pages are all
	 * protected by span_seqlock.  It is a seqlock because it has
	 * to be read outside of zone->lock, and it is done in the main
	 * allocator path.  But, it is written quite infrequently.
	 *
	 * The lock is declared along with zone->lock because it is
	 * frequently read in proximity to zone->lock.  It's good to
	 * give them a chance of being in the same cacheline.
	 */
	/* spanned_pages指定内存域中页的总数， 但并非所有都是可用的。 前文提到过， 内存域中可能
	 * 有一些小的空洞。 另一个计数器（present_pages） 则给出了实际上可用的页数目。 该计数器
	 * 的值通常与spanned_pages相同 */
	unsigned long		spanned_pages;	/* total size, including holes */
	unsigned long		present_pages;	/* amount of memory (excluding holes) */

	/*
	 * rarely used fields:
	 */
	const char		*name;
} ____cacheline_internodealigned_in_smp;

/* 也有可能这些标志均未设置。 这是内存域的正常状态。 ZONE_ALL_UNRECLAIMABLE状态出现在内核试
 * 图重用该内存域的一些页时（页面回收， 参见第18章） ， 但因为所有的页都被钉住而无法回收。 例
 * 如， 用户空间应用程序可以使用mlock系统调用通知内核页不能从物理内存移出， 比如换出到磁盘上。
 * 这样的页称之为钉住的。 如果一个内存域中的所有页都被钉住， 那么该内存域是无法回收的， 即设置该
 * 标志。 为不浪费时间， 交换守护进程在寻找可供回收的页时， 只会简要地扫描一下此类内存域
 * 扫描是无法完全省去的， 因为该内存域经过若干时间后， 在将来可能再次包含可回收的页。 倘若如此，
 * 则消除该标志， 而kswapd守护进程会将该内存域与其他内存域同等对待
 *
 * 在SMP系统上， 多个CPU可能试图并发地回收一个内存域。 ZONE_RECLAIM_LOCKED标志可防止这种情况：
 * 如果一个CPU在回收某个内存域， 则设置该标志。 这防止了其他CPU的尝试
 *
 * ZONE_OOM_LOCKED专用于某种不走运的情况： 如果进程消耗了大量的内存， 致使必要的操作都无法完
 * 成， 那么内核会试图杀死消耗内存最多的进程， 以获得更多的空闲页。 该标志可以防止多个CPU同时进
 * 行这种操作
 * */

typedef enum {
	ZONE_ALL_UNRECLAIMABLE,		/* all pages pinned */
	ZONE_RECLAIM_LOCKED,		/* prevents concurrent reclaim */
	ZONE_OOM_LOCKED,		/* zone is in OOM killer zonelist */
} zone_flags_t;

static inline void zone_set_flag(struct zone *zone, zone_flags_t flag)
{
	set_bit(flag, &zone->flags);
}

static inline int zone_test_and_set_flag(struct zone *zone, zone_flags_t flag)
{
	return test_and_set_bit(flag, &zone->flags);
}

static inline void zone_clear_flag(struct zone *zone, zone_flags_t flag)
{
	clear_bit(flag, &zone->flags);
}

static inline int zone_is_all_unreclaimable(const struct zone *zone)
{
	return test_bit(ZONE_ALL_UNRECLAIMABLE, &zone->flags);
}

static inline int zone_is_reclaim_locked(const struct zone *zone)
{
	return test_bit(ZONE_RECLAIM_LOCKED, &zone->flags);
}

static inline int zone_is_oom_locked(const struct zone *zone)
{
	return test_bit(ZONE_OOM_LOCKED, &zone->flags);
}

/*
 * The "priority" of VM scanning is how much of the queues we will scan in one
 * go. A value of 12 for DEF_PRIORITY implies that we will scan 1/4096th of the
 * queues ("queue_length >> 12") during an aging round.
 */
#define DEF_PRIORITY 12

/* Maximum number of zones on a zonelist */
#define MAX_ZONES_PER_ZONELIST (MAX_NUMNODES * MAX_NR_ZONES)

#ifdef CONFIG_NUMA

/*
 * The NUMA zonelists are doubled becausse we need zonelists that restrict the
 * allocations to a single node for GFP_THISNODE.
 *
 * [0 .. MAX_NR_ZONES -1] 		: Zonelists with fallback
 * [MAZ_NR_ZONES ... MAZ_ZONELISTS -1]  : No fallback (GFP_THISNODE)
 */
#define MAX_ZONELISTS (2 * MAX_NR_ZONES)


/*
 * We cache key information from each zonelist for smaller cache
 * footprint when scanning for free pages in get_page_from_freelist().
 *
 * 1) The BITMAP fullzones tracks which zones in a zonelist have come
 *    up short of free memory since the last time (last_fullzone_zap)
 *    we zero'd fullzones.
 * 2) The array z_to_n[] maps each zone in the zonelist to its node
 *    id, so that we can efficiently evaluate whether that node is
 *    set in the current tasks mems_allowed.
 *
 * Both fullzones and z_to_n[] are one-to-one with the zonelist,
 * indexed by a zones offset in the zonelist zones[] array.
 *
 * The get_page_from_freelist() routine does two scans.  During the
 * first scan, we skip zones whose corresponding bit in 'fullzones'
 * is set or whose corresponding node in current->mems_allowed (which
 * comes from cpusets) is not set.  During the second scan, we bypass
 * this zonelist_cache, to ensure we look methodically at each zone.
 *
 * Once per second, we zero out (zap) fullzones, forcing us to
 * reconsider nodes that might have regained more free memory.
 * The field last_full_zap is the time we last zapped fullzones.
 *
 * This mechanism reduces the amount of time we waste repeatedly
 * reexaming zones for free memory when they just came up low on
 * memory momentarilly ago.
 *
 * The zonelist_cache struct members logically belong in struct
 * zonelist.  However, the mempolicy zonelists constructed for
 * MPOL_BIND are intentionally variable length (and usually much
 * shorter).  A general purpose mechanism for handling structs with
 * multiple variable length members is more mechanism than we want
 * here.  We resort to some special case hackery instead.
 *
 * The MPOL_BIND zonelists don't need this zonelist_cache (in good
 * part because they are shorter), so we put the fixed length stuff
 * at the front of the zonelist struct, ending in a variable length
 * zones[], as is needed by MPOL_BIND.
 *
 * Then we put the optional zonelist cache on the end of the zonelist
 * struct.  This optional stuff is found by a 'zlcache_ptr' pointer in
 * the fixed length portion at the front of the struct.  This pointer
 * both enables us to find the zonelist cache, and in the case of
 * MPOL_BIND zonelists, (which will just set the zlcache_ptr to NULL)
 * to know that the zonelist cache is not there.
 *
 * The end result is that struct zonelists come in two flavors:
 *  1) The full, fixed length version, shown below, and
 *  2) The custom zonelists for MPOL_BIND.
 * The custom MPOL_BIND zonelists have a NULL zlcache_ptr and no zlcache.
 *
 * Even though there may be multiple CPU cores on a node modifying
 * fullzones or last_full_zap in the same zonelist_cache at the same
 * time, we don't lock it.  This is just hint data - if it is wrong now
 * and then, the allocator will still function, perhaps a bit slower.
 */


struct zonelist_cache {
	unsigned short z_to_n[MAX_ZONES_PER_ZONELIST];		/* zone->nid */
	DECLARE_BITMAP(fullzones, MAX_ZONES_PER_ZONELIST);	/* zone full? */
	unsigned long last_full_zap;		/* when last zap'd (jiffies) */
};
#else
#define MAX_ZONELISTS MAX_NR_ZONES
struct zonelist_cache;
#endif

/*
 * One allocation request operates on a zonelist. A zonelist
 * is a list of zones, the first one is the 'goal' of the
 * allocation, the other zones are fallback zones, in decreasing
 * priority.
 *
 * If zlcache_ptr is not NULL, then it is just the address of zlcache,
 * as explained above.  If zlcache_ptr is NULL, there is no zlcache.
 */

struct zonelist {
	struct zonelist_cache *zlcache_ptr;		     // NULL or &zlcache
	/* 由于该备用列表必须包括所有结点的所有内存域，
	 * 因此由MAX_NUMNODES * MAX_NZ_ZONES项组成，
	 * 外加一个用于标记列表结束的空指针 */
	struct zone *zones[MAX_ZONES_PER_ZONELIST + 1];      // NULL delimited
#ifdef CONFIG_NUMA
	struct zonelist_cache zlcache;			     // optional ...
#endif
};

#ifdef CONFIG_NUMA
/*
 * Only custom zonelists like MPOL_BIND need to be filtered as part of
 * policies. As described in the comment for struct zonelist_cache, these
 * zonelists will not have a zlcache so zlcache_ptr will not be set. Use
 * that to determine if the zonelists needs to be filtered or not.
 */
static inline int alloc_should_filter_zonelist(struct zonelist *zonelist)
{
	return !zonelist->zlcache_ptr;
}
#else
static inline int alloc_should_filter_zonelist(struct zonelist *zonelist)
{
	return 0;
}
#endif /* CONFIG_NUMA */

#ifdef CONFIG_ARCH_POPULATES_NODE_MAP
/* start_pfn和end_pfn标记了一个连续内存区中的第一个和最后一个页帧，
 * nid是该内存区所属结点的NUMA ID。 UMA系统设置为0 */
struct node_active_region {
	unsigned long start_pfn;
	unsigned long end_pfn;
	int nid;
};
#endif /* CONFIG_ARCH_POPULATES_NODE_MAP */

#ifndef CONFIG_DISCONTIGMEM
/* The array of struct pages - for discontigmem use pgdat->lmem_map */
extern struct page *mem_map;
#endif

/*
 * The pg_data_t structure is used in machines with CONFIG_DISCONTIGMEM
 * (mostly NUMA machines?) to denote a higher-level memory zone than the
 * zone denotes.
 *
 * On NUMA machines, each NUMA node would have a pg_data_t to describe
 * it's memory layout.
 *
 * Memory statistics and page replacement data structures are maintained on a
 * per-zone basis.
 */
struct bootmem_data;
typedef struct pglist_data {
	/* node_zones是一个数组， 包含了结点中各内存域的数据结构
	 * 结点的内存域保存在node_zones[MAX_NR_ZONES]。 该数组总是
	 * 有3个项， 即使结点没有那么多内存域， 也是如此。 如果不
	 * 足3个， 则其余的数组项用0填充*/
	struct zone node_zones[MAX_NR_ZONES];
	/* node_zonelists指定了备用结点及其内存域的列表，
	 * 以便在当前结点没有可用空间时， 在备用结点分配内存。
	 * node_zonelists数组对每种可能的内存域类型， 都配置了
	 * 一个独立的数组项。 数组项包含了类型为zonelist的一个备用列表
	 * */
	struct zonelist node_zonelists[MAX_ZONELISTS];
	/* 结点中不同内存域的数目保存在nr_zones */
	int nr_zones;
#ifdef CONFIG_FLAT_NODE_MEM_MAP
	/* node_mem_map是指向page实例数组的指针，用于描述结点的所有
	 * 物理内存页。 它包含了结点中所有内存域的页 */
	struct page *node_mem_map;
#endif
	/* 在系统启动期间， 内存管理子系统初始化之前， 内核也需要使用
	 * 内存（另外， 还必须保留部分内存用于初始化内存管理子系统） 。
	 * 为解决这个问题， 内核使用了3.4.3节讲解的自举内存分配器
	 * bdata指向自举内存分配器数据结构的实例 */
	struct bootmem_data *bdata;
#ifdef CONFIG_MEMORY_HOTPLUG
	/*
	 * Must be held any time you expect node_start_pfn, node_present_pages
	 * or node_spanned_pages stay constant.  Holding this will also
	 * guarantee that any pfn_valid() stays that way.
	 *
	 * Nests above zone->lock and zone->size_seqlock.
	 */
	spinlock_t node_size_lock;
#endif
	/* node_start_pfn是该NUMA结点第一个页帧的逻辑编号。 系统中所有结点的
	 * 页帧是依次编号的， 每个页帧的号码都是全局唯一的（不只是结点内唯一）
	 * node_start_pfn在UMA系统中总是0， 因为其中只有一个结点， 因此其第一
	 * 个页帧编号总是0。node_present_pages指定了结点中页帧的数目， 而
	 * node_spanned_pages则给出了该结点以页帧为单位计算的长度。 二者的值不
	 * 一定相同， 因为结点中可能有一些空洞， 并不对应真正的页帧*/
	unsigned long node_start_pfn;
	unsigned long node_present_pages; /* total number of physical pages */
	unsigned long node_spanned_pages; /* total size of physical page
					     range, including holes */
	/* node_id是全局结点ID。 系统中的NUMA结点都从0开始编号 */
	int node_id;
	/* kswapd_wait是交换守护进程（swap daemon） 的等待队列， 在将页帧换出结点时
	 * 会用到（第18章会详细讨论该过程） 。 kswapd指向负责该结点的交换守护进程的
	 * task_struct。 kswapd_max_order用于页交换子系统的实现， 用来定义需要释放的
	 * 区域的长度（我们当前不感兴趣）  */
	wait_queue_head_t kswapd_wait;
	struct task_struct *kswapd;
	int kswapd_max_order;
} pg_data_t;

#define node_present_pages(nid)	(NODE_DATA(nid)->node_present_pages)
#define node_spanned_pages(nid)	(NODE_DATA(nid)->node_spanned_pages)
#ifdef CONFIG_FLAT_NODE_MEM_MAP
#define pgdat_page_nr(pgdat, pagenr)	((pgdat)->node_mem_map + (pagenr))
#else
#define pgdat_page_nr(pgdat, pagenr)	pfn_to_page((pgdat)->node_start_pfn + (pagenr))
#endif
#define nid_page_nr(nid, pagenr) 	pgdat_page_nr(NODE_DATA(nid),(pagenr))

#include <linux/memory_hotplug.h>

void get_zone_counts(unsigned long *active, unsigned long *inactive,
			unsigned long *free);
void build_all_zonelists(void);
void wakeup_kswapd(struct zone *zone, int order);
int zone_watermark_ok(struct zone *z, int order, unsigned long mark,
		int classzone_idx, int alloc_flags);
enum memmap_context {
	MEMMAP_EARLY,
	MEMMAP_HOTPLUG,
};
extern int init_currently_empty_zone(struct zone *zone, unsigned long start_pfn,
				     unsigned long size,
				     enum memmap_context context);

#ifdef CONFIG_HAVE_MEMORY_PRESENT
void memory_present(int nid, unsigned long start, unsigned long end);
#else
static inline void memory_present(int nid, unsigned long start, unsigned long end) {}
#endif

#ifdef CONFIG_NEED_NODE_MEMMAP_SIZE
unsigned long __init node_memmap_size_bytes(int, unsigned long, unsigned long);
#endif

/*
 * zone_idx() returns 0 for the ZONE_DMA zone, 1 for the ZONE_NORMAL zone, etc.
 */
#define zone_idx(zone)		((zone) - (zone)->zone_pgdat->node_zones)

static inline int populated_zone(struct zone *zone)
{
	return (!!zone->present_pages);
}

extern int movable_zone;

static inline int zone_movable_is_highmem(void)
{
#if defined(CONFIG_HIGHMEM) && defined(CONFIG_ARCH_POPULATES_NODE_MAP)
	return movable_zone == ZONE_HIGHMEM;
#else
	return 0;
#endif
}

static inline int is_highmem_idx(enum zone_type idx)
{
#ifdef CONFIG_HIGHMEM
	return (idx == ZONE_HIGHMEM ||
		(idx == ZONE_MOVABLE && zone_movable_is_highmem()));
#else
	return 0;
#endif
}

static inline int is_normal_idx(enum zone_type idx)
{
	return (idx == ZONE_NORMAL);
}

/**
 * is_highmem - helper function to quickly check if a struct zone is a 
 *              highmem zone or not.  This is an attempt to keep references
 *              to ZONE_{DMA/NORMAL/HIGHMEM/etc} in general code to a minimum.
 * @zone - pointer to struct zone variable
 */
static inline int is_highmem(struct zone *zone)
{
#ifdef CONFIG_HIGHMEM
	int zone_idx = zone - zone->zone_pgdat->node_zones;
	return zone_idx == ZONE_HIGHMEM ||
		(zone_idx == ZONE_MOVABLE && zone_movable_is_highmem());
#else
	return 0;
#endif
}

static inline int is_normal(struct zone *zone)
{
	return zone == zone->zone_pgdat->node_zones + ZONE_NORMAL;
}

static inline int is_dma32(struct zone *zone)
{
#ifdef CONFIG_ZONE_DMA32
	return zone == zone->zone_pgdat->node_zones + ZONE_DMA32;
#else
	return 0;
#endif
}

static inline int is_dma(struct zone *zone)
{
#ifdef CONFIG_ZONE_DMA
	return zone == zone->zone_pgdat->node_zones + ZONE_DMA;
#else
	return 0;
#endif
}

/* These two functions are used to setup the per zone pages min values */
struct ctl_table;
struct file;
int min_free_kbytes_sysctl_handler(struct ctl_table *, int, struct file *, 
					void __user *, size_t *, loff_t *);
extern int sysctl_lowmem_reserve_ratio[MAX_NR_ZONES-1];
int lowmem_reserve_ratio_sysctl_handler(struct ctl_table *, int, struct file *,
					void __user *, size_t *, loff_t *);
int percpu_pagelist_fraction_sysctl_handler(struct ctl_table *, int, struct file *,
					void __user *, size_t *, loff_t *);
int sysctl_min_unmapped_ratio_sysctl_handler(struct ctl_table *, int,
			struct file *, void __user *, size_t *, loff_t *);
int sysctl_min_slab_ratio_sysctl_handler(struct ctl_table *, int,
			struct file *, void __user *, size_t *, loff_t *);

extern int numa_zonelist_order_handler(struct ctl_table *, int,
			struct file *, void __user *, size_t *, loff_t *);
extern char numa_zonelist_order[];
#define NUMA_ZONELIST_ORDER_LEN 16	/* string buffer size */

#include <linux/topology.h>
/* Returns the number of the current Node. */
#ifndef numa_node_id
#define numa_node_id()		(cpu_to_node(raw_smp_processor_id()))
#endif

#ifndef CONFIG_NEED_MULTIPLE_NODES

extern struct pglist_data contig_page_data;
#define NODE_DATA(nid)		(&contig_page_data)
#define NODE_MEM_MAP(nid)	mem_map
#define MAX_NODES_SHIFT		1

#else /* CONFIG_NEED_MULTIPLE_NODES */

#include <asm/mmzone.h>

#endif /* !CONFIG_NEED_MULTIPLE_NODES */

extern struct pglist_data *first_online_pgdat(void);
extern struct pglist_data *next_online_pgdat(struct pglist_data *pgdat);
extern struct zone *next_zone(struct zone *zone);

/**
 * for_each_pgdat - helper macro to iterate over all nodes
 * @pgdat - pointer to a pg_data_t variable
 */
#define for_each_online_pgdat(pgdat)			\
	for (pgdat = first_online_pgdat();		\
	     pgdat;					\
	     pgdat = next_online_pgdat(pgdat))
/**
 * for_each_zone - helper macro to iterate over all memory zones
 * @zone - pointer to struct zone variable
 *
 * The user only needs to declare the zone variable, for_each_zone
 * fills it in.
 */
#define for_each_zone(zone)			        \
	for (zone = (first_online_pgdat())->node_zones; \
	     zone;					\
	     zone = next_zone(zone))

#ifdef CONFIG_SPARSEMEM
#include <asm/sparsemem.h>
#endif

#if BITS_PER_LONG == 32
/*
 * with 32 bit page->flags field, we reserve 9 bits for node/zone info.
 * there are 4 zones (3 bits) and this leaves 9-3=6 bits for nodes.
 */
#define FLAGS_RESERVED		9

#elif BITS_PER_LONG == 64
/*
 * with 64 bit flags field, there's plenty of room.
 */
#define FLAGS_RESERVED		32

#else

#error BITS_PER_LONG not defined

#endif

#if !defined(CONFIG_HAVE_ARCH_EARLY_PFN_TO_NID) && \
	!defined(CONFIG_ARCH_POPULATES_NODE_MAP)
#define early_pfn_to_nid(nid)  (0UL)
#endif

#ifdef CONFIG_FLATMEM
#define pfn_to_nid(pfn)		(0)
#endif

#define pfn_to_section_nr(pfn) ((pfn) >> PFN_SECTION_SHIFT)
#define section_nr_to_pfn(sec) ((sec) << PFN_SECTION_SHIFT)

#ifdef CONFIG_SPARSEMEM

/*
 * SECTION_SHIFT    		#bits space required to store a section #
 *
 * PA_SECTION_SHIFT		physical address to/from section number
 * PFN_SECTION_SHIFT		pfn to/from section number
 */
#define SECTIONS_SHIFT		(MAX_PHYSMEM_BITS - SECTION_SIZE_BITS)

#define PA_SECTION_SHIFT	(SECTION_SIZE_BITS)
#define PFN_SECTION_SHIFT	(SECTION_SIZE_BITS - PAGE_SHIFT)

#define NR_MEM_SECTIONS		(1UL << SECTIONS_SHIFT)

#define PAGES_PER_SECTION       (1UL << PFN_SECTION_SHIFT)
#define PAGE_SECTION_MASK	(~(PAGES_PER_SECTION-1))

#define SECTION_BLOCKFLAGS_BITS \
	((1UL << (PFN_SECTION_SHIFT - pageblock_order)) * NR_PAGEBLOCK_BITS)

#if (MAX_ORDER - 1 + PAGE_SHIFT) > SECTION_SIZE_BITS
#error Allocator MAX_ORDER exceeds SECTION_SIZE
#endif

struct page;
struct mem_section {
	/*
	 * This is, logically, a pointer to an array of struct
	 * pages.  However, it is stored with some other magic.
	 * (see sparse.c::sparse_init_one_section())
	 *
	 * Additionally during early boot we encode node id of
	 * the location of the section here to guide allocation.
	 * (see sparse.c::memory_present())
	 *
	 * Making it a UL at least makes someone do a cast
	 * before using it wrong.
	 */
	unsigned long section_mem_map;

	/* See declaration of similar field in struct zone */
	unsigned long *pageblock_flags;
};

#ifdef CONFIG_SPARSEMEM_EXTREME
#define SECTIONS_PER_ROOT       (PAGE_SIZE / sizeof (struct mem_section))
#else
#define SECTIONS_PER_ROOT	1
#endif

#define SECTION_NR_TO_ROOT(sec)	((sec) / SECTIONS_PER_ROOT)
#define NR_SECTION_ROOTS	(NR_MEM_SECTIONS / SECTIONS_PER_ROOT)
#define SECTION_ROOT_MASK	(SECTIONS_PER_ROOT - 1)

#ifdef CONFIG_SPARSEMEM_EXTREME
extern struct mem_section *mem_section[NR_SECTION_ROOTS];
#else
extern struct mem_section mem_section[NR_SECTION_ROOTS][SECTIONS_PER_ROOT];
#endif

static inline struct mem_section *__nr_to_section(unsigned long nr)
{
	if (!mem_section[SECTION_NR_TO_ROOT(nr)])
		return NULL;
	return &mem_section[SECTION_NR_TO_ROOT(nr)][nr & SECTION_ROOT_MASK];
}
extern int __section_nr(struct mem_section* ms);

/*
 * We use the lower bits of the mem_map pointer to store
 * a little bit of information.  There should be at least
 * 3 bits here due to 32-bit alignment.
 */
#define	SECTION_MARKED_PRESENT	(1UL<<0)
#define SECTION_HAS_MEM_MAP	(1UL<<1)
#define SECTION_MAP_LAST_BIT	(1UL<<2)
#define SECTION_MAP_MASK	(~(SECTION_MAP_LAST_BIT-1))
#define SECTION_NID_SHIFT	2

static inline struct page *__section_mem_map_addr(struct mem_section *section)
{
	unsigned long map = section->section_mem_map;
	map &= SECTION_MAP_MASK;
	return (struct page *)map;
}

static inline int present_section(struct mem_section *section)
{
	return (section && (section->section_mem_map & SECTION_MARKED_PRESENT));
}

static inline int present_section_nr(unsigned long nr)
{
	return present_section(__nr_to_section(nr));
}

static inline int valid_section(struct mem_section *section)
{
	return (section && (section->section_mem_map & SECTION_HAS_MEM_MAP));
}

static inline int valid_section_nr(unsigned long nr)
{
	return valid_section(__nr_to_section(nr));
}

static inline struct mem_section *__pfn_to_section(unsigned long pfn)
{
	return __nr_to_section(pfn_to_section_nr(pfn));
}

static inline int pfn_valid(unsigned long pfn)
{
	if (pfn_to_section_nr(pfn) >= NR_MEM_SECTIONS)
		return 0;
	return valid_section(__nr_to_section(pfn_to_section_nr(pfn)));
}

static inline int pfn_present(unsigned long pfn)
{
	if (pfn_to_section_nr(pfn) >= NR_MEM_SECTIONS)
		return 0;
	return present_section(__nr_to_section(pfn_to_section_nr(pfn)));
}

/*
 * These are _only_ used during initialisation, therefore they
 * can use __initdata ...  They could have names to indicate
 * this restriction.
 */
#ifdef CONFIG_NUMA
#define pfn_to_nid(pfn)							\
({									\
	unsigned long __pfn_to_nid_pfn = (pfn);				\
	page_to_nid(pfn_to_page(__pfn_to_nid_pfn));			\
})
#else
#define pfn_to_nid(pfn)		(0)
#endif

#define early_pfn_valid(pfn)	pfn_valid(pfn)
void sparse_init(void);
#else
#define sparse_init()	do {} while (0)
#define sparse_index_init(_sec, _nid)  do {} while (0)
#endif /* CONFIG_SPARSEMEM */

#ifdef CONFIG_NODES_SPAN_OTHER_NODES
#define early_pfn_in_nid(pfn, nid)	(early_pfn_to_nid(pfn) == (nid))
#else
#define early_pfn_in_nid(pfn, nid)	(1)
#endif

#ifndef early_pfn_valid
#define early_pfn_valid(pfn)	(1)
#endif

void memory_present(int nid, unsigned long start, unsigned long end);
unsigned long __init node_memmap_size_bytes(int, unsigned long, unsigned long);

/*
 * If it is possible to have holes within a MAX_ORDER_NR_PAGES, then we
 * need to check pfn validility within that MAX_ORDER_NR_PAGES block.
 * pfn_valid_within() should be used in this case; we optimise this away
 * when we have no holes within a MAX_ORDER_NR_PAGES block.
 */
#ifdef CONFIG_HOLES_IN_ZONE
#define pfn_valid_within(pfn) pfn_valid(pfn)
#else
#define pfn_valid_within(pfn) (1)
#endif

#endif /* !__ASSEMBLY__ */
#endif /* __KERNEL__ */
#endif /* _LINUX_MMZONE_H */
