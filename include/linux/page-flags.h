/*
 * Macros for manipulating and testing page->flags
 */

#ifndef PAGE_FLAGS_H
#define PAGE_FLAGS_H

#include <linux/types.h>
#include <linux/mm_types.h>

/*
 * Various page->flags bits:
 *
 * PG_reserved is set for special pages, which can never be swapped out. Some
 * of them might not even exist (eg empty_bad_page)...
 *
 * The PG_private bitflag is set on pagecache pages if they contain filesystem
 * specific data (which is normally at page->private). It can be used by
 * private allocations for its own usage.
 *
 * During initiation of disk I/O, PG_locked is set. This bit is set before I/O
 * and cleared when writeback _starts_ or when read _completes_. PG_writeback
 * is set before writeback starts and cleared when it finishes.
 *
 * PG_locked also pins a page in pagecache, and blocks truncation of the file
 * while it is held.
 *
 * page_waitqueue(page) is a wait queue of all tasks waiting for the page
 * to become unlocked.
 *
 * PG_uptodate tells whether the page's contents is valid.  When a read
 * completes, the page becomes uptodate, unless a disk I/O error happened.
 *
 * PG_referenced, PG_reclaim are used for page reclaim for anonymous and
 * file-backed pagecache (see mm/vmscan.c).
 *
 * PG_error is set to indicate that an I/O error occurred on this page.
 *
 * PG_arch_1 is an architecture specific page state bit.  The generic code
 * guarantees that this bit is cleared for a page when it first is entered into
 * the page cache.
 *
 * PG_highmem pages are not permanently mapped into the kernel virtual address
 * space, they need to be kmapped separately for doing IO on the pages.  The
 * struct page (these bits with information) are always mapped into kernel
 * address space...
 *
 * PG_buddy is set to indicate that the page is free and in the buddy system
 * (see mm/page_alloc.c).
 *
 */

/*
 * Don't use the *_dontuse flags.  Use the macros.  Otherwise you'll break
 * locked- and dirty-page accounting.
 *
 * The page flags field is split into two parts, the main flags area
 * which extends from the low bits upwards, and the fields area which
 * extends from the high bits downwards.
 *
 *  | FIELD | ... | FLAGS |
 *  N-1     ^             0
 *          (N-FLAGS_RESERVED)
 *
 * The fields area is reserved for fields mapping zone, node and SPARSEMEM
 * section.  The boundry between these two areas is defined by
 * FLAGS_RESERVED which defines the width of the fields section
 * (see linux/mmzone.h).  New flags must _not_ overlap with this area.
 */
/* PG_locked指定了页是否锁定。 如果该比特位置位， 内核的其他部分不允许访问该页。
 * 这防止了内存管理出现竞态条件， 例如， 在从硬盘读取数据到页帧时  */
#define PG_locked	 	 0	/* Page is locked. Don't touch. */
/* 如果在涉及该页的I/O操作期间发生错误 */
#define PG_error		 1
/* PG_referenced和PG_active控制了系统使用该页的活跃程度。
 * 在页交换子系统选择换出页时， 该信息是很重要的 */
#define PG_referenced		 2
/* 表示页的数据已经从块设备读取， 其间没有出错 */
#define PG_uptodate		 3

/* 如果与硬盘上的数据相比， 页的内容已经改变， 则置位PG_dirty */
#define PG_dirty	 	 4
/* PG_lru有助于实现页面回收和切换。 内核使用两个最近最少使用
 * （least recently used， lru） 链表8来区别活动和不活动页。
 * 如果页在其中一个链表中， 则设置该比特位。 还有一个PG_active标志，
 * 如果页在活动页链表中， 则设置该标志。
 * 频繁使用的项自动排到链表最靠前的位置， 而不活动项总是向链表末尾方向移动 */
#define PG_lru			 5
/* PG_referenced和PG_active控制了系统使用该页的活跃程度。
 * 在页交换子系统选择换出页时， 该信息是很重要的 */
#define PG_active		 6
/* 如果页是3.6节讨论的slab分配器的一部分， 则设置PG_slab位 */
#define PG_slab			 7	/* slab debug (Suparna wants this) */

#define PG_owner_priv_1		 8	/* Owner use. If pagecache, fs may use*/
#define PG_arch_1		 9
#define PG_reserved		10
/* 如果page结构的private成员非空， 则必须设置PG_private位
 * 用于I/O的页， 可使用该字段将页细分为多个缓冲区
 * 但内核的其他部分也有各种不同的方法， 将私有数据附加页面上 */
#define PG_private		11	/* If pagecache, has fs-private data */

/* 如果页的内容处于向块设备回写的过程中， 则需要设置PG_writeback位 */
#define PG_writeback		12	/* Page is under writeback */
/* 表示该页属于一个更大的复合页， 复合页由多个毗连的普通页组成 */
#define PG_compound		14	/* Part of a compound page */
/* 如果页处于交换缓存， 则设置PG_swapcache位。
 * 在这种情况下， private包含一个类型为swap_entry_t的项 */
#define PG_swapcache		15	/* Swap page: swp_entry_t in private */

#define PG_mappedtodisk		16	/* Has blocks allocated on-disk */
/* 在可用内存的数量变少时， 内核试图周期性地回收页， 即剔除不活动、 未用的页
 * 在内核决定回收某个特定的页之后， 需要设置PG_reclaim标志通知 */
#define PG_reclaim		17	/* To be reclaimed asap */
/* 如果页空闲且包含在伙伴系统的列表中， 则设置PG_buddy位
 * 伙伴系统是页分配机制的核心 */
#define PG_buddy		19	/* Page is free, on buddy lists */

/* PG_readahead is only used for file reads; PG_reclaim is only for writes */
#define PG_readahead		PG_reclaim /* Reminder to do async read-ahead */

/* PG_owner_priv_1 users should have descriptive aliases */
#define PG_checked		PG_owner_priv_1 /* Used by some filesystems */
#define PG_pinned		PG_owner_priv_1	/* Xen pinned pagetable */

#if (BITS_PER_LONG > 32)
/*
 * 64-bit-only flags build down from bit 31
 *
 * 32 bit  -------------------------------| FIELDS |       FLAGS         |
 * 64 bit  |           FIELDS             | ??????         FLAGS         |
 *         63                            32                              0
 */
#define PG_uncached		31	/* Page has been mapped as uncached */
#endif

/*
 * Manipulation of page state flags
 */
#define PageLocked(page)		\
		test_bit(PG_locked, &(page)->flags)
#define SetPageLocked(page)		\
		set_bit(PG_locked, &(page)->flags)
#define TestSetPageLocked(page)		\
		test_and_set_bit(PG_locked, &(page)->flags)
#define ClearPageLocked(page)		\
		clear_bit(PG_locked, &(page)->flags)
#define TestClearPageLocked(page)	\
		test_and_clear_bit(PG_locked, &(page)->flags)

#define PageError(page)		test_bit(PG_error, &(page)->flags)
#define SetPageError(page)	set_bit(PG_error, &(page)->flags)
#define ClearPageError(page)	clear_bit(PG_error, &(page)->flags)

#define PageReferenced(page)	test_bit(PG_referenced, &(page)->flags)
#define SetPageReferenced(page)	set_bit(PG_referenced, &(page)->flags)
#define ClearPageReferenced(page)	clear_bit(PG_referenced, &(page)->flags)
#define TestClearPageReferenced(page) test_and_clear_bit(PG_referenced, &(page)->flags)

#define PageUptodate(page)	test_bit(PG_uptodate, &(page)->flags)
#ifdef CONFIG_S390
static inline void SetPageUptodate(struct page *page)
{
	if (!test_and_set_bit(PG_uptodate, &page->flags))
		page_clear_dirty(page);
}
#else
#define SetPageUptodate(page)	set_bit(PG_uptodate, &(page)->flags)
#endif
#define ClearPageUptodate(page)	clear_bit(PG_uptodate, &(page)->flags)

#define PageDirty(page)		test_bit(PG_dirty, &(page)->flags)
#define SetPageDirty(page)	set_bit(PG_dirty, &(page)->flags)
#define TestSetPageDirty(page)	test_and_set_bit(PG_dirty, &(page)->flags)
#define ClearPageDirty(page)	clear_bit(PG_dirty, &(page)->flags)
#define __ClearPageDirty(page)	__clear_bit(PG_dirty, &(page)->flags)
#define TestClearPageDirty(page) test_and_clear_bit(PG_dirty, &(page)->flags)

#define PageLRU(page)		test_bit(PG_lru, &(page)->flags)
#define SetPageLRU(page)	set_bit(PG_lru, &(page)->flags)
#define ClearPageLRU(page)	clear_bit(PG_lru, &(page)->flags)
#define __ClearPageLRU(page)	__clear_bit(PG_lru, &(page)->flags)

#define PageActive(page)	test_bit(PG_active, &(page)->flags)
#define SetPageActive(page)	set_bit(PG_active, &(page)->flags)
#define ClearPageActive(page)	clear_bit(PG_active, &(page)->flags)
#define __ClearPageActive(page)	__clear_bit(PG_active, &(page)->flags)

#define PageSlab(page)		test_bit(PG_slab, &(page)->flags)
#define __SetPageSlab(page)	__set_bit(PG_slab, &(page)->flags)
#define __ClearPageSlab(page)	__clear_bit(PG_slab, &(page)->flags)

#ifdef CONFIG_HIGHMEM
#define PageHighMem(page)	is_highmem(page_zone(page))
#else
#define PageHighMem(page)	0 /* needed to optimize away at compile time */
#endif

#define PageChecked(page)	test_bit(PG_checked, &(page)->flags)
#define SetPageChecked(page)	set_bit(PG_checked, &(page)->flags)
#define ClearPageChecked(page)	clear_bit(PG_checked, &(page)->flags)

#define PagePinned(page)	test_bit(PG_pinned, &(page)->flags)
#define SetPagePinned(page)	set_bit(PG_pinned, &(page)->flags)
#define ClearPagePinned(page)	clear_bit(PG_pinned, &(page)->flags)

#define PageReserved(page)	test_bit(PG_reserved, &(page)->flags)
#define SetPageReserved(page)	set_bit(PG_reserved, &(page)->flags)
#define ClearPageReserved(page)	clear_bit(PG_reserved, &(page)->flags)
#define __ClearPageReserved(page)	__clear_bit(PG_reserved, &(page)->flags)

#define SetPagePrivate(page)	set_bit(PG_private, &(page)->flags)
#define ClearPagePrivate(page)	clear_bit(PG_private, &(page)->flags)
#define PagePrivate(page)	test_bit(PG_private, &(page)->flags)
#define __SetPagePrivate(page)  __set_bit(PG_private, &(page)->flags)
#define __ClearPagePrivate(page) __clear_bit(PG_private, &(page)->flags)

/*
 * Only test-and-set exist for PG_writeback.  The unconditional operators are
 * risky: they bypass page accounting.
 */
#define PageWriteback(page)	test_bit(PG_writeback, &(page)->flags)
#define TestSetPageWriteback(page) test_and_set_bit(PG_writeback,	\
							&(page)->flags)
#define TestClearPageWriteback(page) test_and_clear_bit(PG_writeback,	\
							&(page)->flags)

#define PageBuddy(page)		test_bit(PG_buddy, &(page)->flags)
#define __SetPageBuddy(page)	__set_bit(PG_buddy, &(page)->flags)
#define __ClearPageBuddy(page)	__clear_bit(PG_buddy, &(page)->flags)

#define PageMappedToDisk(page)	test_bit(PG_mappedtodisk, &(page)->flags)
#define SetPageMappedToDisk(page) set_bit(PG_mappedtodisk, &(page)->flags)
#define ClearPageMappedToDisk(page) clear_bit(PG_mappedtodisk, &(page)->flags)

#define PageReadahead(page)	test_bit(PG_readahead, &(page)->flags)
#define SetPageReadahead(page)	set_bit(PG_readahead, &(page)->flags)
#define ClearPageReadahead(page) clear_bit(PG_readahead, &(page)->flags)

#define PageReclaim(page)	test_bit(PG_reclaim, &(page)->flags)
#define SetPageReclaim(page)	set_bit(PG_reclaim, &(page)->flags)
#define ClearPageReclaim(page)	clear_bit(PG_reclaim, &(page)->flags)
#define TestClearPageReclaim(page) test_and_clear_bit(PG_reclaim, &(page)->flags)

#define PageCompound(page)	test_bit(PG_compound, &(page)->flags)
#define __SetPageCompound(page)	__set_bit(PG_compound, &(page)->flags)
#define __ClearPageCompound(page) __clear_bit(PG_compound, &(page)->flags)

/*
 * PG_reclaim is used in combination with PG_compound to mark the
 * head and tail of a compound page
 *
 * PG_compound & PG_reclaim	=> Tail page
 * PG_compound & ~PG_reclaim	=> Head page
 */

#define PG_head_tail_mask ((1L << PG_compound) | (1L << PG_reclaim))

#define PageTail(page)	((page->flags & PG_head_tail_mask) \
				== PG_head_tail_mask)

static inline void __SetPageTail(struct page *page)
{
	page->flags |= PG_head_tail_mask;
}

static inline void __ClearPageTail(struct page *page)
{
	page->flags &= ~PG_head_tail_mask;
}

#define PageHead(page)	((page->flags & PG_head_tail_mask) \
				== (1L << PG_compound))
#define __SetPageHead(page)	__SetPageCompound(page)
#define __ClearPageHead(page)	__ClearPageCompound(page)

#ifdef CONFIG_SWAP
#define PageSwapCache(page)	test_bit(PG_swapcache, &(page)->flags)
#define SetPageSwapCache(page)	set_bit(PG_swapcache, &(page)->flags)
#define ClearPageSwapCache(page) clear_bit(PG_swapcache, &(page)->flags)
#else
#define PageSwapCache(page)	0
#endif

#define PageUncached(page)	test_bit(PG_uncached, &(page)->flags)
#define SetPageUncached(page)	set_bit(PG_uncached, &(page)->flags)
#define ClearPageUncached(page)	clear_bit(PG_uncached, &(page)->flags)

struct page;	/* forward declaration */

extern void cancel_dirty_page(struct page *page, unsigned int account_size);

int test_clear_page_writeback(struct page *page);
int test_set_page_writeback(struct page *page);

static inline void set_page_writeback(struct page *page)
{
	test_set_page_writeback(page);
}

#endif	/* PAGE_FLAGS_H */
