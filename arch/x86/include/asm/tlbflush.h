/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_TLBFLUSH_H
#define _ASM_X86_TLBFLUSH_H

#include <linux/mm.h>
#include <linux/sched.h>

#include <asm/processor.h>
#include <asm/cpufeature.h>
#include <asm/special_insns.h>
#include <asm/smp.h>
#include <asm/invpcid.h>
#include <asm/pti.h>
#include <asm/processor-flags.h>

void __flush_tlb_all(void);

#define TLB_FLUSH_ALL	-1UL

void cr4_update_irqsoff(unsigned long set, unsigned long clear);
unsigned long cr4_read_shadow(void);

/* Set in this cpu's CR4. */
static inline void cr4_set_bits_irqsoff(unsigned long mask)
{
	cr4_update_irqsoff(mask, 0);
}

/* Clear in this cpu's CR4. */
static inline void cr4_clear_bits_irqsoff(unsigned long mask)
{
	cr4_update_irqsoff(0, mask);
}

/* Set in this cpu's CR4. */
static inline void cr4_set_bits(unsigned long mask)
{
	unsigned long flags;

	local_irq_save(flags);
	cr4_set_bits_irqsoff(mask);
	local_irq_restore(flags);
}

/* Clear in this cpu's CR4. */
static inline void cr4_clear_bits(unsigned long mask)
{
	unsigned long flags;

	local_irq_save(flags);
	cr4_clear_bits_irqsoff(mask);
	local_irq_restore(flags);
}

#ifndef MODULE
/*
 * 6 because 6 should be plenty and struct tlb_state will fit in two cache
 * lines.
 */
#define TLB_NR_DYN_ASIDS	6

/**
 * @brief Why don't merge this information into hte tlb_state ?
 * 
 */
struct tlb_context {
	u64 ctx_id;
	u64 tlb_gen;
};


/**
 * @brief Maintain the excuting process's TLB states.
 * 
 * Why does the tlb_state may not match the current->active_mm ?
 * 
 * What's the connection between tlb_state, current->active_mm and CR3 ?
 * 
 * [?] each process has such a structure ?
 * 
 */
struct tlb_state {
	/*
	 * cpu_tlbstate.loaded_mm should match CR3 whenever interrupts
	 * are on.  This means that it may not match current->active_mm,
	 * which will contain the previous user mm when we're in lazy TLB
	 * mode even if we've already switched back to swapper_pg_dir.
	 *
	 * During switch_mm_irqs_off(), loaded_mm will be set to
	 * LOADED_MM_SWITCHING during the brief interrupts-off window
	 * when CR3 and loaded_mm would otherwise be inconsistent.  This
	 * is for nmi_uaccess_okay()'s benefit.
	 */
	struct mm_struct *loaded_mm;

#define LOADED_MM_SWITCHING ((struct mm_struct *)1UL)

	/* Last user mm for optimizing IBPB */
	union {
		struct mm_struct	*last_user_mm;
		unsigned long		last_user_mm_ibpb;
	};

	u16 loaded_mm_asid; // asid should be the same as pcid
	u16 next_asid;

	/*
	 * If set we changed the page tables in such a way that we
	 * needed an invalidation of all contexts (aka. PCIDs / ASIDs).
	 * This tells us to go invalidate all the non-loaded ctxs[]
	 * on the next context switch.
	 *
	 * The current ctx was kept up-to-date as it ran and does not
	 * need to be invalidated.
	 */
	bool invalidate_other;

	/*
	 * Mask that contains TLB_NR_DYN_ASIDS+1 bits to indicate
	 * the corresponding user PCID needs a flush next time we
	 * switch to it; see SWITCH_TO_USER_CR3.
	 */
	unsigned short user_pcid_flush_mask;

	/*
	 * Access to this CR4 shadow and to H/W CR4 is protected by
	 * disabling interrupts when modifying either one.
	 */
	unsigned long cr4;

	/*
	 * This is a list of all contexts that might exist in the TLB.
	 * There is one per ASID that we use, and the ASID (what the
	 * CPU calls PCID) is the index into ctxts.
	 *
	 * For each context, ctx_id indicates which mm the TLB's user
	 * entries came from.  As an invariant, the TLB will never
	 * contain entries that are out-of-date as when that mm reached
	 * the tlb_gen in the list.
	 *
	 * To be clear, this means that it's legal for the TLB code to
	 * flush the TLB without updating tlb_gen.  This can happen
	 * (for now, at least) due to paravirt remote flushes.
	 *
	 * NB: context 0 is a bit special, since it's also used by
	 * various bits of init code.  This is fine -- code that
	 * isn't aware of PCID will end up harmlessly flushing
	 * context 0.
	 */
	struct tlb_context ctxs[TLB_NR_DYN_ASIDS];

	//
	// Hermit support
	
	// Direct-TLB stuff
	// each core  keeps 5 pages for the fake page table
	pgd_t *s_pgdp;
	p4d_t *s_p4dp;
	pud_t *s_pudp;
	pmd_t *s_pmdp;
	pte_t *s_ptep;
	// unsigned long s_last_ptep;
	// int generation;

};
DECLARE_PER_CPU_ALIGNED(struct tlb_state, cpu_tlbstate);

struct tlb_state_shared {
	/*
	 * We can be in one of several states:
	 *
	 *  - Actively using an mm.  Our CPU's bit will be set in
	 *    mm_cpumask(loaded_mm) and is_lazy == false;
	 *
	 *  - Not using a real mm.  loaded_mm == &init_mm.  Our CPU's bit
	 *    will not be set in mm_cpumask(&init_mm) and is_lazy == false.
	 *
	 *  - Lazily using a real mm.  loaded_mm != &init_mm, our bit
	 *    is set in mm_cpumask(loaded_mm), but is_lazy == true.
	 *    We're heuristically guessing that the CR3 load we
	 *    skipped more than makes up for the overhead added by
	 *    lazy mode.
	 */
	bool is_lazy;
};
DECLARE_PER_CPU_SHARED_ALIGNED(struct tlb_state_shared, cpu_tlbstate_shared);

bool nmi_uaccess_okay(void);
#define nmi_uaccess_okay nmi_uaccess_okay

/* Initialize cr4 shadow for this CPU. */
static inline void cr4_init_shadow(void)
{
	this_cpu_write(cpu_tlbstate.cr4, __read_cr4());
}

extern unsigned long mmu_cr4_features;
extern u32 *trampoline_cr4_features;

extern void initialize_tlbstate_and_flush(void);

/*
 * TLB flushing:
 *
 *  - flush_tlb_all() flushes all processes TLBs
 *  - flush_tlb_mm(mm) flushes the specified mm context TLB's
 *  - flush_tlb_page(vma, vmaddr) flushes one page
 *  - flush_tlb_range(vma, start, end) flushes a range of pages
 *  - flush_tlb_kernel_range(start, end) flushes a range of kernel pages
 *  - flush_tlb_multi(cpumask, info) flushes TLBs on multiple cpus
 *
 * ..but the i386 has somewhat limited tlb flushing capabilities,
 * and page-granular flushes are available only on i486 and up.
 */
struct flush_tlb_info {
	/*
	 * We support several kinds of flushes.
	 *
	 * - Fully flush a single mm.  .mm will be set, .end will be
	 *   TLB_FLUSH_ALL, and .new_tlb_gen will be the tlb_gen to
	 *   which the IPI sender is trying to catch us up.
	 *
	 * - Partially flush a single mm.  .mm will be set, .start and
	 *   .end will indicate the range, and .new_tlb_gen will be set
	 *   such that the changes between generation .new_tlb_gen-1 and
	 *   .new_tlb_gen are entirely contained in the indicated range.
	 *
	 * - Fully flush all mms whose tlb_gens have been updated.  .mm
	 *   will be NULL, .end will be TLB_FLUSH_ALL, and .new_tlb_gen
	 *   will be zero.
	 */
	struct mm_struct	*mm;
	unsigned long		start;
	unsigned long		end;
	u64			new_tlb_gen;
	unsigned int		initiating_cpu; // ? what does this mean ?
	u8			stride_shift;
	u8			freed_tables;
};

void flush_tlb_local(void);
void flush_tlb_one_user(unsigned long addr);
void flush_tlb_one_kernel(unsigned long addr);
void flush_tlb_multi(const struct cpumask *cpumask,
		      const struct flush_tlb_info *info);

#ifdef CONFIG_PARAVIRT
#include <asm/paravirt.h>
#endif

#define flush_tlb_mm(mm)						\
		flush_tlb_mm_range(mm, 0UL, TLB_FLUSH_ALL, 0UL, true)

#define flush_tlb_range(vma, start, end)				\
	flush_tlb_mm_range((vma)->vm_mm, start, end,			\
			   ((vma)->vm_flags & VM_HUGETLB)		\
				? huge_page_shift(hstate_vma(vma))	\
				: PAGE_SHIFT, false)

extern void flush_tlb_all(void);
extern void flush_tlb_mm_range(struct mm_struct *mm, unsigned long start,
				unsigned long end, unsigned int stride_shift,
				bool freed_tables);
extern void flush_tlb_kernel_range(unsigned long start, unsigned long end);

static inline void flush_tlb_page(struct vm_area_struct *vma, unsigned long a)
{
	flush_tlb_mm_range(vma->vm_mm, a, a + PAGE_SIZE, PAGE_SHIFT, false);
}

static inline u64 inc_mm_tlb_gen(struct mm_struct *mm)
{
	/*
	 * Bump the generation count.  This also serves as a full barrier
	 * that synchronizes with switch_mm(): callers are required to order
	 * their read of mm_cpumask after their writes to the paging
	 * structures.
	 */
	return atomic64_inc_return(&mm->context.tlb_gen);
}

static inline void arch_tlbbatch_add_mm(struct arch_tlbflush_unmap_batch *batch,
					struct mm_struct *mm)
{
	inc_mm_tlb_gen(mm);
	
	// gathering the cpu_bitmap info from sharing process
	cpumask_or(&batch->cpumask, &batch->cpumask, mm_cpumask(mm)); 
}

extern void arch_tlbbatch_flush(struct arch_tlbflush_unmap_batch *batch);


//
// Hermit support


extern int arch_init_sw_tlb(bool primary);
extern void arch_deinit_sw_tlb(void);

static inline int arch_can_push_to_tlb(pte_t pte)
{
	// pte is non dirty, skip ?
	if ((pte_flags(pte) & (_PAGE_RW | _PAGE_DIRTY)) == _PAGE_RW)
		return false;

	// can not be _PAGE_GLOBAL
	// This flag is used to prevent ordinary TLB flushes from evicting this page's mapping from the TLB.
	return (pte_flags(pte) & (_PAGE_NX | _PAGE_USER | _PAGE_GLOBAL | _PAGE_PRESENT)) \
		== (_PAGE_NX | _PAGE_USER | _PAGE_PRESENT);
}

// push a fake pte into TLB
void arch_push_to_tlb(struct mm_struct *mm, unsigned long addr, pmd_t *pmd, int n_entries, unsigned int flags);

// Record pte for TLB batch flushing
extern void hermit_arch_tlbbatch_add_flush_range(struct hermit_tlbflush_unmap_batch *batch,
					struct mm_struct *mm, unsigned long address, int cpu);


// Do the  TLB batch flusing operation
extern void hermit_arch_tlbbatch_flush(struct hermit_tlbflush_unmap_batch *batch);

// Do the TLB flushing operations according the flush_tlb_info
extern void hermit_flush_tlb_mm_entries(struct flush_tlb_info *info);



/**
 * @brief Judge if we really need a TLB flush for the unmapping.
 * 	In some situations, the corresponding TLB entries is already flushed
 * 	and we can omit this one.
 * @param mm 
 * @param pte 
 * @param epte 
 * @param cpu 
 * @return true 
 * @return false 
 */
static inline bool pte_need_flush(struct mm_struct *mm, pte_t pte,
				  epte_t epte, int *cpu)
{
	int cur_gen;

	// default vlaue,  -1 means the pte is shared between cores.
	// We need to send IPI to other cores
	*cpu = -1;

	if (pte_young(pte)) // the ACCESSED_BIT of this pte is set
		return true; // a multi tlb flushing

	// ?? fix me ??
	// not support yet

	// /* disabled - need on all, uncached - no need */
	// if (epte.generation < EPTE_GEN_MIN)
	// 	return epte.generation == EPTE_GEN_DISABLED;

	// cur_gen = atomic_read(&mm->flush_cnt);
	// if (epte.generation != cur_gen &&
	//     next_flush_gen(epte.generation) != cur_gen)
	// 	return false;

	/* local to certain cpu */
	*cpu = (int)epte.cpu_plus_one - 1; // a single TLB shootdown

	return true;
}




static inline void set_flush_tlb_n_pages(struct flush_tlb_entry *entry,
					 unsigned long n_pages)
{
	entry->n_pages = min_t(unsigned long, TLB_FLUSH_ALL_LEN, n_pages);
}


static inline void set_flush_tlb_entry_range(struct flush_tlb_entry *entry,
				       unsigned long start, unsigned long end)
{
	entry->vpn = start >> PAGE_SHIFT;
	set_flush_tlb_n_pages(entry, (end >> PAGE_SHIFT) - (start >> PAGE_SHIFT));
}

/* Each entry is either kernel, mm-specific or cpu-specific */
static inline void set_flush_tlb_entry_mm(struct flush_tlb_entry *entry,
					  struct mm_struct *mm)
{
	entry->mm = mm;
	entry->kernel = 0;
}


// End of Hermit
//


#endif /* !MODULE */

#endif /* _ASM_X86_TLBFLUSH_H */
