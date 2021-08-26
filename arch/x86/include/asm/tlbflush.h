#ifndef _ASM_X86_TLBFLUSH_H
#define _ASM_X86_TLBFLUSH_H

#include <linux/mm.h>
#include <linux/sched.h>

#include <asm/processor.h>
#include <asm/special_insns.h>

#ifdef CONFIG_PARAVIRT
#include <asm/paravirt.h>
#else
#define __flush_tlb() __native_flush_tlb()
#define __flush_tlb_global() __native_flush_tlb_global()
#define __flush_tlb_single(addr) __native_flush_tlb_single(addr)
#endif

static inline int next_flush_gen(int gen)
{
	return max_t(int, EPTE_GEN_MIN, (gen + 1) & FLUSH_GEN_MASK);
}

static inline void finish_tlb_flush_tracking(struct mm_struct *mm, int cpu)
{
	int i;
	cpumask_t temp, removed;
	int nr_cpus;

	if (!mm)
		return;

	/*
	 * We may have missed flushes in the meanwhile; since we
	 * anyhow need to check it is not empty, it is a good
	 * time to check
	 */
	if (!cpumask_empty(mm->cpu_vm_flush_mask_var))
		return;

	if (!spin_trylock(&mm->flush_gen_lock))
		return;

	if (!cpumask_empty(mm->cpu_vm_flush_mask_var))
		goto out;

	/* open coded */
	cpumask_copy(&temp, mm_cpumask(mm));
	nr_cpus = nr_cpu_ids;
	for (i = 0; i < (nr_cpus + BITS_PER_LONG - 1) / BITS_PER_LONG; i++) {
		unsigned long *dst_bits = ((unsigned long *)cpumask_bits(mm->cpu_vm_flush_mask_var)) + i;
		unsigned long *src_bits = ((unsigned long *)cpumask_bits(&temp)) + i;
		xchg(dst_bits, *src_bits);
	}
	cpumask_copy(&temp,  mm->cpu_vm_flush_mask_var);
	if (cpumask_andnot(&removed, &temp, mm_cpumask(mm))) {
		for_each_cpu(i, &removed)
			cpumask_clear_cpu(i, mm->cpu_vm_flush_mask_var);
	}
	atomic_set(&mm->flush_cnt,
		   next_flush_gen(atomic_read(&mm->flush_cnt)));
out:
	spin_unlock(&mm->flush_gen_lock);
}

static inline void set_flush_tlb_n_pages(struct flush_tlb_entry *entry,
					 unsigned long n_pages)
{
	entry->n_pages = min_t(unsigned long, TLB_FLUSH_ALL_LEN, n_pages);
}

static inline void add_flush_tlb_page(struct flush_tlb_entry *entry)
{
	set_flush_tlb_n_pages(entry, entry->n_pages + 1);
}

static inline void set_flush_tlb_entry_range(struct flush_tlb_entry *entry,
				       unsigned long start, unsigned long end)
{
	entry->vpn = start >> PAGE_SHIFT;
	set_flush_tlb_n_pages(entry,
			      (end >> PAGE_SHIFT) - (start >> PAGE_SHIFT));
}

static inline void set_flush_tlb_entry_all_mm(struct flush_tlb_entry *entry)
{
	entry->mm = NULL;
	entry->kernel = 0;
	entry->cpu_specific = 0;
}

static inline void set_flush_tlb_entry_full(struct flush_tlb_entry *entry)
{
	entry->n_pages = TLB_FLUSH_ALL_LEN;
}

static inline
unsigned long get_flush_tlb_entry_addr(const struct flush_tlb_entry *entry)
{
	return (unsigned long)(((long)entry->vpn << (BITS_PER_LONG - 36))
						>> (BITS_PER_LONG - 48));
}

static inline unsigned long flush_tlb_entry_end(struct flush_tlb_entry *entry)
{
	return get_flush_tlb_entry_addr(entry) + (entry->n_pages << PAGE_SHIFT);
}

static inline void set_flush_tlb_entry_kernel(struct flush_tlb_entry *entry)
{
	entry->n_pages = TLB_FLUSH_ALL_LEN;
	entry->mm = NULL;
	entry->kernel = 1;
}

/* Each entry is either kernel, mm-specific or cpu-specific */
static inline void set_flush_tlb_entry_mm(struct flush_tlb_entry *entry,
					  struct mm_struct *mm)
{
	entry->mm = mm;
	entry->kernel = 0;
}

static inline void set_flush_tlb_entry_current(struct flush_tlb_entry *entry)
{
	set_flush_tlb_entry_mm(entry, current->mm);
}

struct tlb_state {
#ifdef CONFIG_SMP
	struct mm_struct *active_mm;
	struct task_struct *active_task;
	int state;
	int nearly_lazy_cnt;
#endif

	/*
	 * Access to this CR4 shadow and to H/W CR4 is protected by
	 * disabling interrupts when modifying either one.
	 */
	unsigned long cr4;

	/* Direct-TLB stuff */
	pgd_t *s_pgdp;
	pud_t *s_pudp;
	pmd_t *s_pmdp;
	pte_t *s_ptep;
	unsigned long s_last_ptep;
	int generation;
};
DECLARE_PER_CPU_SHARED_ALIGNED(struct tlb_state, cpu_tlbstate);

/* Initialize cr4 shadow for this CPU. */
static inline void cr4_init_shadow(void)
{
	this_cpu_write(cpu_tlbstate.cr4, __read_cr4());
}

/* Set in this cpu's CR4. */
static inline void cr4_set_bits(unsigned long mask)
{
	unsigned long cr4;

	cr4 = this_cpu_read(cpu_tlbstate.cr4);
	if ((cr4 | mask) != cr4) {
		cr4 |= mask;
		this_cpu_write(cpu_tlbstate.cr4, cr4);
		__write_cr4(cr4);
	}
}

/* Clear in this cpu's CR4. */
static inline void cr4_clear_bits(unsigned long mask)
{
	unsigned long cr4;

	cr4 = this_cpu_read(cpu_tlbstate.cr4);
	if ((cr4 & ~mask) != cr4) {
		cr4 &= ~mask;
		this_cpu_write(cpu_tlbstate.cr4, cr4);
		__write_cr4(cr4);
	}
}

/* Read the CR4 shadow. */
static inline unsigned long cr4_read_shadow(void)
{
	return this_cpu_read(cpu_tlbstate.cr4);
}

/*
 * Save some of cr4 feature set we're using (e.g.  Pentium 4MB
 * enable and PPro Global page enable), so that any CPU's that boot
 * up after us can get the correct flags.  This should only be used
 * during boot on the boot cpu.
 */
extern unsigned long mmu_cr4_features;
extern u32 *trampoline_cr4_features;

static inline void cr4_set_bits_and_update_boot(unsigned long mask)
{
	mmu_cr4_features |= mask;
	if (trampoline_cr4_features)
		*trampoline_cr4_features = mmu_cr4_features;
	cr4_set_bits(mask);
}

static inline void __native_flush_tlb(void)
{
	preempt_disable();
	native_write_cr3(native_read_cr3());
	preempt_enable();
}

static inline void __native_flush_tlb_global_irq_disabled(void)
{
	unsigned long cr4;

	cr4 = this_cpu_read(cpu_tlbstate.cr4);
	/* clear PGE */
	native_write_cr4(cr4 & ~X86_CR4_PGE);
	/* write old PGE again and flush TLBs */
	native_write_cr4(cr4);
}

static inline void __native_flush_tlb_global(void)
{
	unsigned long flags;

	/*
	 * Read-modify-write to CR4 - protect it from preemption and
	 * from interrupts. (Use the raw variant because this code can
	 * be called from deep inside debugging code.)
	 */
	raw_local_irq_save(flags);

	__native_flush_tlb_global_irq_disabled();

	raw_local_irq_restore(flags);
}

static inline void __native_flush_tlb_single(unsigned long addr)
{
	asm volatile("invlpg (%0)" ::"r" (addr) : "memory");
}

static inline void __flush_tlb_all(void)
{
	if (cpu_has_pge)
		__flush_tlb_global();
	else
		__flush_tlb();
}

static inline void __flush_tlb_one(unsigned long addr)
{
	count_vm_tlb_event(NR_TLB_LOCAL_FLUSH_ONE);
	__flush_tlb_single(addr);
}

#define TLB_FLUSH_ALL	-1UL

/*
 * TLB flushing:
 *
 *  - flush_tlb() flushes the current mm struct TLBs
 *  - flush_tlb_all() flushes all processes TLBs
 *  - flush_tlb_mm(mm) flushes the specified mm context TLB's
 *  - flush_tlb_page(vma, vmaddr) flushes one page
 *  - flush_tlb_range(vma, start, end) flushes a range of pages
 *  - flush_tlb_kernel_range(start, end) flushes a range of kernel pages
 *  - flush_tlb_others(cpumask, mm, start, end) flushes TLBs on other cpus
 *
 * ..but the i386 has somewhat limited tlb flushing capabilities,
 * and page-granular flushes are available only on i486 and up.
 */

#ifndef CONFIG_SMP

/* "_up" is for UniProcessor.
 *
 * This is a helper for other header functions.  *Not* intended to be called
 * directly.  All global TLB flushes need to either call this, or to bump the
 * vm statistics themselves.
 */
static inline void __flush_tlb_up(void)
{
	count_vm_tlb_event(NR_TLB_LOCAL_FLUSH_ALL);
	__flush_tlb();
}

static inline void flush_tlb_all(void)
{
	count_vm_tlb_event(NR_TLB_LOCAL_FLUSH_ALL);
	__flush_tlb_all();
}

static inline void flush_tlb(void)
{
	__flush_tlb_up();
}

static inline void local_flush_tlb(void)
{
	__flush_tlb_up();
}

static inline void flush_tlb_mm(struct mm_struct *mm)
{
	if (mm == current->active_mm)
		__flush_tlb_up();
}

static inline void flush_tlb_page(struct vm_area_struct *vma,
				  unsigned long addr)
{
	if (vma->vm_mm == current->active_mm)
		__flush_tlb_one(addr);
}

static inline void flush_tlb_range(struct vm_area_struct *vma,
				   unsigned long start, unsigned long end)
{
	if (vma->vm_mm == current->active_mm)
		__flush_tlb_up();
}

static inline void flush_tlb_mm_range(struct mm_struct *mm,
	   unsigned long start, unsigned long end, unsigned long vmflag)
{
	if (mm == current->active_mm)
		__flush_tlb_up();
}

void native_flush_tlb_others(struct flush_tlb_info *info,
			     struct flush_tlb_entry *entries)
{
}

static inline void reset_lazy_tlbstate(void)
{
}

static inline void flush_tlb_kernel_range(unsigned long start,
					  unsigned long end)
{
	flush_tlb_all();
}

#else  /* SMP */

#include <asm/smp.h>

#define local_flush_tlb() __flush_tlb()

#define flush_tlb_mm(mm)	flush_tlb_mm_range(mm, 0UL, TLB_FLUSH_ALL, \
						   0UL)

#define flush_tlb_range(vma, start, end)	\
		flush_tlb_mm_range(vma->vm_mm, start, end, vma->vm_flags)

extern void flush_tlb_all(void);
extern void flush_tlb_task(struct mm_struct *mm);
extern void flush_tlb_current_task(void);
extern void flush_tlb_page(struct vm_area_struct *, unsigned long);
extern void flush_tlb_page_cpu(struct vm_area_struct *, unsigned long, int);
extern void flush_tlb_mm_range(struct mm_struct *mm, unsigned long start,
				unsigned long end, unsigned long vmflag);
extern void flush_tlb_kernel_range(unsigned long start, unsigned long end);
extern void flush_tlb_mm_entries(struct flush_tlb_info *info);

#define flush_tlb()	flush_tlb_current_task()

void native_flush_tlb_others(struct flush_tlb_info *info);

#define TLBSTATE_OK		1
#define TLBSTATE_NEARLY_LAZY	2
#define TLBSTATE_LAZY		3

static inline void reset_lazy_tlbstate(void)
{
	this_cpu_write(cpu_tlbstate.state, 0);
	this_cpu_write(cpu_tlbstate.active_mm, &init_mm);
	this_cpu_write(cpu_tlbstate.active_task, NULL);
}

static inline int arch_can_push_to_tlb(pte_t pte)
{
	if ((pte_flags(pte) & (_PAGE_RW | _PAGE_DIRTY)) == _PAGE_RW)
		return false;

	return (pte_flags(pte) &
		(_PAGE_NX | _PAGE_USER | _PAGE_GLOBAL |
		 _PAGE_PRESENT)) == (_PAGE_NX | _PAGE_USER | _PAGE_PRESENT);
}

void arch_push_to_tlb(struct mm_struct *mm, unsigned long addr,
		pmd_t *pmd, int n_entries);

#endif	/* SMP */

static inline bool pte_need_flush(struct mm_struct *mm, pte_t pte,
				  epte_t epte, int *cpu)
{
	int cur_gen;

	*cpu = -1;

	if (pte_young(pte))
		return true;

	/* disabled - need on all, uncached - no need */
	if (epte.generation < EPTE_GEN_MIN)
		return epte.generation == EPTE_GEN_DISABLED;

	cur_gen = atomic_read(&mm->flush_cnt);
	if (epte.generation != cur_gen &&
	    next_flush_gen(epte.generation) != cur_gen)
		return false;

	/* local to certain cpu */
	*cpu = (int)epte.cpu_plus_one - 1;

	return true;
}

static void tlb_flush_out_of_space(struct flush_tlb_info *info)
{
	struct flush_tlb_entry *entry;
	/* If filled, replace with global entry */
	info->n_entries = 1;
	entry = &info->entries[0];

	if (!info->same_mm)
		set_flush_tlb_entry_all_mm(entry);
	else {
		entry->cpu_specific = 0;
		BUG_ON(!entry->mm);
		BUG_ON(entry->kernel);
	}
	entry->n_pages = TLB_FLUSH_ALL_LEN;
}

static inline void tlb_add_flush_range(struct flush_tlb_info *info,
					 struct mm_struct *mm,
					 unsigned long address,
					 int cpu)
{
	struct flush_tlb_entry *entry;

	/* make sure changes to the cpumask of mm are visible */
	if (info->n_entries == 0)
		goto new_entry;

	if (++info->n_pages > 33)
		tlb_flush_out_of_space(info);

	entry = &info->entries[info->n_entries - 1];
	if (!entry->mm) {
		BUG_ON(entry->cpu_specific);
		return;
	}
	if (entry->mm != mm) {
		BUG_ON(info->same_mm);
		goto try_new_entry;
	}
	if (cpu >= 0 && entry->cpu_specific && entry->cpu != cpu)
		goto try_new_entry;
	if (entry->n_pages == TLB_FLUSH_ALL_LEN)
		goto found_matching;
	if (flush_tlb_entry_end(entry) == address)
		goto found_adjacent;

	/* Create new entry */
try_new_entry:
	if (info->n_entries == N_TLB_FLUSH_ENTRIES) {
		tlb_flush_out_of_space(info);
		return;
	}
new_entry:
	entry = &info->entries[info->n_entries++];
	entry->vpn = address >> PAGE_SHIFT;
	BUG_ON(get_flush_tlb_entry_addr(entry) != (address & PAGE_MASK));
	entry->cpu_specific = 1;
	entry->cpu = cpu;
	set_flush_tlb_entry_mm(entry, mm);
	entry->n_pages = 1;
	entry->last = 0;
	goto found_matching;
found_adjacent:
	set_flush_tlb_n_pages(entry, entry->n_pages + 1);
found_matching:
	if (cpu < 0)
		entry->cpu_specific = 0;
}

#ifndef CONFIG_PARAVIRT
#define flush_tlb_others(info)	\
	native_flush_tlb_others(info)
#endif

extern int arch_init_sw_tlb(bool primary);
extern void arch_deinit_sw_tlb(void);

#endif /* _ASM_X86_TLBFLUSH_H */
