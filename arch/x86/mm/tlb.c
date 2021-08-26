#include <linux/init.h>

#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/smp.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/cpu.h>
#include <linux/vmstat.h>
#include <linux/kasan.h>

#include <asm/tlbflush.h>
#include <asm/mmu_context.h>
#include <asm/cache.h>
#include <asm/apic.h>
#include <asm/uv/uv.h>
#include <asm/arch_hweight.h>
#include <linux/debugfs.h>

/*
 *	Smarter SMP flushing macros.
 *		c/o Linus Torvalds.
 *
 *	These mean you can really definitely utterly forget about
 *	writing to user space from interrupts. (Its not allowed anyway).
 *
 *	Optimizations Manfred Spraul <manfred@colorfullife.com>
 *
 *	More scalable flush, from Andi Kleen
 *
 *	Implement flush IPI by CALL_FUNCTION_VECTOR, Alex Shi
 */

/*
 * See Documentation/x86/tlb.txt for details.  We choose 33
 * because it is large enough to cover the vast majority (at
 * least 95%) of allocations, and is small enough that we are
 * confident it will not cause too much overhead.  Each single
 * flush is about 100 ns, so this caps the maximum overhead at
 * _about_ 3,000 ns.
 *
 * This is in units of pages.
 */
static unsigned long tlb_single_page_flush_ceiling __read_mostly = 33;

static inline void init_tlb_flush_single(struct flush_tlb_info_single *i_single)
{
	struct flush_tlb_info *info = &i_single->info;

	info->n_entries = 1;
	info->same_mm = true;
	info->n_pages = 0;
}

/*
 * We cannot call mmdrop() because we are in interrupt context,
 * instead update mm->cpu_vm_mask.
 */
bool leave_mm(int cpu)
{
	struct mm_struct *active_mm = this_cpu_read(cpu_tlbstate.active_mm);
	if (this_cpu_read(cpu_tlbstate.state) == TLBSTATE_OK)
		BUG();
	if (cpumask_test_cpu(cpu, mm_cpumask(active_mm))) {
		cpumask_clear_cpu(cpu, mm_cpumask(active_mm));
		cpumask_clear_cpu(cpu, active_mm->cpu_vm_flush_mask_var);
		load_cr3(swapper_pg_dir);

		/*
		 * This gets called in the idle path where RCU
		 * functions differently.  Tracing normally
		 * uses RCU, so we have to call the tracepoint
		 * specially here.
		 */
		trace_tlb_flush_rcuidle(TLB_FLUSH_ON_TASK_SWITCH, TLB_FLUSH_ALL);
		return true;
	}
	return false;
}
EXPORT_SYMBOL_GPL(leave_mm);

static inline pte_t native_pfn_pte(unsigned long page_nr, pgprot_t pgprot)
{
	return native_make_pte(((phys_addr_t)page_nr << PAGE_SHIFT) |
		     massage_pgprot(pgprot));
}

static inline pud_t native_pfn_pud(unsigned long page_nr, pgprot_t pgprot)
{
	return native_make_pud(((phys_addr_t)page_nr << PAGE_SHIFT) |
				massage_pgprot(pgprot));
}

static inline pmd_t native_pfn_pmd(unsigned long page_nr, pgprot_t pgprot)
{
	return native_make_pmd(((phys_addr_t)page_nr << PAGE_SHIFT) |
		     massage_pgprot(pgprot));
}

static inline pgd_t native_pfn_pgd(unsigned long page_nr, pgprot_t pgprot)
{
	return native_make_pgd(((phys_addr_t)page_nr << PAGE_SHIFT) |
				massage_pgprot(pgprot));
}

void arch_push_to_tlb(struct mm_struct *mm, unsigned long addr,
		      pmd_t *pmd, int n_entries)
{
	pgd_t *s_pgd, *s_pgdp;
	pud_t *s_pud, *s_pudp;
	pmd_t *s_pmd, *s_pmdp;
	pte_t *s_ptep, *s_pte, *ptep;
	epte_t *eptep;
	bool restore_pgd, restore_pud;
	int i, cpu, generation;
	int first = 0;
	int last = -1;
	unsigned long last_ptep, start_addr;
	pgprot_t pgprot = __pgprot(_PAGE_ACCESSED | _PAGE_RW | _PAGE_PRESENT |
				   _PAGE_USER);
	spinlock_t *ptl;

	addr &= PAGE_MASK;
	start_addr = addr;

	ptl = pte_lockptr(mm, pmd);

	preempt_disable();

	ptep = pte_offset_map(pmd, addr);
	eptep = get_eptep(ptep);
	if (unlikely(!eptep)) {
		pte_unmap(ptep);
		goto out;
	}
#if 0
	/* To be really safe, the following should be enabled */
	__native_flush_tlb_single(addr);
#endif

	s_ptep = this_cpu_read(cpu_tlbstate.s_ptep);
	s_pmdp = this_cpu_read(cpu_tlbstate.s_pmdp);
	s_pudp = this_cpu_read(cpu_tlbstate.s_pudp);
	s_pgdp = this_cpu_read(cpu_tlbstate.s_pgdp);

	s_pgd = s_pgdp + pgd_index(addr);

	cpu = smp_processor_id();
	restore_pgd = !pgd_present(*s_pgd);
	if (restore_pgd)
		native_set_pgd(s_pgd,
			native_pfn_pgd(__pa(s_pudp) >> PAGE_SHIFT, pgprot));
	s_pud = pud_offset(s_pgd, addr);
	restore_pud = !pud_present(*s_pud);
	if (restore_pud)
		native_set_pud(s_pud,
			native_pfn_pud(__pa(s_pmdp) >> PAGE_SHIFT, pgprot));
	s_pmd = pmd_offset(s_pud, addr);
	native_set_pmd_at(mm, addr, s_pmd,
			native_pfn_pmd(__pa(s_ptep) >> PAGE_SHIFT, pgprot));

	spin_lock(ptl);
	native_irq_disable();
	generation = atomic_read(&mm->flush_cnt);

	for (i = 0, s_pte = s_ptep + pte_index(addr);
	     i < n_entries;
	     i++, addr += PAGE_SIZE, ptep++, s_pte++, eptep++) {
		pte_t pte = *ptep;
		epte_t epte = *eptep;

		if (!arch_can_push_to_tlb(pte) || pte_young(pte) ||
		    epte.generation == EPTE_GEN_DISABLED) {
			continue;
		}

		if (last < 0)
			first = i;
		last = i;

		//epte.sw_young = 1;
		pte = pte_mkyoung(pte);

		native_set_pte_at(mm, addr, s_pte, pte);
		if (epte.generation == EPTE_GEN_UNCACHED)
			epte.cpu_plus_one = cpu + 1;
		else if (epte.cpu_plus_one != cpu + 1)
			epte.cpu_plus_one = 0;

		epte.generation = generation;
		__set_epte(eptep, epte);
	}
	pte_unmap_unlock(ptep-1, ptl);

	if (last < 0)
		goto out_irq_enable;

	native_load_cr3_no_invd(s_pgdp); /* implicit barrier */
	addr = start_addr + first * PAGE_SIZE;

	for (i = first, s_pte = s_ptep + pte_index(addr);
	     i <= last;
	     i++, addr += PAGE_SIZE, s_pte++) {
		if (!pte_present(*s_pte))
			continue;

		stac();
		kasan_disable_current();
		ACCESS_ONCE(*(__user int *)addr);
		kasan_enable_current();
		clac();

		barrier();

		/* pte_clear(mm, addr, s_pte); */
		native_set_pte_at(mm, addr, s_pte, native_make_pte(0));
	}
	/* We can already release the lock */

	barrier();
	native_pmd_clear(s_pmd);
	if (restore_pud)
		native_pud_clear(s_pud);
	if (restore_pgd)
		native_pgd_clear(s_pgd);
	native_load_cr3_no_invd(mm->pgd); /* implicit barrier */

	/* local_irq_restore(flags); */
out_irq_enable:
	native_irq_enable();
out:
	preempt_enable();
}

/*
 * See Documentation/x86/tlb.txt for details.  We choose 33
 * because it is large enough to cover the vast majority (at
 * least 95%) of allocations, and is small enough that we are
 * confident it will not cause too much overhead.  Each single
 * flush is about 100 ns, so this caps the maximum overhead at
 * _about_ 3,000 ns.
 *
 * This is in units of pages.
 */

#define NEARLY_LAZY_CNT		(10)

static bool remote_lazy_tlb_flush(void)
{
	bool flushed = false;
	int state = this_cpu_read(cpu_tlbstate.state);

	if ((state == TLBSTATE_NEARLY_LAZY) &&
	    this_cpu_inc_return(cpu_tlbstate.nearly_lazy_cnt) >
	    NEARLY_LAZY_CNT)
		this_cpu_write(cpu_tlbstate.state, TLBSTATE_LAZY);

	if (state == TLBSTATE_LAZY) {
		leave_mm(smp_processor_id());
		flushed = true;
	}
	return flushed;
}

static inline void flush_range_entry(const struct flush_tlb_entry *entry)
{
	int j;
	unsigned long addr;

	for (j = 0, addr = get_flush_tlb_entry_addr(entry);
	     j < entry->n_pages; j++, addr += PAGE_SIZE) {
		__flush_tlb_single(addr);
	}
}


static void ___flush_tlb(struct flush_tlb_entry *entries, int trace_event)
{
	unsigned long n_pages = 0;
	int cpu = smp_processor_id();
	const struct flush_tlb_entry *entry =
				(const struct flush_tlb_entry *)entries;
	bool local = (trace_event != TLB_REMOTE_SHOOTDOWN);
	struct mm_struct *mm;
	int ceiling = tlb_single_page_flush_ceiling;
	bool should_leave_mm = this_cpu_read(cpu_tlbstate.state) !=
				TLBSTATE_OK;

	/* kernel flushes have a single entry */
	if (entry->kernel) {
		if (entry->n_pages > ceiling) {
			__flush_tlb_all();
			if (should_leave_mm)
				leave_mm(cpu);
		} else
			flush_range_entry(entry);
		return;
	}

	/* leaving-mm cases */
	if (local) {
		if (!current->mm) {
			leave_mm(cpu);
			return;
		}
		mm = current->active_mm;
	} else {
		if (remote_lazy_tlb_flush())
			return;
		mm = this_cpu_read(cpu_tlbstate.active_mm);
	}

	/* specific */
	do {
		if (entry->mm && entry->mm != mm)
			continue;
		if (entry->cpu_specific && entry->cpu != cpu)
			continue;

		if (entry->n_pages > ceiling) {
			/* We got the almost lazy thing, so check again */
			if (should_leave_mm) {
				leave_mm(cpu);
				break;
			}

			if (local)
				count_vm_tlb_event(NR_TLB_LOCAL_FLUSH_ALL);
			trace_tlb_flush(trace_event, TLB_FLUSH_ALL);

			if (cpumask_test_cpu(cpu, mm->cpu_vm_flush_mask_var))
				cpumask_clear_cpu(cpu,
						mm->cpu_vm_flush_mask_var);

			/*
			 * It is important that no PTE will be set between
			 * clearing the PTE in the flush-mask and the actual
			 * flush
			 */

			local_flush_tlb();
			break;
		}

		/* entry specific */
		flush_range_entry(entry);
		n_pages += entry->n_pages;
	} while (!(entry++)->last);

	if (n_pages > 0) {
		if (local)
			count_vm_tlb_events(NR_TLB_LOCAL_FLUSH_ONE, n_pages);
		trace_tlb_flush(trace_event, n_pages);
	}
}


/*
 * The flush IPI assumes that a thread switch happens in this order:
 * [cpu0: the cpu that switches]
 * 1) switch_mm() either 1a) or 1b)
 * 1a) thread switch to a different mm
 * 1a1) set cpu_tlbstate to TLBSTATE_OK
 *	Now the tlb flush NMI handler flush_tlb_func won't call leave_mm
 *	if cpu0 was in lazy tlb mode.
 * 1a2) update cpu active_mm
 *	Now cpu0 accepts tlb flushes for the new mm.
 * 1a3) cpu_set(cpu, new_mm->cpu_vm_mask);
 *	Now the other cpus will send tlb flush ipis.
 * 1a4) change cr3.
 * 1a5) cpu_clear(cpu, old_mm->cpu_vm_mask);
 *	Stop ipi delivery for the old mm. This is not synchronized with
 *	the other cpus, but flush_tlb_func ignore flush ipis for the wrong
 *	mm, and in the worst case we perform a superfluous tlb flush.
 * 1b) thread switch without mm change
 *	cpu active_mm is correct, cpu0 already handles flush ipis.
 * 1b1) set cpu_tlbstate to TLBSTATE_OK
 * 1b2) test_and_set the cpu bit in cpu_vm_mask.
 *	Atomically set the bit [other cpus will start sending flush ipis],
 *	and test the bit.
 * 1b3) if the bit was 0: leave_mm was called, flush the tlb.
 * 2) switch %%esp, ie current
 *
 * The interrupt must handle 2 special cases:
 * - cr3 is changed before %%esp, ie. it cannot use current->{active_,}mm.
 * - the cpu performs speculative tlb reads, i.e. even if the cpu only
 *   runs in kernel space, the cpu could load tlb entries for user space
 *   pages.
 *
 * The good news is that cpu_tlbstate is local to each cpu, no
 * write/read ordering problems.
 */

/*
 * TLB flush funcation:
 * 1) Flush the tlb entries if the cpu uses the mm that's being flushed.
 * 2) Leave the mm if we are in the lazy tlb mode.
 */
static void flush_tlb_func(void *entries)
{
	inc_irq_stat(irq_tlb_count);

	count_vm_tlb_event(NR_TLB_REMOTE_FLUSH_RECEIVED);

	___flush_tlb(entries, TLB_REMOTE_SHOOTDOWN);
}

void native_flush_tlb_others(struct flush_tlb_info *info)
{
	count_vm_tlb_event(NR_TLB_REMOTE_FLUSH);

	trace_tlb_flush(TLB_REMOTE_SEND_IPI, info->n_pages);

	/* XXX: the following was disabled since I was lazy to adapt uv */
#if 0
	if (is_uv_system()) {
		unsigned int cpu;

		cpu = smp_processor_id();
		cpumask = uv_flush_tlb_others(cpumask, mm, start, end, cpu);
		if (cpumask)
			smp_call_function_many(cpumask, flush_tlb_func,
								&info, 1);
		return;
	}
#endif
	smp_call_function_many(&info->cpumask, flush_tlb_func, info->entries,
				1);
}

void flush_tlb_current_task(void)
{
	struct flush_tlb_info_single info_single;
	struct flush_tlb_info *info = &info_single.info;
	struct flush_tlb_entry *entry = &info->entries[0];

	init_tlb_flush_single(&info_single);
	set_flush_tlb_entry_full(entry);
	set_flush_tlb_entry_current(entry);

	flush_tlb_mm_entries(info);
}

/* We cannot defer the processing of the list since mm may change */
static void flush_tlb_prolog(struct flush_tlb_info *info,
					   int cpu)
{
	int i;
	struct mm_struct *last_mm = NULL; /* last mm which was fully flushed */

	cpumask_clear(&info->cpumask);

	/* we may need to read mm_cpumask */
	smp_mb();

	for (i = 0; i < info->n_entries; i++) {
		struct flush_tlb_entry *entry = &info->entries[i];
		struct mm_struct *mm = entry->mm;

		if (entry->kernel || !mm) {
			/*
			 * XXX: we could have hold a pointer to cpu_all_mask
			 * but this case should not be a bottleneck
			 */
			cpumask_copy(&info->cpumask, cpu_all_mask);
			BUG_ON(info->n_entries > 1);
			break;
		}
		/* If we already did all the tracking */
		if (mm == last_mm)
			continue;

		if (entry->cpu_specific) {
			if (entry->cpu != cpu &&
			    atomic_read(&mm->mm_count) <= 1)
				entry->n_pages = TLB_FLUSH_ALL_LEN;

			__cpumask_set_cpu(entry->cpu, &info->cpumask);
			continue;
		}
		if (mm) {
			/*
			 * we should find even if mm_cpumask changes.
			 * if a CPU joined, then we flush more than promised.
			 * if a CPU left, then anyhow it flushed
			 */
			cpumask_or(&info->cpumask, mm_cpumask(mm),
				   &info->cpumask);

			last_mm = mm;
		}
	}
}

static void flush_tlb_epilog(struct flush_tlb_info *info,
				      int cpu)
{
	int i;

	for (i = 0; i < info->n_entries; i++) {
		struct flush_tlb_entry *entry = &info->entries[i];
		struct mm_struct *mm = entry->mm;

		finish_tlb_flush_tracking(mm, cpu);
	}
}

void flush_tlb_mm_entries(struct flush_tlb_info *info)
{
	int cpu;

	if (info->n_entries == 0)
		return;

	BUG_ON(!info->entries);
	info->entries[info->n_entries - 1].last = 1;

	preempt_disable();

	cpu = smp_processor_id();
	flush_tlb_prolog(info, cpu);

	if (cpumask_test_cpu(cpu, &info->cpumask))
		___flush_tlb(info->entries, TLB_LOCAL_MM_SHOOTDOWN);

	if (cpumask_any_but(&info->cpumask, cpu) < nr_cpu_ids)
		flush_tlb_others(info);

	flush_tlb_epilog(info, cpu);

	preempt_enable();
}

void flush_tlb_mm_range(struct mm_struct *mm, unsigned long start,
				unsigned long end, unsigned long vmflag)
{
	/* do a global flush by default */
	struct flush_tlb_info_single info_single;
	struct flush_tlb_info *info = &info_single.info;
	struct flush_tlb_entry *entry = &info->entries[0];

	if (end <= start)
		return;

	if (vmflag & VM_HUGETLB)
		end = start + TLB_FLUSH_ALL_LEN;

	init_tlb_flush_single(&info_single);
	entry->cpu_specific = 0;
	entry->cpu = 0; /* ignored */
	set_flush_tlb_entry_mm(entry, mm);
	set_flush_tlb_entry_range(entry, start, end);

	flush_tlb_mm_entries(info);
}

static void __flush_tlb_page(struct vm_area_struct *vma, unsigned long start,
			     int target)
{
	struct flush_tlb_info_single info_single;
	struct flush_tlb_info *info = &info_single.info;
	struct flush_tlb_entry *entry = &info->entries[0];

	init_tlb_flush_single(&info_single);

	set_flush_tlb_entry_range(entry, start, start + PAGE_SIZE);
	set_flush_tlb_entry_mm(entry, vma->vm_mm);
	entry->cpu_specific = (target >= 0);
	entry->cpu = target;

	flush_tlb_mm_entries(info);
}

void flush_tlb_page(struct vm_area_struct *vma, unsigned long start)
{
	return __flush_tlb_page(vma, start, -1);
}

void flush_tlb_page_cpu(struct vm_area_struct *vma, unsigned long start,
			int cpu)
{
	return __flush_tlb_page(vma, start, cpu);
}

void flush_tlb_all(void)
{
	struct flush_tlb_info_single info_single;
	struct flush_tlb_info *info = &info_single.info;
	struct flush_tlb_entry *entry = &info->entries[0];

	init_tlb_flush_single(&info_single);
	set_flush_tlb_entry_kernel(entry);
	set_flush_tlb_entry_full(entry);

	flush_tlb_mm_entries(info);
}

void flush_tlb_kernel_range(unsigned long start, unsigned long end)
{
	/* Balance as user space task's flush, a bit conservative */
	struct flush_tlb_info_single info_single;
	struct flush_tlb_info *info = &info_single.info;
	struct flush_tlb_entry *entry = &info->entries[0];

	init_tlb_flush_single(&info_single);
	set_flush_tlb_entry_kernel(entry);
	set_flush_tlb_entry_range(entry, start, end);

	flush_tlb_mm_entries(info);
}

static ssize_t tlbflush_read_file(struct file *file, char __user *user_buf,
			     size_t count, loff_t *ppos)
{
	char buf[32];
	unsigned int len;

	len = sprintf(buf, "%ld\n", tlb_single_page_flush_ceiling);
	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t tlbflush_write_file(struct file *file,
		 const char __user *user_buf, size_t count, loff_t *ppos)
{
	char buf[32];
	ssize_t len;
	int ceiling;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';
	if (kstrtoint(buf, 0, &ceiling))
		return -EINVAL;

	if (ceiling < 0)
		return -EINVAL;

	tlb_single_page_flush_ceiling = ceiling;
	return count;
}

static const struct file_operations fops_tlbflush = {
	.read = tlbflush_read_file,
	.write = tlbflush_write_file,
	.llseek = default_llseek,
};

static int __init create_tlb_single_page_flush_ceiling(void)
{
	debugfs_create_file("tlb_single_page_flush_ceiling", S_IRUSR | S_IWUSR,
			    arch_debugfs_dir, NULL, &fops_tlbflush);
	return 0;
}
late_initcall(create_tlb_single_page_flush_ceiling);

static int tlb_task_migrate(struct notifier_block *nb, unsigned long l,
			    void *v)
{
	struct task_migration_notifier *mn = v;

	struct tlb_state *ts = &per_cpu(cpu_tlbstate, mn->from_cpu);

	/* expedite TLB flush on task migration */
	if (mn->task == ts->active_task) {
		ts->active_task = NULL;
		ts->nearly_lazy_cnt = TLBSTATE_NEARLY_LAZY;
	}
	return NOTIFY_DONE;
}

static struct notifier_block tlb_migrate = {
	.notifier_call = tlb_task_migrate,
};

int arch_init_sw_tlb(bool primary)
{
	pgd_t *s_pgdp = pgd_alloc(NULL);
	pud_t *s_pudp = pud_alloc_one(NULL, 0);
	pmd_t *s_pmdp = pmd_alloc_one(NULL, 0);
	pte_t *s_ptep = pte_alloc_one_kernel(NULL, 0);

	this_cpu_write(cpu_tlbstate.s_pgdp, pgd_alloc(NULL));
	this_cpu_write(cpu_tlbstate.s_pudp, pud_alloc_one(NULL, 0));
	this_cpu_write(cpu_tlbstate.s_pmdp, pmd_alloc_one(NULL, 0));
	this_cpu_write(cpu_tlbstate.s_ptep, pte_alloc_one_kernel(NULL, 0));

	if (!s_pgdp || !s_pudp || !s_pmdp || !s_ptep)
		goto err;

	this_cpu_write(cpu_tlbstate.generation, 0);
	if (primary)
		register_task_migration_notifier(&tlb_migrate);

	return 0;
err:
	deinit_sw_tlb();
	return -EINVAL;
}

void arch_deinit_sw_tlb(void)
{
	pte_free(NULL, virt_to_page(this_cpu_read(cpu_tlbstate.s_ptep)));
	pmd_free(NULL, this_cpu_read(cpu_tlbstate.s_pmdp));
	pud_free(NULL, this_cpu_read(cpu_tlbstate.s_pudp));
	pgd_free(NULL, this_cpu_read(cpu_tlbstate.s_pgdp));
	this_cpu_write(cpu_tlbstate.s_pgdp, NULL);
	this_cpu_write(cpu_tlbstate.s_pudp, NULL);
	this_cpu_write(cpu_tlbstate.s_pmdp, NULL);
	this_cpu_write(cpu_tlbstate.s_ptep, NULL);
}
