/**
 * @file hermit_inline.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2021-10-10
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#ifndef _PROJECT_HERMIT_INLINE_H
#define _PROJECT_HERMIT_INLINE_H

#include <linux/hermit.h>
#include <linux/slab.h>

#include <asm/page_types.h>
#include <asm/pgtable.h>




//
// Migrated from kernel 4.15
//

/*
 * Prevent the compiler from merging or refetching accesses.  The compiler
 * is also forbidden from reordering successive instances of ACCESS_ONCE(),
 * but only when the compiler is aware of some particular ordering.  One way
 * to make the compiler aware of ordering is to put the two invocations of
 * ACCESS_ONCE() in different C statements.
 *
 * ACCESS_ONCE will only work on scalar types. For union types, ACCESS_ONCE
 * on a union member will work as long as the size of the member matches the
 * size of the union and the size is smaller than word size.
 *
 * The major use cases of ACCESS_ONCE used to be (1) Mediating communication
 * between process-level code and irq/NMI handlers, all running on the same CPU,
 * and (2) Ensuring that the compiler does not  fold, spindle, or otherwise
 * mutilate accesses that either do not require ordering or that interact
 * with an explicit memory barrier or atomic instruction that provides the
 * required ordering.
 *
 * If possible use READ_ONCE()/WRITE_ONCE() instead.
 */
#define __ACCESS_ONCE(x) ({ \
	 __maybe_unused typeof(x) __var = (__force typeof(x)) 0; \
	(volatile typeof(x) *)&(x); })
#define ACCESS_ONCE(x) (*__ACCESS_ONCE(x))




/**
 * Debug Functions
 * 
 */


static inline int within_hermit_debug_range(size_t virt_addr){
	return (virt_addr >= 0x400000000000UL ) && (virt_addr < 0x400200000000UL );
}




/**
 * @brief Print the first unsigned long value of a page
 * 
 * @param pte : the page to print
 */
static inline void print_pte_virtaddr_value(pte_t pte, unsigned long user_virt_addr, const char* message){

	struct page *taget_page;
	unsigned long *kernel_virt;
	char *copied_from_user = kmalloc(sizeof(char)*PAGE_SIZE, GFP_KERNEL);

	taget_page = pfn_to_page(pte_pfn(pte));
	kernel_virt = kmap(taget_page);

	copy_from_user(copied_from_user, (__user char*)user_virt_addr, PAGE_SIZE);

	pr_warn("%s, pte 0x%lx,\n\
	mapped kernel virt 0x%lx, the first size_t is %lu\n\
	user_virt_addr 0x%lx, value %lu\n",
		message, pte.pte, 
		(unsigned long)kernel_virt, *kernel_virt,
		user_virt_addr,  *((unsigned long*)copied_from_user) );

	kunmap(taget_page);
}

/**
 * @brief Return the the pte vlaue of its previous page
 * 	Warning: 
 * 	1) be sure we are holding the coressponding pmd's ptl lock.
 * 	2) Clear the cached fake TLB entries	
 * 
 * @param addr, the faulting virtual address
 * @param pmd,  the pmd containing the pte
 * @return pte_t , the previous page's pte value
 */
static inline pte_t exchange_pte_val_to_previous(unsigned long addr, pmd_t *pmd)
{
	unsigned long pre_page_virt_addr;
	pte_t *ptep, *prev_ptep;
	pte_t pte, prev_pte;

	pre_page_virt_addr = (addr & PAGE_MASK) - PAGE_SIZE;
	prev_ptep = pte_offset_map(pmd, pre_page_virt_addr);

	if (pte_present(*prev_ptep)) {
		// got the valid the pte,
#ifdef HERMIT_IPI_OPT_DEBUG
		pr_warn("%s, exchange the addr 0x%lx \n \
		to prev_addr 0x%lx 's pte 0x%lx\n",
			__func__, addr, pre_page_virt_addr, prev_ptep->pte);

		prev_pte = pte_mkold(*prev_ptep);
		return prev_pte;
#endif
	} else {
		// the previous page's pte is not valid,
		// return the original pte
		ptep = pte_offset_map(pmd, addr & PAGE_MASK);
		// clear the ACCESS_BIT
		pte = pte_mkold(*ptep);

		return pte;
	}

}

#endif //_PROJECT_HERMIT_INLINE_H

