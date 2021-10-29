/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ARCH_X86_TLBBATCH_H
#define _ARCH_X86_TLBBATCH_H

#include <linux/cpumask.h>




struct arch_tlbflush_unmap_batch {
	/*
	 * Each bit set is a CPU that potentially has a TLB entry for one of
	 * the PFNs being flushed..
	 */
	struct cpumask cpumask;
};





/**
 * @brief Hermit reduced IPI TLB Flushing
 * 
 * The basic TLB flushing structs and functions are defined in
 * arch/x86/include/asm/tlbflush.h
 * Its basic flusing granularity is th the TLB entirs within same PCID on a cpu.
 * The cpu selection is based on the process scheduling mechanism.
 * 
 * However, VMWare proposed a way to limit the TLB flushing range.
 * Use the pte __ACCESS_BIT to detect the if a pte is only accessed by a single cpu,
 * even if the process is scheduled to multiple cpus.
 * 
 */



// TLB batch flusing entry limit, 32 ?
#define N_TLB_FLUSH_ENTRIES (32)

// TLB batch flusing page limit, 1023 pages
#define TLB_FLUSH_LEN_BITS	(PAGE_SHIFT - 2)
#define TLB_FLUSH_ALL_LEN	((1<<TLB_FLUSH_LEN_BITS)-1)

// ? 63 cpu max ?
#define TLB_FLUSH_CPU_BITS	(63)

// Used to record one pte
struct flush_tlb_entry {
	struct mm_struct *mm;	/* may be redundant, but easier */
	struct {
		unsigned long n_pages : TLB_FLUSH_LEN_BITS;
		unsigned long kernel : 1;
		unsigned long last : 1;	// flag of if this is the last one of the flush_tlb_info_multi
		unsigned long vpn : 36;	/* virtu page number. x86 address is 48 bits */
		unsigned long cpu : 12;
		unsigned long cpu_specific : 1; // single CPU TLB flushing or not
	};
};


// duplicated with the information defiend in arch/x86/include/asm/tlbflush.h
// The TLB flushing granulairty is the struct flush_tlb_entry
struct hermit_flush_tlb_info {
	unsigned int n_entries; // number of recorded entires.
	unsigned short n_pages; // for huge page ? one entry may contain multi-pages
	bool same_mm; // what's the used for ?
	struct cpumask cpumask; // the core to do TLB flush

	// points to the adjacent memory size of this struct
	// e.g., the __entries[N_TLB_FLUSH_ENTRIES]; of the struct flush_tlb_info_multi
	// the memory size is flexible.
	struct flush_tlb_entry entries[0];  
} __packed;

struct flush_tlb_info_single {
	struct hermit_flush_tlb_info info;
	struct flush_tlb_entry __entry; // single entry
} __packed;


struct flush_tlb_info_multi {
	struct hermit_flush_tlb_info info; // info.entries points to the adjacent memory space.
	struct flush_tlb_entry __entries[N_TLB_FLUSH_ENTRIES]; // muti-entries
} __packed;



struct hermit_tlbflush_unmap_batch {
	/*
	 * Each bit set is a CPU that potentially has a TLB entry for one of
	 * the PFNs being flushed..
	 * 
	 * ?? fix me ??
	 * Keep this field for legacy code.
	 * Hermit never use his cpumask.
	 * Hermit utilize the cpumask information stored in flush_tlb_info_multi.flush_tlb_info.cpumask.
	 */
	//struct cpumask cpumask;


	// Hermit fields
	struct flush_tlb_info_multi multi_flush;

};



#endif /* _ARCH_X86_TLBBATCH_H */
