/**
 * @file hermit.h
 * @brief header for project hermit. 
 * @version 0.1
 * @date 2021-10-08
 * 
 * @copyright Copyright (c) 2021
 * 
 * 
 */

#ifndef _PROJECT_HERMIT_H
#define _PROJECT_HERMIT_H


#include <asm/page_types.h>



//#define HERMIT_IPI_OPT_DEBUG_DETAIL 1
#define HERMIT_IPI_OPT_DEBUG 1





//
// Hermit

#define FLUSH_GEN_BITS		(7)
#define FLUSH_GEN_MASK		((1UL << FLUSH_GEN_BITS) - 1)

#define EPTE_GEN_DISABLED	(0x0)
#define EPTE_GEN_UNCACHED	(0x1)
#define EPTE_GEN_MIN		(0x2)

// VMWare IPI opt
// 2 bytes
// sw_young : ?
// generation : identify if a full TLB flushing is necessary
// cpu_plus_one : record the owner of this private pte.
// val : ?
typedef union {
	struct {
		unsigned short sw_young : 1;
		unsigned short generation : FLUSH_GEN_BITS;
		unsigned short cpu_plus_one : 8;
	};
	unsigned short val;
} epte_t;

#define EXTENDEDPT_SIZE sizeof(epte_t)

#define ZERO_EPTE(a)                                                                                                           \
	({                                                                                                                     \
		epte_t __epte = { 0 };                                                                                         \
		__epte;                                                                                                        \
	})

// the initial value of extended pte
#define UNCACHED_EPTE(a)                                                                                                       \
	({                                                                                                                     \
		epte_t __epte = { .generation = EPTE_GEN_UNCACHED };                                                           \
		__epte;                                                                                                        \
	})




/**
 * @brief Set a epte entry. not atomic.
 * 
 * @param eptep : the target epet to be set
 * @param epte : the new epte value
 */
static inline void  __set_epte(epte_t *eptep, epte_t epte)
{
	*eptep = epte;
}

/**
 * @brief clear a epete, not atomic
 * 
 * @param eptep : the cleared epete
 */
static inline void __epte_clear(epte_t *eptep)
{
	eptep->val = 0;
}








/**
 * Debug Functions
 * 
 */






#endif // _PROJECT_HERMIT_H