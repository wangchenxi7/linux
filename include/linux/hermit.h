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

//#define HERMIT_IPI_OPT_DEBUG_DETAIL 1
#define HERMIT_IPI_OPT_DEBUG 1




/**
 * Debug Functions
 * 
 */


static inline int within_hermit_debug_range(size_t virt_addr){
	return (virt_addr >= 0x400000000000UL ) && (virt_addr < 0x400200000000UL );
}



#endif // _PROJECT_HERMIT_H