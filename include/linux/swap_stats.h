/**
 * swap_stats.h - collect swap stats for profiling
 */

#ifndef _LINUX_SWAP_STATS_H
#define _LINUX_SWAP_STATS_H

#include <linux/swap.h>


// ############# Macro ##################

// the cpu frequency of each server
#define FUSILLI_CPU_FREQ 2100 // in MHz 



// ############# Structure ##################


// profile swap-in cnts
enum adc_counter_type {
	ADC_ONDEMAND_SWAPIN,
	ADC_PREFETCH_SWAPIN,
	ADC_HIT_ON_PREFETCH,
	ADC_SWAPOUT,
	NUM_ADC_COUNTER_TYPE
};

extern atomic_t adc_profile_counters[NUM_ADC_COUNTER_TYPE];

// profile page fault latency
enum adc_profile_flag { ADC_PROFILE_SWAP_BIT = 1, ADC_PROFILE_MAJOR_BIT = 2 };

// profile accumulated time stats
struct adc_time_stat {
	atomic64_t accum_val;
	atomic_t cnt;
};

/**
 * @brief Record the average latency of each operation.
 * 	each type has 2 counter 1) accumulated time 2) number of operations
 * 	So, the average latency is caculated by these 2 counters.
 */
enum adc_time_stat_type {
	ADC_SWAP_MAJOR_LATENCY,		// 0
	ADC_SWAP_MINOR_LATENCY,	
	ADC_NON_SWAP_LATENCY,
	ADC_RDMA_READ_LATENCY,
	ADC_RDMA_WRITE_LATENCY,
	ADC_SWAPOUT_LATENCY,	//5
	ADC_SWAP_REVERSE_MAPPING_LATENCY,
	ADC_SWAP_TLB_FLUSH_LATENCY_1,  // tlb flush before paging out
	ADC_SWAP_TLB_FLUSH_LATENCY_2,  // tlb flush after paging out
	NUM_ADC_TIME_STAT_TYPE
};

extern struct adc_time_stat adc_time_stats[NUM_ADC_TIME_STAT_TYPE];



// ############# Functions ##################

static inline void reset_adc_profile_counter(enum adc_counter_type type)
{
	atomic_set(&adc_profile_counters[type], 0);
}

static inline void adc_profile_counter_inc(enum adc_counter_type type)
{
	atomic_inc(&adc_profile_counters[type]);
}

static inline int get_adc_profile_counter(enum adc_counter_type type)
{
	return (int)atomic_read(&adc_profile_counters[type]);
}





// time utils
// reference cycles.
// #1, Fix the clock cycles of CPU.
// #2, Divided by CPU frequency to calculate the wall time.
// 500 cycles/ 4.0GHz * 10^9 ns = 500/4.0 ns = xx ns.
// Use "__asm__" in header files (".h") and "asm" in source files (".c")
static inline uint64_t get_cycles_start(void)
{
	uint32_t cycles_high, cycles_low;
	__asm__ __volatile__("xorl %%eax, %%eax\n\t"
			     "CPUID\n\t"
			     "RDTSC\n\t"
			     "mov %%edx, %0\n\t"
			     "mov %%eax, %1\n\t"
			     : "=r"(cycles_high), "=r"(cycles_low)::"%rax",
			       "%rbx", "%rcx", "%rdx");
	return ((uint64_t)cycles_high << 32) + (uint64_t)cycles_low;
}

// More strict than get_cycles_start since "RDTSCP; read registers; CPUID"
// gurantee all instructions before are executed and all instructions after
// are not speculativly executed
// Refer to https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/ia-32-ia-64-benchmark-code-execution-paper.pdf
static inline uint64_t get_cycles_end(void)
{
	uint32_t cycles_high, cycles_low;
	__asm__ __volatile__("RDTSCP\n\t"
			     "mov %%edx, %0\n\t"
			     "mov %%eax, %1\n\t"
			     "xorl %%eax, %%eax\n\t"
			     "CPUID\n\t"
			     : "=r"(cycles_high), "=r"(cycles_low)::"%rax",
			       "%rbx", "%rcx", "%rdx");
	return ((uint64_t)cycles_high << 32) + (uint64_t)cycles_low;
}




#define SERVER_CPU_FREQ FUSILLI_CPU_FREQ

static inline uint64_t timer_start_in_us(void)
{
	return get_cycles_start() / SERVER_CPU_FREQ;
}
static inline uint64_t timer_end_in_us(void)
{
	return get_cycles_end() / SERVER_CPU_FREQ;
}

/**
 * @brief Record the elapsed time and number for the specific event
 * 
 * @param type : event type
 * @param val : the elapsed time, in micro-second (us)
 */
static inline void accum_adc_time_stat(enum adc_time_stat_type type, uint64_t val)
{
	struct adc_time_stat *ts = &adc_time_stats[type];
	atomic64_add(val, &(ts->accum_val));
	atomic_inc(&(ts->cnt));
}




size_t report_adc_time_stat(enum adc_time_stat_type type);
void reset_adc_time_stat(enum adc_time_stat_type type);
void reset_adc_swap_stats(void);

#endif /* _LINUX_SWAP_STATS_H */
