#include <linux/swap_stats.h>
#include <linux/syscalls.h>
#include <linux/printk.h>

asmlinkage int sys_reset_swap_stats(void)
{
	reset_adc_swap_stats();
	return 0;
}


/**
 * @brief print the swap related profiling statistics
 * 
 * 
 */
asmlinkage int sys_get_swap_stats(void)
{
	size_t swap_major_dur = report_adc_time_stat(ADC_SWAP_MAJOR_LATENCY);
	size_t swap_minor_dur = report_adc_time_stat(ADC_SWAP_MINOR_LATENCY);
	size_t swapout_latency = report_adc_time_stat(ADC_SWAPOUT_LATENCY);
	size_t swapout_tlb_flush_1 = report_adc_time_stat(ADC_SWAP_TLB_FLUSH_LATENCY_1);
	size_t swapout_tlb_flush_2 = report_adc_time_stat(ADC_SWAP_TLB_FLUSH_LATENCY_2);

	pr_warn("%s, Major fault: %lu us, Minor fault: %lu us \n, Swap out latency: %lu us, tlb flush latency #1: %lu us, tlb flush latency #2: %lu us\n",
		__func__, swap_major_dur, swap_minor_dur, swapout_latency, swapout_tlb_flush_1, swapout_tlb_flush_2);

	return 0;
}
