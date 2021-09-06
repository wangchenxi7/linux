#include <linux/swap_stats.h>

atomic_t adc_profile_counters[NUM_ADC_COUNTER_TYPE];
EXPORT_SYMBOL(adc_profile_counters);

struct adc_time_stat adc_time_stats[NUM_ADC_TIME_STAT_TYPE];
EXPORT_SYMBOL(adc_time_stats);

void reset_adc_time_stat(enum adc_time_stat_type type)
{
	struct adc_time_stat *ts = &adc_time_stats[type];
	atomic64_set(&(ts->accum_val), 0);
	atomic_set(&(ts->cnt), 0);
}


static const char *adc_time_stat_names[NUM_ADC_TIME_STAT_TYPE] = {
	"major swap latency", "minor swap latency", "non-swap-out latency",
	"RDMA read latency ", "RDMA write latency ",
	"swap out latency", "reverse mapping  ", "unmap flush #1 ", "unmap flush #2"
};



size_t report_adc_time_stat(enum adc_time_stat_type type)
{
	struct adc_time_stat *ts = &adc_time_stats[type];
	if ((size_t)atomic_read(&(ts->cnt)) == 0) {
		return 0;
	} else {
		return (int64_t)atomic64_read(&(ts->accum_val)) /
		       (int64_t)atomic_read(&(ts->cnt));
	}
}

void reset_adc_swap_stats(void)
{
	int i;
	for (i = 0; i < NUM_ADC_COUNTER_TYPE; i++) {
		reset_adc_profile_counter(i);
	}

	for (i = 0; i < NUM_ADC_TIME_STAT_TYPE; i++) {
		reset_adc_time_stat(i);
	}
}