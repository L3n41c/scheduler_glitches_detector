#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <assert.h>

#define TIME_TO_SLEEP_MS 100

struct proc_stat_cpu_t
{
    uint64_t user;
    uint64_t nice;
    uint64_t system;
    uint64_t idle;
    uint64_t iowait;
    uint64_t irq;
    uint64_t softirq;
    uint64_t steal;
    uint64_t guest;
    uint64_t guest_nice;
    uint64_t total;
};

struct stats_t
{
    unsigned                nb_cpu;
    struct proc_stat_cpu_t *proc_stat_cpu;
    struct timespec         clock_realtime;
    struct timespec         clock_monotonic;
    struct timespec         clock_monotonic_raw;
};

void stats_init(struct stats_t *stats)
{
    memset(stats, 0, sizeof(struct stats_t));

    FILE *fp = fopen("/proc/stat", "r");
    if(!fp) {
        perror("fopen(\"/proc/stat\", \"r\")");
        exit(EXIT_FAILURE);
    }

    stats->nb_cpu = -1u;

    {
        char *line = NULL;
        size_t len = 0;
        while(getline(&line, &len, fp) != -1) {
            if(strncmp(line, "cpu", 3) != 0)
                break;
            stats->nb_cpu++;
        }
        free(line);
    }

    if(fclose(fp)) {
        perror("fclose(fp)");
        exit(EXIT_FAILURE);
    }

    stats->proc_stat_cpu = calloc(stats->nb_cpu , sizeof(struct proc_stat_cpu_t));
    assert(stats->proc_stat_cpu);
}

void stats_destroy(struct stats_t *stats)
{
    free(stats->proc_stat_cpu);
}

void stats_fill(struct stats_t *stats)
{
    FILE *fp = fopen("/proc/stat", "r");
    if(!fp) {
        perror("fopen(\"/proc/stat\", \"r\")");
        exit(EXIT_FAILURE);
    }

    char *line = NULL;
    size_t len = 0;
    unsigned i = 0;
    while(getline(&line, &len, fp) != -1) {
        if(strncmp(line, "cpu ", 4) == 0)
            continue;
        if(strncmp(line, "cpu", 3) != 0)
            break;
        unsigned j;
        sscanf(line, "cpu%u %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64,
               &j,
               &stats->proc_stat_cpu[i].user,
               &stats->proc_stat_cpu[i].nice,
               &stats->proc_stat_cpu[i].system,
               &stats->proc_stat_cpu[i].idle,
               &stats->proc_stat_cpu[i].iowait,
               &stats->proc_stat_cpu[i].irq,
               &stats->proc_stat_cpu[i].softirq,
               &stats->proc_stat_cpu[i].steal,
               &stats->proc_stat_cpu[i].guest,
               &stats->proc_stat_cpu[i].guest_nice);
        stats->proc_stat_cpu[i].total =
            stats->proc_stat_cpu[i].user +
            stats->proc_stat_cpu[i].nice +
            stats->proc_stat_cpu[i].system +
            stats->proc_stat_cpu[i].idle +
            stats->proc_stat_cpu[i].iowait +
            stats->proc_stat_cpu[i].irq +
            stats->proc_stat_cpu[i].softirq +
            stats->proc_stat_cpu[i].steal +
            stats->proc_stat_cpu[i].guest +
            stats->proc_stat_cpu[i].guest_nice;
        assert(i == j);
        i++;
    }
    free(line);

    if(fclose(fp)) {
        perror("fclose(fp)");
        exit(EXIT_FAILURE);
    }

    clock_gettime(CLOCK_REALTIME,      &stats->clock_realtime);
    clock_gettime(CLOCK_MONOTONIC,     &stats->clock_monotonic);
    clock_gettime(CLOCK_MONOTONIC_RAW, &stats->clock_monotonic_raw);
}

void stats_print_diff(const struct stats_t *stats_before,
                      const struct stats_t *stats_after)
{
    time_t tloc;
    time(&tloc);
    printf("\n%s", asctime(gmtime(&tloc)));

    for(unsigned i = 0; i < stats_before->nb_cpu; i++)
        printf("cpu %2u:"
               " %3" PRIu64 "ms ut,"
               " %3" PRIu64 "ms ni,"
               " %3" PRIu64 "ms sy,"
               " %3" PRIu64 "ms id,"
               " %3" PRIu64 "ms wa,"
               " %3" PRIu64 "ms hi,"
               " %3" PRIu64 "ms si,"
               " %3" PRIu64 "ms st,"
               " %3" PRIu64 "ms gu,"
               " %3" PRIu64 "ms gn,"
               " %3" PRIu64 "ms total"
               "\n",
               i,
               ( stats_after->proc_stat_cpu[i].user       - stats_before->proc_stat_cpu[i].user       ) * 10,
               ( stats_after->proc_stat_cpu[i].nice       - stats_before->proc_stat_cpu[i].nice       ) * 10,
               ( stats_after->proc_stat_cpu[i].system     - stats_before->proc_stat_cpu[i].system     ) * 10,
               ( stats_after->proc_stat_cpu[i].idle       - stats_before->proc_stat_cpu[i].idle       ) * 10,
               ( stats_after->proc_stat_cpu[i].iowait     - stats_before->proc_stat_cpu[i].iowait     ) * 10,
               ( stats_after->proc_stat_cpu[i].irq        - stats_before->proc_stat_cpu[i].irq        ) * 10,
               ( stats_after->proc_stat_cpu[i].softirq    - stats_before->proc_stat_cpu[i].softirq    ) * 10,
               ( stats_after->proc_stat_cpu[i].steal      - stats_before->proc_stat_cpu[i].steal      ) * 10,
               ( stats_after->proc_stat_cpu[i].guest      - stats_before->proc_stat_cpu[i].guest      ) * 10,
               ( stats_after->proc_stat_cpu[i].guest_nice - stats_before->proc_stat_cpu[i].guest_nice ) * 10,
               ( stats_after->proc_stat_cpu[i].total      - stats_before->proc_stat_cpu[i].total      ) * 10);

    printf("clock realtime:      %3ldms\n", ( stats_after->clock_realtime.tv_sec       - stats_before->clock_realtime.tv_sec       ) * 1000 +
                                            ( stats_after->clock_realtime.tv_nsec      - stats_before->clock_realtime.tv_nsec      ) / 1000000);
    printf("clock monotonic:     %3ldms\n", ( stats_after->clock_monotonic.tv_sec      - stats_before->clock_monotonic.tv_sec      ) * 1000 +
                                            ( stats_after->clock_monotonic.tv_nsec     - stats_before->clock_monotonic.tv_nsec     ) / 1000000);
    printf("clock monotonic raw: %3ldms\n", ( stats_after->clock_monotonic_raw.tv_sec  - stats_before->clock_monotonic_raw.tv_sec  ) * 1000 +
                                            ( stats_after->clock_monotonic_raw.tv_nsec - stats_before->clock_monotonic_raw.tv_nsec ) / 1000000);
}

bool stats_is_abnormal(const struct stats_t *stats_before,
                       const struct stats_t *stats_after)
{
    for(unsigned i = 0; i < stats_before->nb_cpu; i++)
        if(llabs((stats_after->proc_stat_cpu[i].total - stats_before->proc_stat_cpu[i].total) * 10 - TIME_TO_SLEEP_MS) > 20)
            return true;

    if(llabs(( stats_after->clock_realtime.tv_sec  - stats_before->clock_realtime.tv_sec  ) * 1000 +
             ( stats_after->clock_realtime.tv_nsec - stats_before->clock_realtime.tv_nsec ) / 1000000 - TIME_TO_SLEEP_MS) > 1)
        return true;

    if(llabs(( stats_after->clock_monotonic.tv_sec  - stats_before->clock_monotonic.tv_sec  ) * 1000 +
             ( stats_after->clock_monotonic.tv_nsec - stats_before->clock_monotonic.tv_nsec ) / 1000000 - TIME_TO_SLEEP_MS) > 1)
        return true;

    if(llabs(( stats_after->clock_monotonic_raw.tv_sec  - stats_before->clock_monotonic_raw.tv_sec  ) * 1000 +
             ( stats_after->clock_monotonic_raw.tv_nsec - stats_before->clock_monotonic_raw.tv_nsec ) / 1000000 - TIME_TO_SLEEP_MS) > 1)
        return true;

    return false;
}

int main()
{
    struct stats_t *stats_before, *stats_after;

    if((stats_before = malloc(sizeof(struct stats_t))) == NULL)
        exit(EXIT_FAILURE);
    if((stats_after = malloc(sizeof(struct stats_t))) == NULL)
        exit(EXIT_FAILURE);
    stats_init(stats_before);
    stats_init(stats_after);

    stats_fill(stats_before);

    while(true) {
        struct timespec sleeptime = {
            .tv_sec  =   TIME_TO_SLEEP_MS / 1000,
            .tv_nsec = ( TIME_TO_SLEEP_MS % 1000 ) * 1000000
        };
        TEMP_FAILURE_RETRY(nanosleep(&sleeptime, &sleeptime));

        stats_fill(stats_after);

        if(stats_is_abnormal(stats_before, stats_after))
            stats_print_diff(stats_before, stats_after);

        struct stats_t *stats_temp = stats_before;
        stats_before = stats_after;
        stats_after  = stats_temp;
    }

    stats_destroy(stats_before);
    stats_destroy(stats_after);
    free(stats_before);
    free(stats_after);

    return EXIT_SUCCESS;
}
