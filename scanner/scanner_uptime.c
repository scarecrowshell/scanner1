#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <time.h>       /* for time_t */
#include <sys/sysinfo.h> /* for get_boottime (but we'll use /proc/uptime) */
#include <unistd.h>     /* for sysconf(_SC_CLK_TCK) */

/* Comparator for qsort by PID */
static int pid_cmp(const void *a, const void *b) {
    return (*(const int *)a) - (*(const int *)b);
}

typedef struct {
    int    pid;
    char   comm[17];              /* short name */
    unsigned long start_jiffies;  /* raw starttime from /proc/pid/stat (field 22) */
    time_t start_time;            /* absolute start time (seconds since epoch) */
    unsigned long uptime_sec;     /* process uptime in seconds */
    char   uptime_human[64];      /* human-readable uptime (e.g. "2d 3h 45m 12s") */
} ProcUptime;

/* Get system boot time (seconds since epoch) from /proc/uptime */
static time_t get_boot_time(void) {
    FILE *fp = fopen("/proc/uptime", "re");
    if (!fp) return 0;

    double uptime_sec;
    if (fscanf(fp, "%lf", &uptime_sec) != 1) {
        fclose(fp);
        return 0;
    }
    fclose(fp);

    return time(NULL) - (time_t)uptime_sec;
}

/* Convert seconds to human-readable "Xd Yh Zm Ws" */
static void seconds_to_human(unsigned long sec, char *buf, size_t bufsize) {
    unsigned long days = sec / 86400;
    sec %= 86400;
    unsigned long hours = sec / 3600;
    sec %= 3600;
    unsigned long mins = sec / 60;
    sec %= 60;

    snprintf(buf, bufsize, "%lud %luh %lum %lus", days, hours, mins, sec);
}

/*
   Scanner: Process start time & uptime
   - start_jiffies: raw from /proc/pid/stat field 22 (jiffies since boot)
   - start_time: absolute Unix timestamp (seconds since epoch)
   - uptime_sec: process runtime in seconds
   - uptime_human: readable string like "0d 1h 23m 45s"

   Requires system CLK_TCK for jiffies → seconds conversion
   Uses /proc/uptime for boot time calc
*/
void scan_process_start_uptime(void)
{
    long clk_tck = sysconf(_SC_CLK_TCK);
    if (clk_tck <= 0) {
        fprintf(stderr, "sysconf(_SC_CLK_TCK) failed\n");
        return;
    }

    time_t boot_time = get_boot_time();
    if (boot_time == 0) {
        fprintf(stderr, "Failed to get boot time from /proc/uptime\n");
        return;
    }

    DIR *proc = opendir("/proc");
    if (!proc) {
        perror("opendir /proc");
        return;
    }

    ProcUptime *uptimes = NULL;
    size_t capacity = 0;
    size_t count = 0;

    struct dirent *ent;
    while ((ent = readdir(proc)) != NULL) {
        if (ent->d_type != DT_DIR) continue;
        if (!isdigit((unsigned char)ent->d_name[0])) continue;

        int pid = atoi(ent->d_name);
        if (pid <= 0) continue;

        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/stat", pid);

        FILE *fp = fopen(path, "re");
        if (!fp) continue;

        int dummy_int;
        char dummy_char;
        char comm[17] = {0};
        unsigned long start_jiffies = 0;

        /* Parse up to field 22: pid (comm) state ppid ... starttime (field 22) */
        int scanned = fscanf(fp,
            "%d (%16[^)]) %c %d %*d %*d %*d %*d %*u %*u %*u %*u %*u "
            "%*u %*u %*d %*d %*d %*d %*d %*d %lu",
            &dummy_int, comm, &dummy_char, &dummy_int,
            &start_jiffies);

        fclose(fp);

        if (scanned != 5) continue;  /* parsing failed */

        /* Compute start_time and uptime */
        time_t start_time = boot_time + (start_jiffies / clk_tck);
        time_t now = time(NULL);
        unsigned long uptime_sec = (unsigned long)difftime(now, start_time);

        /* Grow array */
        if (count >= capacity) {
            capacity = capacity ? capacity * 2 : 8192;
            ProcUptime *new_uptimes = realloc(uptimes, capacity * sizeof(ProcUptime));
            if (!new_uptimes) continue;
            uptimes = new_uptimes;
        }

        uptimes[count].pid = pid;
        strncpy(uptimes[count].comm, comm, sizeof(uptimes[count].comm) - 1);
        uptimes[count].comm[sizeof(uptimes[count].comm) - 1] = '\0';
        uptimes[count].start_jiffies = start_jiffies;
        uptimes[count].start_time = start_time;
        uptimes[count].uptime_sec = uptime_sec;
        seconds_to_human(uptime_sec, uptimes[count].uptime_human, sizeof(uptimes[count].uptime_human));

        count++;
    }

    closedir(proc);

    if (count == 0) {
        free(uptimes);
        printf("[]\n");
        return;
    }

    /* Sort by PID */
    qsort(uptimes, count, sizeof(ProcUptime), pid_cmp);

    /* === OUTPUT – replace this with your database insert logic === */
    printf("[\n");
    for (size_t i = 0; i < count; i++) {
        printf("  {\"pid\":%d,\"comm\":\"%s\","
               "\"start_jiffies\":%lu,\"start_time\":%ld,"
               "\"uptime_sec\":%lu,\"uptime_human\":\"%s\"}",
               uptimes[i].pid, uptimes[i].comm,
               uptimes[i].start_jiffies, uptimes[i].start_time,
               uptimes[i].uptime_sec, uptimes[i].uptime_human);

        if (i < count - 1) printf(",");
        printf("\n");
    }
    printf("]\n");

    /* Example DB replacement:
    for (size_t i = 0; i < count; i++) {
        db_insert_uptime(uptimes[i].pid, uptimes[i].comm,
                         uptimes[i].start_jiffies, uptimes[i].start_time,
                         uptimes[i].uptime_sec, uptimes[i].uptime_human);
    }
    */

    free(uptimes);
}

int main(void)
{
    scan_process_start_uptime();
    return 0;
}
