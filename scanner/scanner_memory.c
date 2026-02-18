#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

/* Comparator for qsort by PID */
static int pid_cmp(const void *a, const void *b) {
    return (*(const int *)a) - (*(const int *)b);
}

typedef struct {
    int    pid;
    char   comm[17];          /* short name from /proc/pid/comm */
    unsigned long vmsize;     /* VmSize  - total virtual memory (kB) */
    unsigned long vmrss;      /* VmRSS   - resident set size (physical RAM used, kB) */
    unsigned long vmhwm;      /* VmHWM   - peak resident set size (kB) */
    unsigned long vmswap;     /* VmSwap  - amount swapped out (kB) */
    unsigned long vmdata;     /* VmData  - size of data + stack (kB) */
    unsigned long vmstk;      /* VmStk   - stack size (kB) */
} ProcMemory;

/*
   Scanner: Memory usage (RSS, VSZ, Swap, HWM, etc.) for all processes
   Reads selected fields from /proc/<pid>/status
   All values in kB (as reported by kernel)
   Output: JSON array → replace with your DB insert code
*/
void scan_process_memory(void)
{
    DIR *proc = opendir("/proc");
    if (!proc) {
        perror("opendir /proc");
        return;
    }

    ProcMemory *mems = NULL;
    size_t capacity = 0;
    size_t count = 0;

    struct dirent *ent;
    while ((ent = readdir(proc)) != NULL) {
        if (ent->d_type != DT_DIR) continue;
        if (!isdigit((unsigned char)ent->d_name[0])) continue;

        int pid = atoi(ent->d_name);
        if (pid <= 0) continue;

        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/status", pid);

        FILE *fp = fopen(path, "re");
        if (!fp) continue;

        ProcMemory info = { .pid = pid, .vmsize = 0, .vmrss = 0, .vmhwm = 0,
                            .vmswap = 0, .vmdata = 0, .vmstk = 0 };

        char line[256];
        int comm_read = 0;

        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "Name:", 5) == 0 && !comm_read) {
                sscanf(line + 5, "%16s", info.comm);
                comm_read = 1;
            }
            else if (strncmp(line, "VmSize:", 7) == 0) {
                sscanf(line + 7, "%lu", &info.vmsize);
            }
            else if (strncmp(line, "VmRSS:", 6) == 0) {
                sscanf(line + 6, "%lu", &info.vmrss);
            }
            else if (strncmp(line, "VmHWM:", 6) == 0) {
                sscanf(line + 6, "%lu", &info.vmhwm);
            }
            else if (strncmp(line, "VmSwap:", 7) == 0) {
                sscanf(line + 7, "%lu", &info.vmswap);
            }
            else if (strncmp(line, "VmData:", 7) == 0) {
                sscanf(line + 7, "%lu", &info.vmdata);
            }
            else if (strncmp(line, "VmStk:", 6) == 0) {
                sscanf(line + 6, "%lu", &info.vmstk);
            }
        }
        fclose(fp);

        /* Require at least the core ones to be present */
        if (info.vmsize == 0 && info.vmrss == 0) continue;

        /* Grow array */
        if (count >= capacity) {
            capacity = capacity ? capacity * 2 : 8192;
            ProcMemory *new_mems = realloc(mems, capacity * sizeof(ProcMemory));
            if (!new_mems) continue;
            mems = new_mems;
        }

        mems[count++] = info;
    }

    closedir(proc);

    if (count == 0) {
        free(mems);
        printf("[]\n");
        return;
    }

    /* Sort by PID for consistent output */
    qsort(mems, count, sizeof(ProcMemory), pid_cmp);

    /* === OUTPUT – replace this block with your database insert === */
    printf("[\n");
    for (size_t i = 0; i < count; i++) {
        printf("  {\"pid\":%d,\"comm\":\"%s\","
               "\"vmsize_kb\":%lu,\"vmrss_kb\":%lu,\"vmhwm_kb\":%lu,"
               "\"vmswap_kb\":%lu,\"vmdata_kb\":%lu,\"vmstk_kb\":%lu}",
               mems[i].pid, mems[i].comm,
               mems[i].vmsize, mems[i].vmrss, mems[i].vmhwm,
               mems[i].vmswap, mems[i].vmdata, mems[i].vmstk);

        if (i < count - 1) printf(",");
        printf("\n");
    }
    printf("]\n");

    /* Example DB-style replacement:
    for (size_t i = 0; i < count; i++) {
        db_insert_memory(mems[i].pid, mems[i].comm,
                         mems[i].vmsize, mems[i].vmrss, mems[i].vmhwm,
                         mems[i].vmswap, mems[i].vmdata, mems[i].vmstk);
    }
    */

    free(mems);
}

int main(void)
{
    scan_process_memory();
    return 0;
}
