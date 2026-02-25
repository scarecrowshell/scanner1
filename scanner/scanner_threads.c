// scanner_threads.c
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
    char   comm[17];              /* main process comm */
    int    thread_count;          /* number of threads (including main) */
    char **thread_names;          /* array of thread comm names */
    size_t name_count;
    size_t name_capacity;
} ProcThreads;

static void add_thread_name(ProcThreads *p, const char *name) {
    if (p->name_count >= p->name_capacity) {
        p->name_capacity = p->name_capacity ? p->name_capacity * 2 : 64;
        char **new_names = realloc(p->thread_names, p->name_capacity * sizeof(char *));
        if (!new_names) return;
        p->thread_names = new_names;
    }

    p->thread_names[p->name_count] = strdup(name);
    if (p->thread_names[p->name_count]) p->name_count++;
}

static void free_procthreads(ProcThreads *p) {
    for (size_t i = 0; i < p->name_count; i++) {
        free(p->thread_names[i]);
    }
    free(p->thread_names);
    p->thread_names = NULL;
    p->name_count = p->name_capacity = 0;
}

/*
   Scanner: Number of threads and their names (comm) per process
   - thread_count: from /proc/<pid>/status "Threads:" or by counting entries under /proc/<pid>/task/
   - thread_names: comm from each /proc/<pid>/task/<tid>/comm

   Output: JSON array of {pid, comm, thread_count, threads: ["name1", "name2", ...]}
*/
void scan_process_threads(void)
{
    DIR *proc = opendir("/proc");
    if (!proc) {
        perror("opendir /proc");
        return;
    }

    ProcThreads *processes = NULL;
    size_t capacity = 0;
    size_t count = 0;

    struct dirent *ent;
    while ((ent = readdir(proc)) != NULL) {
        if (ent->d_type != DT_DIR) continue;
        if (!isdigit((unsigned char)ent->d_name[0])) continue;

        int pid = atoi(ent->d_name);
        if (pid <= 0) continue;

        /* Get main comm */
        char comm_path[64];
        snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
        FILE *fc = fopen(comm_path, "re");
        char comm[17] = "[unknown]";
        if (fc) {
            if (fgets(comm, sizeof(comm), fc)) {
                size_t len = strlen(comm);
                if (len > 0 && comm[len-1] == '\n') comm[len-1] = '\0';
            }
            fclose(fc);
        }

        /* Open /proc/<pid>/task directory */
        char task_path[64];
        snprintf(task_path, sizeof(task_path), "/proc/%d/task", pid);

        DIR *taskdir = opendir(task_path);
        if (!taskdir) continue;

        ProcThreads info = { .pid = pid, .thread_count = 0,
                             .name_count = 0, .name_capacity = 0, .thread_names = NULL };
        /* safe copy of comm to avoid truncation warnings */
        snprintf(info.comm, sizeof(info.comm), "%s", comm);

        struct dirent *taskent;
        while ((taskent = readdir(taskdir)) != NULL) {
            if (taskent->d_type != DT_DIR) continue;
            if (!isdigit((unsigned char)taskent->d_name[0])) continue;

            int tid = atoi(taskent->d_name);
            if (tid <= 0) continue;

            /* Get thread comm */
            char tcomm_path[128];
            snprintf(tcomm_path, sizeof(tcomm_path), "/proc/%d/task/%d/comm", pid, tid);

            FILE *ftc = fopen(tcomm_path, "re");
            if (!ftc) continue;

            char tcomm[17] = "[thread]";
            if (fgets(tcomm, sizeof(tcomm), ftc)) {
                size_t len = strlen(tcomm);
                if (len > 0 && tcomm[len-1] == '\n') tcomm[len-1] = '\0';
            }
            fclose(ftc);

            add_thread_name(&info, tcomm);
            info.thread_count++;
        }
        closedir(taskdir);

        if (info.thread_count == 0) {
            free_procthreads(&info);
            continue;
        }

        /* Grow main array */
        if (count >= capacity) {
            capacity = capacity ? capacity * 2 : 8192;
            ProcThreads *new_proc = realloc(processes, capacity * sizeof(ProcThreads));
            if (!new_proc) {
                free_procthreads(&info);
                continue;
            }
            processes = new_proc;
        }

        processes[count++] = info;
    }

    closedir(proc);

    if (count == 0) {
        free(processes);
        printf("[]\n");
        return;
    }

    /* Sort by PID */
    qsort(processes, count, sizeof(ProcThreads), pid_cmp);

    /* === OUTPUT – replace this block with your DB insert === */
    printf("[\n");
    for (size_t i = 0; i < count; i++) {
        printf("  {\"pid\":%d,\"comm\":\"%s\",\"thread_count\":%d,\"threads\":[",
               processes[i].pid, processes[i].comm, processes[i].thread_count);

        for (size_t j = 0; j < processes[i].name_count; j++) {
            /* escape quotes/backslashes in thread names */
            printf("\"");
            for (char *p = processes[i].thread_names[j]; *p; p++) {
                if (*p == '"' || *p == '\\') putchar('\\');
                putchar(*p);
            }
            printf("\"");
            if (j < processes[i].name_count - 1) printf(",");
        }

        printf("]}");
        if (i < count - 1) printf(",");
        printf("\n");
    }
    printf("]\n");

    /* Cleanup */
    for (size_t i = 0; i < count; i++) {
        free_procthreads(&processes[i]);
    }
    free(processes);
}

int main(void)
{
    scan_process_threads();
    return 0;
}
