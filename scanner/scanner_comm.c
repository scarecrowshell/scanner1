#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

/* Comparator for qsort by PID */
static int pid_cmp(const void *a, const void *b) {
    return (*(const int *)a) - (*(const int *)b);
}

/*
   Scanner: All running processes → PID + comm (short process name)
   Output format: simple JSON array of objects
   Example:
   [{"pid":1,"name":"systemd"},{"pid":2,"name":"kthreadd"},...]

   Replace the output block with your DB insert logic.
*/
void scan_process_names_comm(void)
{
    DIR *proc = opendir("/proc");
    if (!proc) {
        perror("opendir /proc failed");
        return;
    }

    /* We'll collect structs with pid + name */
    struct proc_info {
        int pid;
        char name[17];          /* TASK_COMM_LEN = 16 + null */
    };

    struct proc_info *procs = NULL;
    size_t capacity = 0;
    size_t count = 0;

    struct dirent *ent;
    while ((ent = readdir(proc)) != NULL) {
        if (ent->d_type != DT_DIR) continue;

        /* Skip if not a numeric directory (PID) */
        if (!isdigit((unsigned char)ent->d_name[0])) continue;

        int pid = atoi(ent->d_name);
        if (pid <= 0) continue;

        /* Build path: /proc/<pid>/comm */
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/comm", pid);

        FILE *fp = fopen(path, "re");   /* e = O_CLOEXEC */
        if (!fp) continue;              /* process may have died meanwhile */

        char comm[17] = {0};
        if (fgets(comm, sizeof(comm), fp)) {
            /* Remove trailing newline if present */
            size_t len = strlen(comm);
            if (len > 0 && comm[len-1] == '\n')
                comm[len-1] = '\0';

            /* Grow array if needed */
            if (count >= capacity) {
                capacity = capacity ? capacity * 2 : 8192;
                struct proc_info *new_procs = realloc(procs, capacity * sizeof(*procs));
                if (!new_procs) {
                    fclose(fp);
                    continue;   /* skip on alloc failure – or handle error */
                }
                procs = new_procs;
            }

            procs[count].pid = pid;
            strncpy(procs[count].name, comm, sizeof(procs[count].name) - 1);
            procs[count].name[sizeof(procs[count].name) - 1] = '\0';
            count++;
        }
        fclose(fp);
    }

    closedir(proc);

    if (count == 0) {
        free(procs);
        printf("[]\n");
        return;
    }

    /* Sort by PID (optional but nice for consistent output) */
    qsort(procs, count, sizeof(struct proc_info), pid_cmp);

    /* === OUTPUT – replace this with your database insert === */
    printf("[\n");
    for (size_t i = 0; i < count; i++) {
        printf("  {\"pid\":%d,\"name\":\"%s\"}",
               procs[i].pid,
               procs[i].name);
        if (i < count - 1)
            printf(",");
        printf("\n");
    }
    printf("]\n");

    /* Alternative DB-style loop example:
    for (size_t i = 0; i < count; i++) {
        db_insert_process(procs[i].pid, procs[i].name);
    }
    */

    free(procs);
}

int main(void)
{
    scan_process_names_comm();
    return 0;
}
