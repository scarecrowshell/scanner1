// scanner_cwd.c (fixed)
#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>     /* for readlink */
#include <limits.h>     /* for PATH_MAX */

/* Comparator for qsort by PID */
static int pid_cmp(const void *a, const void *b) {
    return (*(const int *)a) - (*(const int *)b);
}

typedef struct {
    int   pid;
    char  comm[17];           /* short process name */
    char  cwd[PATH_MAX];      /* current working directory path */
} ProcCWD;

/*
   Scanner: Current working directory (CWD) for all running processes
   Reads symlink target of /proc/<pid>/cwd
   Output: JSON array → replace with your DB insert code
*/
void scan_current_working_directory(void)
{
    DIR *proc = opendir("/proc");
    if (!proc) {
        perror("opendir /proc");
        return;
    }

    ProcCWD *cwds = NULL;
    size_t capacity = 0;
    size_t count = 0;

    struct dirent *ent;
    while ((ent = readdir(proc)) != NULL) {
        if (ent->d_type != DT_DIR) continue;
        if (!isdigit((unsigned char)ent->d_name[0])) continue;

        int pid = atoi(ent->d_name);
        if (pid <= 0) continue;

        /* Get comm */
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

        /* Get CWD via readlink on /proc/<pid>/cwd */
        char cwd_path[64];
        snprintf(cwd_path, sizeof(cwd_path), "/proc/%d/cwd", pid);

        char cwd_buf[PATH_MAX + 1];
        ssize_t r = readlink(cwd_path, cwd_buf, PATH_MAX);
        if (r < 0) {
            /* Process vanished or no permission — skip */
            continue;
        }
        /* ensure we never write past buffer and always null-terminate */
        ssize_t len = r;
        if (len >= PATH_MAX) len = PATH_MAX - 1;
        cwd_buf[len] = '\0';   /* null-terminate */

        /* Grow array */
        if (count >= capacity) {
            capacity = capacity ? capacity * 2 : 8192;
            ProcCWD *new_cwds = realloc(cwds, capacity * sizeof(ProcCWD));
            if (!new_cwds) continue;
            cwds = new_cwds;
        }

        cwds[count].pid = pid;
        /* safe copy of comm */
        snprintf(cwds[count].comm, sizeof(cwds[count].comm), "%s", comm);

        /* copy exact length into fixed buffer and NUL terminate (avoids snprintf truncation warning) */
        size_t copy_len = (size_t)len;
        if (copy_len >= sizeof(cwds[count].cwd)) copy_len = sizeof(cwds[count].cwd) - 1;
        memcpy(cwds[count].cwd, cwd_buf, copy_len);
        cwds[count].cwd[copy_len] = '\0';

        count++;
    }

    closedir(proc);

    if (count == 0) {
        free(cwds);
        printf("[]\n");
        return;
    }

    /* Sort by PID for consistent output */
    qsort(cwds, count, sizeof(ProcCWD), pid_cmp);

    /* === OUTPUT – replace this block with your database insert === */
    printf("[\n");
    for (size_t i = 0; i < count; i++) {
        /* Escape quotes/backslashes in CWD for JSON safety */
        printf("  {\"pid\":%d,\"comm\":\"%s\",\"cwd\":\"",
               cwds[i].pid, cwds[i].comm);
        for (char *p = cwds[i].cwd; *p; p++) {
            if (*p == '"' || *p == '\\') putchar('\\');
            putchar(*p);
        }
        printf("\"}");

        if (i < count - 1) printf(",");
        printf("\n");
    }
    printf("]\n");

    free(cwds);
}

int main(void)
{
    scan_current_working_directory();
    return 0;
}
