/* scanner_proc_open_files.c - safer string handling + correct qsort comparator */
#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>     /* for readlink */
#include <limits.h>     /* for PATH_MAX */

/* struct must be visible to comparator */
typedef struct {
    int   pid;
    char  comm[17];           /* short process name */
    char **files;             /* array of "fd:target_path" strings */
    size_t file_count;
    size_t file_capacity;
} ProcOpenFiles;

/* Comparator for qsort by PID (compare struct entries, safe) */
static int pid_cmp(const void *a, const void *b) {
    const ProcOpenFiles *pa = (const ProcOpenFiles *)a;
    const ProcOpenFiles *pb = (const ProcOpenFiles *)b;
    return (pa->pid > pb->pid) - (pa->pid < pb->pid);
}

/* Helper: add fd:target string to ProcOpenFiles (allocates copy) */
static void add_open_file(ProcOpenFiles *p, const char *fd_str, const char *target) {
    if (!p || !fd_str || !target) return;

    size_t need = strlen(fd_str) + 1 + strlen(target) + 1; /* fd:target + NUL */
    char *entry = malloc(need);
    if (!entry) return;

    /* snprintf won't overflow because entry is sized precisely */
    snprintf(entry, need, "%s:%s", fd_str, target);

    if (p->file_count >= p->file_capacity) {
        size_t newcap = p->file_capacity ? p->file_capacity * 2 : 128;
        char **new_files = realloc(p->files, newcap * sizeof(char *));
        if (!new_files) {
            free(entry);
            return;
        }
        p->files = new_files;
        p->file_capacity = newcap;
    }

    p->files[p->file_count++] = entry;
}

static void free_procopenfiles(ProcOpenFiles *p) {
    if (!p) return;
    for (size_t i = 0; i < p->file_count; i++) {
        free(p->files[i]);
    }
    free(p->files);
    p->files = NULL;
    p->file_count = p->file_capacity = 0;
}

/*
   Scanner: Open files per process (which process has which file open)
   For each process: list FD numbers and their target paths (via readlink /proc/pid/fd/N)
   Includes sockets/pipes/anon_inodes (e.g., "socket:[12345]") if no path.
   Output: JSON array of {pid, comm, open_files: ["fd1:/path/to/file", "fd2:socket:[inode]", ...]}
   Note: requires root for other users' processes; skips inaccessible.
*/
void scan_open_files_per_process(void)
{
    DIR *proc = opendir("/proc");
    if (!proc) {
        perror("opendir /proc");
        return;
    }

    ProcOpenFiles *procs = NULL;
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

        /* Open /proc/<pid>/fd */
        char fd_path[64];
        snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd", pid);

        DIR *fddir = opendir(fd_path);
        if (!fddir) continue;  /* no access or gone */

        ProcOpenFiles info = { .pid = pid, .file_count = 0, .file_capacity = 0, .files = NULL };
        /* use snprintf to copy comm safely and avoid strncpy truncation warning */
        (void)snprintf(info.comm, sizeof(info.comm), "%s", comm);
        info.comm[sizeof(info.comm)-1] = '\0';

        struct dirent *fdent;
        while ((fdent = readdir(fddir)) != NULL) {
            if (fdent->d_name[0] == '.' &&
                (fdent->d_name[1] == '\0' || (fdent->d_name[1] == '.' && fdent->d_name[2] == '\0'))) continue;

            /* Get target via readlink */
            char link_path[128];
            int needed = snprintf(link_path, sizeof(link_path), "/proc/%d/fd/%s", pid, fdent->d_name);
            if (needed < 0 || needed >= (int)sizeof(link_path)) {
                /* path unexpectedly long — skip this fd */
                continue;
            }

            char target[PATH_MAX + 1];
            ssize_t tlen = readlink(link_path, target, (sizeof(target) - 1));
            if (tlen < 0) continue;
            if (tlen >= (ssize_t)sizeof(target)) continue; /* too long — defensive */
            target[tlen] = '\0';

            add_open_file(&info, fdent->d_name, target);
        }
        closedir(fddir);

        if (info.file_count == 0) {
            free_procopenfiles(&info);
            continue;
        }

        /* Grow main array */
        if (count >= capacity) {
            size_t newcap = capacity ? capacity * 2 : 8192;
            ProcOpenFiles *new_procs = realloc(procs, newcap * sizeof(ProcOpenFiles));
            if (!new_procs) {
                free_procopenfiles(&info);
                continue;
            }
            procs = new_procs;
            capacity = newcap;
        }

        procs[count++] = info;
    }

    closedir(proc);

    if (count == 0) {
        free(procs);
        printf("[]\n");
        return;
    }

    /* Sort by PID using the safe comparator above */
    qsort(procs, count, sizeof(ProcOpenFiles), pid_cmp);

    /* === OUTPUT – replace this block with your DB insert === */
    printf("[\n");
    for (size_t i = 0; i < count; i++) {
        printf("  {\"pid\":%d,\"comm\":\"%s\",\"open_files\":[",
               procs[i].pid, procs[i].comm);

        for (size_t j = 0; j < procs[i].file_count; j++) {
            printf("\"");
            for (char *p = procs[i].files[j]; *p; p++) {
                if (*p == '"' || *p == '\\') putchar('\\');
                putchar(*p);
            }
            printf("\"");
            if (j < procs[i].file_count - 1) printf(",");
        }

        printf("]}");
        if (i < count - 1) printf(",");
        printf("\n");
    }
    printf("]\n");

    /* Cleanup */
    for (size_t i = 0; i < count; i++) {
        free_procopenfiles(&procs[i]);
    }
    free(procs);
}

int main(void)
{
    scan_open_files_per_process();
    return 0;
}
