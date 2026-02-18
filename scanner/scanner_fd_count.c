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
    int   pid;
    char  comm[17];           /* short process name */
    int   open_fds;           /* number of entries in /proc/pid/fd */
    int   fdinfo_count;       /* optional: number in /proc/pid/fdinfo (usually same) */
} ProcFDCount;

/*
   Scanner: Open file descriptors count for all running processes
   Counts entries in /proc/<pid>/fd directory (most accurate & efficient method)
   Also optionally counts /proc/<pid>/fdinfo (should match)

   Output: JSON array → replace print block with your DB insert logic
*/
void scan_open_file_descriptors(void)
{
    DIR *proc = opendir("/proc");
    if (!proc) {
        perror("opendir /proc");
        return;
    }

    ProcFDCount *fds = NULL;
    size_t capacity = 0;
    size_t count = 0;

    struct dirent *ent;
    while ((ent = readdir(proc)) != NULL) {
        if (ent->d_type != DT_DIR) continue;
        if (!isdigit((unsigned char)ent->d_name[0])) continue;

        int pid = atoi(ent->d_name);
        if (pid <= 0) continue;

        /* Build /proc/<pid>/comm for nicer output */
        char comm_path[64];
        snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);

        FILE *fc = fopen(comm_path, "re");
        char comm[17] = {0};
        if (fc) {
            if (fgets(comm, sizeof(comm), fc)) {
                size_t len = strlen(comm);
                if (len > 0 && comm[len-1] == '\n') comm[len-1] = '\0';
            }
            fclose(fc);
        }

        /* Count open fds: number of entries in /proc/<pid>/fd */
        char fd_path[64];
        snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd", pid);

        DIR *fddir = opendir(fd_path);
        if (!fddir) continue;   /* process vanished or no access */

        int fd_count = 0;
        struct dirent *fdent;
        while ((fdent = readdir(fddir)) != NULL) {
            /* Skip . and .. */
            if (fdent->d_name[0] == '.' &&
                (fdent->d_name[1] == '\0' || (fdent->d_name[1] == '.' && fdent->d_name[2] == '\0'))) {
                continue;
            }
            fd_count++;
        }
        closedir(fddir);

        if (fd_count == 0) continue;   /* rare, but skip empty */

        /* Optional: also count fdinfo (usually same number) */
        int fdinfo_count = 0;
        snprintf(fd_path, sizeof(fd_path), "/proc/%d/fdinfo", pid);
        DIR *fdinfodir = opendir(fd_path);
        if (fdinfodir) {
            while ((fdent = readdir(fdinfodir)) != NULL) {
                if (fdent->d_name[0] == '.' && 
                    (fdent->d_name[1] == '\0' || (fdent->d_name[1] == '.' && fdent->d_name[2] == '\0'))) continue;
                fdinfo_count++;
            }
            closedir(fdinfodir);
        }

        /* Grow array */
        if (count >= capacity) {
            capacity = capacity ? capacity * 2 : 8192;
            ProcFDCount *new_fds = realloc(fds, capacity * sizeof(ProcFDCount));
            if (!new_fds) continue;
            fds = new_fds;
        }

        fds[count].pid = pid;
        strncpy(fds[count].comm, comm, sizeof(fds[count].comm) - 1);
        fds[count].comm[sizeof(fds[count].comm) - 1] = '\0';
        fds[count].open_fds = fd_count;
        fds[count].fdinfo_count = fdinfo_count;

        count++;
    }

    closedir(proc);

    if (count == 0) {
        free(fds);
        printf("[]\n");
        return;
    }

    /* Sort by PID for consistent output */
    qsort(fds, count, sizeof(ProcFDCount), pid_cmp);

    /* === OUTPUT – replace this with your database insert code === */
    printf("[\n");
    for (size_t i = 0; i < count; i++) {
        printf("  {\"pid\":%d,\"comm\":\"%s\",\"open_fds\":%d,\"fdinfo_count\":%d}",
               fds[i].pid, fds[i].comm,
               fds[i].open_fds, fds[i].fdinfo_count);

        if (i < count - 1) printf(",");
        printf("\n");
    }
    printf("]\n");

    /* Example DB-style loop:
    for (size_t i = 0; i < count; i++) {
        db_insert_fd_count(fds[i].pid, fds[i].comm,
                           fds[i].open_fds, fds[i].fdinfo_count);
    }
    */

    free(fds);
}

int main(void)
{
    scan_open_file_descriptors();
    return 0;
}
