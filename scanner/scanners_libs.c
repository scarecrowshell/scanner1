#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdbool.h>

/* Comparator for qsort by PID */
static int pid_cmp(const void *a, const void *b) {
    return (*(const int *)a) - (*(const int *)b);
}

typedef struct {
    int    pid;
    char   comm[17];
    char **libs;           /* dynamic array of library paths */
    size_t lib_count;
    size_t lib_capacity;
} ProcLibs;

static void add_library(ProcLibs *p, const char *path) {
    if (p->lib_count >= p->lib_capacity) {
        p->lib_capacity = p->lib_capacity ? p->lib_capacity * 2 : 32;
        char **new_libs = realloc(p->libs, p->lib_capacity * sizeof(char *));
        if (!new_libs) return;
        p->libs = new_libs;
    }

    /* Deduplicate — skip if already present */
    for (size_t i = 0; i < p->lib_count; i++) {
        if (strcmp(p->libs[i], path) == 0) return;
    }

    p->libs[p->lib_count] = strdup(path);
    if (p->libs[p->lib_count]) p->lib_count++;
}

static void free_proclib(ProcLibs *p) {
    for (size_t i = 0; i < p->lib_count; i++) {
        free(p->libs[i]);
    }
    free(p->libs);
    p->libs = NULL;
    p->lib_count = p->lib_capacity = 0;
}

/*
   Scanner: Loaded shared libraries (.so files) per process
   Parses /proc/<pid>/maps and collects unique .so paths
   Output: JSON array of {pid, comm, libraries: [...]}
*/
void scan_loaded_shared_libraries(void)
{
    DIR *proc = opendir("/proc");
    if (!proc) {
        perror("opendir /proc");
        return;
    }

    ProcLibs *processes = NULL;
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

        /* Open /proc/<pid>/maps */
        char maps_path[64];
        snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

        FILE *fm = fopen(maps_path, "re");
        if (!fm) continue;

        ProcLibs info = { .pid = pid, .lib_count = 0, .lib_capacity = 0, .libs = NULL };
        snprintf(info.comm, sizeof(info.comm), "%s", comm);
        info.comm[sizeof(info.comm) - 1] = '\0';

        char line[1024];
        while (fgets(line, sizeof(line), fm)) {
            /* Typical line: address           perms offset  dev   inode       pathname
               Example: 7f8b5c000000-7f8b5c021000 r-xp 00000000 08:01 1234567 /usr/lib/x86_64-linux-gnu/libc.so.6
            */
            char *pathname = strrchr(line, '/');
            if (!pathname) continue;

            /* Look for .so at the end */
            if (strstr(pathname, ".so") == NULL) continue;

            /* Trim trailing whitespace/newline */
            char *end = pathname + strlen(pathname) - 1;
            while (end >= pathname && isspace((unsigned char)*end)) *end-- = '\0';

            add_library(&info, pathname);
        }
        fclose(fm);

        if (info.lib_count == 0) {
            free_proclib(&info);
            continue;
        }

        /* Grow main array */
        if (count >= capacity) {
            capacity = capacity ? capacity * 2 : 8192;
            ProcLibs *new_proc = realloc(processes, capacity * sizeof(ProcLibs));
            if (!new_proc) {
                free_proclib(&info);
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
    qsort(processes, count, sizeof(ProcLibs), pid_cmp);

    /* === OUTPUT – replace this block with your DB insert === */
    printf("[\n");
    for (size_t i = 0; i < count; i++) {
        printf("  {\"pid\":%d,\"comm\":\"%s\",\"libraries\":[",
               processes[i].pid, processes[i].comm);

        for (size_t j = 0; j < processes[i].lib_count; j++) {
            /* Escape quotes in path (very rare in real paths, but safe) */
            printf("\"");
            for (char *p = processes[i].libs[j]; *p; p++) {
                if (*p == '"' || *p == '\\') putchar('\\');
                putchar(*p);
            }
            printf("\"");
            if (j < processes[i].lib_count - 1) printf(",");
        }

        printf("]}");
        if (i < count - 1) printf(",");
        printf("\n");
    }
    printf("]\n");

    /* Cleanup */
    for (size_t i = 0; i < count; i++) {
        free_proclib(&processes[i]);
    }
    free(processes);
}

int main(void)
{
    scan_loaded_shared_libraries();
    return 0;
}
