// scanner_critical_files.c (fixed - safe path copy)
#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>

/* File info structure (must be defined before comparator) */
typedef struct {
    char path[PATH_MAX];
    off_t size;         /* file size in bytes */
    mode_t mode;        /* permissions (octal) */
    uid_t uid;
    gid_t gid;
    time_t mtime;       /* last modification time (Unix timestamp) */
} FileInfo;

/* Comparator for qsort by path (alphabetical) */
static int path_cmp(const void *a, const void *b) {
    return strcmp(((const FileInfo *)a)->path,
                  ((const FileInfo *)b)->path);
}

/* Recursive scanner function */
static void scan_dir(const char *dir, FileInfo **files, size_t *count, size_t *capacity) {
    DIR *d = opendir(dir);
    if (!d) {
        /* skip directories we cannot open (permission, non-existent) */
        return;
    }

    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;

        char full[PATH_MAX];
        /* build path safely */
        int ret = snprintf(full, sizeof(full), "%s/%s", dir, e->d_name);
        if (ret < 0) continue; /* encoding error */
        /* if truncated, ensure full is a valid truncated path (we'll copy truncated) */

        struct stat st;
        if (lstat(full, &st) < 0) continue;  /* skip on error (e.g., permission) */

        /* Grow array if needed */
        if (*count >= *capacity) {
            *capacity = *capacity ? *capacity * 2 : 8192;
            FileInfo *new_files = realloc(*files, *capacity * sizeof(FileInfo));
            if (!new_files) {
                closedir(d);
                return;  /* alloc fail – abort scanning this branch */
            }
            *files = new_files;
        }

        /* safe copy of path: copy exact length up to buffer-1 and NUL terminate */
        size_t plen = strlen(full);
        if (plen >= sizeof((*files)[*count].path)) plen = sizeof((*files)[*count].path) - 1;
        memcpy((*files)[*count].path, full, plen);
        (*files)[*count].path[plen] = '\0';

        (*files)[*count].size = st.st_size;
        (*files)[*count].mode = st.st_mode & 07777;  /* mask to permissions */
        (*files)[*count].uid = st.st_uid;
        (*files)[*count].gid = st.st_gid;
        (*files)[*count].mtime = st.st_mtime;

        (*count)++;

        /* Recurse if directory (but not symlink to dir) */
        if (S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) {
            scan_dir(full, files, count, capacity);
        }
    }

    closedir(d);
}

/*
   Scanner: Files in critical directories
   Recursively scans: /etc, /bin, /sbin, /usr/bin, /lib, /var, /tmp, /home, /root
*/
void scan_critical_files(void)
{
    const char *dirs[] = {
        "/etc", "/bin", "/sbin", "/usr/bin", "/lib",
        "/var", "/tmp", "/home", "/root",
        NULL
    };

    FileInfo *files = NULL;
    size_t capacity = 0;
    size_t count = 0;

    for (int i = 0; dirs[i]; i++) {
        scan_dir(dirs[i], &files, &count, &capacity);
    }

    if (count == 0) {
        free(files);
        printf("[]\n");
        return;
    }

    /* Sort by path for consistent output */
    qsort(files, count, sizeof(FileInfo), path_cmp);

    /* Output JSON */
    printf("[\n");
    for (size_t i = 0; i < count; i++) {
        char mode_str[7];
        snprintf(mode_str, sizeof(mode_str), "%04o", files[i].mode);

        /* Escape quotes/backslashes in path for JSON */
        printf("  {\"path\":\"");
        for (char *p = files[i].path; *p; p++) {
            if (*p == '"' || *p == '\\') putchar('\\');
            putchar(*p);
        }
        printf("\",\"size\":%lld,\"mode\":\"%s\",\"uid\":%u,\"gid\":%u,\"mtime\":%ld}",
               (long long)files[i].size, mode_str,
               files[i].uid, files[i].gid, (long)files[i].mtime);

        if (i < count - 1) printf(",");
        printf("\n");
    }
    printf("]\n");

    free(files);
}

int main(void)
{
    scan_critical_files();
    return 0;
}
