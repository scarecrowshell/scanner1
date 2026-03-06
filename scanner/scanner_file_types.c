// scanner_file_types.c
#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>

/* FileInfo must be defined before comparator */
typedef struct {
    char path[PATH_MAX];
    char type[32];      /* "regular", "directory", "symlink", ... */
} FileInfo;

/* Comparator for qsort by path (alphabetical) */
static int path_cmp(const void *a, const void *b) {
    return strcmp(((const FileInfo *)a)->path,
                  ((const FileInfo *)b)->path);
}

/* Get human-readable file type from mode */
static const char *get_file_type(mode_t mode) {
    if (S_ISREG(mode)) return "regular";
    if (S_ISDIR(mode)) return "directory";
    if (S_ISLNK(mode)) return "symlink";
    if (S_ISFIFO(mode)) return "fifo";
    if (S_ISCHR(mode)) return "character device";
    if (S_ISBLK(mode)) return "block device";
    if (S_ISSOCK(mode)) return "socket";
    return "unknown";
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
        int rc = snprintf(full, sizeof(full), "%s/%s", dir, e->d_name);
        if (rc < 0) continue;

        struct stat st;
        if (lstat(full, &st) < 0) continue;  /* skip on error (e.g., permission) */

        /* Grow array if needed */
        if (*count >= *capacity) {
            *capacity = *capacity ? *capacity * 2 : 8192;
            FileInfo *new_files = realloc(*files, *capacity * sizeof(FileInfo));
            if (!new_files) {
                closedir(d);
                return;  /* alloc fail – stop */
            }
            *files = new_files;
        }

        /* safe copy of path */
        size_t plen = strlen(full);
        if (plen >= sizeof((*files)[*count].path)) plen = sizeof((*files)[*count].path) - 1;
        memcpy((*files)[*count].path, full, plen);
        (*files)[*count].path[plen] = '\0';

        /* safe copy of type */
        const char *t = get_file_type(st.st_mode);
        snprintf((*files)[*count].type, sizeof((*files)[*count].type), "%s", t);

        (*count)++;

        /* Recurse if directory (but not symlink to dir) */
        if (S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) {
            scan_dir(full, files, count, capacity);
        }
    }

    closedir(d);
}

/*
   Scanner: File type (regular, directory, symlink, device, etc.)
   Recursively scans a directory (default: current, or from argv[1])
*/
void scan_file_types(const char *start_dir)
{
    FileInfo *files = NULL;
    size_t capacity = 0;
    size_t count = 0;

    scan_dir(start_dir, &files, &count, &capacity);

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
        /* Escape quotes/backslashes in path for JSON */
        printf("  {\"path\":\"");
        for (char *p = files[i].path; *p; p++) {
            if (*p == '"' || *p == '\\') putchar('\\');
            putchar(*p);
        }
        printf("\",\"type\":\"%s\"}", files[i].type);

        if (i < count - 1) printf(",");
        printf("\n");
    }
    printf("]\n");

    free(files);
}

int main(int argc, char **argv)
{
    const char *dir = (argc > 1) ? argv[1] : ".";
    scan_file_types(dir);
    return 0;
}
