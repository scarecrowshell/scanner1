#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>

/* Tagged struct so 'struct FileInfo' is defined before use in path_cmp */
typedef struct FileInfo {
    char path[PATH_MAX];
    off_t size;
    mode_t mode;        /* permissions (octal) */
    uid_t uid;
    gid_t gid;
    time_t mtime;
    time_t ctime;       /* key for "created since last scan" */
    time_t atime;
    char type[32];
} FileInfo;

/* Comparator for qsort by path (alphabetical) */
static int path_cmp(const void *a, const void *b) {
    return strcmp(((const struct FileInfo *)a)->path,
                  ((const struct FileInfo *)b)->path);
}

/* Human-readable file type */
static const char *get_file_type(mode_t mode) {
    if (S_ISREG(mode))  return "regular";
    if (S_ISDIR(mode))  return "directory";
    if (S_ISLNK(mode))  return "symlink";
    if (S_ISFIFO(mode)) return "fifo";
    if (S_ISCHR(mode))  return "character device";
    if (S_ISBLK(mode))  return "block device";
    if (S_ISSOCK(mode)) return "socket";
    return "unknown";
}

/* Recursive scan – only ADD files/dirs whose ctime > last_scan_time */
static void scan_dir(const char *dir, time_t last_scan_time,
                     FileInfo **files, size_t *count, size_t *capacity) {
    DIR *d = opendir(dir);
    if (!d) {
        /* Silent for permission issues on some subdirs */
        return;
    }

    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;

        char full[PATH_MAX];
        /* build path safely and detect truncation */
        int needed = snprintf(full, sizeof(full), "%s/%s", dir, e->d_name);
        if (needed < 0 || needed >= (int)sizeof(full)) {
            /* Path too long – skip */
            continue;
        }

        struct stat st;
        if (lstat(full, &st) < 0) continue;

        /* Only collect if this entry was created/changed since last scan */
        if (st.st_ctime > last_scan_time) {
            if (*count >= *capacity) {
                *capacity = *capacity ? *capacity * 2 : 16384;  /* bigger default for safety */
                FileInfo *new_files = realloc(*files, *capacity * sizeof(FileInfo));
                if (!new_files) {
                    closedir(d);
                    return;
                }
                *files = new_files;
            }

            /* Use snprintf to copy to fixed-size buffer (avoids strncpy truncation warnings) */
            FileInfo *fi = &(*files)[*count];
            (void)snprintf(fi->path, sizeof(fi->path), "%s", full);

            fi->size  = st.st_size;
            fi->mode  = st.st_mode & 07777;
            fi->uid   = st.st_uid;
            fi->gid   = st.st_gid;
            fi->mtime = st.st_mtime;
            fi->ctime = st.st_ctime;
            fi->atime = st.st_atime;

            strncpy(fi->type, get_file_type(st.st_mode),
                    sizeof(fi->type) - 1);
            fi->type[sizeof(fi->type) - 1] = '\0';

            (*count)++;
        }

        /* Always recurse into directories (even old ones – new files may be inside) */
        if (S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) {
            scan_dir(full, last_scan_time, files, count, capacity);
        }
    }

    closedir(d);
}

/*
   Scanner: New files created since last scan
   Scans the same critical directories as your earlier scanner.
   Uses st_ctime (inode change time) > last_scan_time to detect newly created files/directories.
   (Modified files also appear because modification updates ctime.)

   Usage:
     ./scanner_new_files               → first run (reports everything)
     ./scanner_new_files 1739999999    → only files with ctime > that Unix timestamp

   After DB insert, update your last scan time with:
     date +%s > last_scan.time
*/
void scan_new_files(time_t last_scan_time)
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
        scan_dir(dirs[i], last_scan_time, &files, &count, &capacity);
    }

    if (count == 0) {
        free(files);
        printf("[]\n");
        printf("# No new files since last scan (ctime > %ld)\n", last_scan_time);
        return;
    }

    /* Sort by path */
    qsort(files, count, sizeof(FileInfo), path_cmp);

    /* === OUTPUT – replace this block with your DB insert === */
    printf("[\n");
    for (size_t i = 0; i < count; i++) {
        char mode_str[5];
        snprintf(mode_str, sizeof(mode_str), "%04o", files[i].mode);

        printf("  {\"path\":\"");
        for (char *p = files[i].path; *p; p++) {
            if (*p == '"' || *p == '\\') putchar('\\');
            putchar(*p);
        }
        printf("\",\"size\":%lld,\"mode\":\"%s\",\"uid\":%u,\"gid\":%u,"
               "\"mtime\":%ld,\"ctime\":%ld,\"atime\":%ld,\"type\":\"%s\"}",
               (long long)files[i].size, mode_str,
               files[i].uid, files[i].gid,
               files[i].mtime, files[i].ctime, files[i].atime,
               files[i].type);

        if (i < count - 1) printf(",");
        printf("\n");
    }
    printf("]\n");

    /* Helpful info for next run */
    time_t now = time(NULL);
    printf("\n# Next last_scan_time for the next run: %ld\n", now);
    printf("# Save it with: date +%%s > last_scan.time\n");

    free(files);
}

int main(int argc, char **argv)
{
    time_t last_scan_time = 0;
    if (argc > 1) {
        last_scan_time = (time_t)strtol(argv[1], NULL, 10);
    }

    printf("# New files since last scan (ctime > %ld)\n", last_scan_time);
    scan_new_files(last_scan_time);
    return 0;
}
