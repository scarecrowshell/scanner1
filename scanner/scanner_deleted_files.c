#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <stdbool.h>

/* Tagged struct so 'struct PathEntry' is defined before use in comparators */
typedef struct PathEntry {
    char path[PATH_MAX];
} PathEntry;

/* Comparator for qsort on PathEntry.path */
static int path_cmp(const void *a, const void *b) {
    return strcmp(((const struct PathEntry *)a)->path,
                  ((const struct PathEntry *)b)->path);
}

/* Comparator for qsort on char** (string pointers) */
static int str_cmp(const void *a, const void *b) {
    return strcmp(*(const char **)a, *(const char **)b);
}

/* Recursive scan – collect EVERY entry (files, dirs, symlinks, etc.) */
static void scan_dir(const char *dir, PathEntry **paths, size_t *count, size_t *capacity) {
    DIR *d = opendir(dir);
    if (!d) return;   /* silent on permission errors (common in /root, /var etc.) */

    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;

        char full[PATH_MAX];
        int needed = snprintf(full, sizeof(full), "%s/%s", dir, e->d_name);
        if (needed < 0 || needed >= (int)sizeof(full)) {
            /* path too long — skip it */
            continue;
        }

        struct stat st;
        if (lstat(full, &st) < 0) continue;

        /* Grow array */
        if (*count >= *capacity) {
            *capacity = *capacity ? *capacity * 2 : 32768;
            PathEntry *new_paths = realloc(*paths, *capacity * sizeof(PathEntry));
            if (!new_paths) {
                closedir(d);
                return;
            }
            *paths = new_paths;
        }

        /* Use snprintf to copy into fixed-size buffer (avoids strncpy truncation warning) */
        (void)snprintf((*paths)[*count].path, sizeof((*paths)[*count].path), "%s", full);
        (*paths)[*count].path[PATH_MAX - 1] = '\0';
        (*count)++;

        /* Recurse into real directories */
        if (S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) {
            scan_dir(full, paths, count, capacity);
        }
    }
    closedir(d);
}

/* Scan all critical directories */
static void scan_critical_paths(PathEntry **paths, size_t *count, size_t *capacity) {
    const char *dirs[] = {
        "/etc", "/bin", "/sbin", "/usr/bin", "/lib",
        "/var", "/tmp", "/home", "/root",
        NULL
    };

    for (int i = 0; dirs[i]; i++) {
        scan_dir(dirs[i], paths, count, capacity);
    }
}

/* Load previous snapshot (one absolute path per line) */
static char **load_snapshot(const char *filename, size_t *out_count) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        fprintf(stderr, "Error: cannot open previous snapshot '%s'\n", filename);
        return NULL;
    }

    char **arr = NULL;
    size_t capacity = 0;
    size_t count = 0;
    char line[PATH_MAX];

    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') line[len-1] = '\0';
        if (len <= 1) continue;   /* skip empty lines */

        if (count >= capacity) {
            capacity = capacity ? capacity * 2 : 32768;
            char **new_arr = realloc(arr, capacity * sizeof(char *));
            if (!new_arr) {
                fclose(f);
                for (size_t i = 0; i < count; i++) free(arr[i]);
                free(arr);
                return NULL;
            }
            arr = new_arr;
        }

        arr[count] = strdup(line);
        if (arr[count]) count++;
    }
    fclose(f);

    *out_count = count;
    return arr;
}

int main(int argc, char **argv)
{
    bool generate_snapshot = false;
    const char *prev_file = NULL;

    if (argc == 2 && strcmp(argv[1], "--snapshot") == 0) {
        generate_snapshot = true;
    } else if (argc == 2) {
        prev_file = argv[1];
    } else {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s --snapshot                  # Generate current snapshot (one path per line)\n", argv[0]);
        fprintf(stderr, "  %s <previous_snapshot.txt>     # Detect deleted files → JSON output\n", argv[0]);
        fprintf(stderr, "\nExample workflow:\n");
        fprintf(stderr, "  sudo %s --snapshot > snapshot.txt\n", argv[0]);
        fprintf(stderr, "  ... (time passes) ...\n");
        fprintf(stderr, "  sudo %s snapshot.txt\n\n", argv[0]);
        return 1;
    }

    /* === Scan current state of critical directories === */
    PathEntry *current = NULL;
    size_t curr_count = 0;
    size_t curr_capacity = 0;

    scan_critical_paths(&current, &curr_count, &curr_capacity);

    if (curr_count == 0) {
        free(current);
        printf("[]\n");
        if (generate_snapshot) {
            printf("# No files found in critical directories (very unusual)\n");
        } else {
            printf("# No current files – nothing to compare\n");
        }
        return 0;
    }

    /* Sort current paths for fast lookup */
    qsort(current, curr_count, sizeof(PathEntry), path_cmp);

    if (generate_snapshot) {
        /* Output one path per line – ready to be saved as snapshot */
        for (size_t i = 0; i < curr_count; i++) {
            printf("%s\n", current[i].path);
        }
        free(current);
        return 0;
    }

    /* === DELETED MODE === */
    size_t prev_count = 0;
    char **prev_paths = load_snapshot(prev_file, &prev_count);
    if (!prev_paths) {
        free(current);
        return 1;
    }

    /* Sort previous snapshot */
    qsort(prev_paths, prev_count, sizeof(char *), str_cmp);

    /* Find deleted paths: in prev but NOT in current */
    char **deleted = NULL;
    size_t del_count = 0;
    size_t del_capacity = 0;

    size_t i = 0, j = 0;
    while (i < prev_count && j < curr_count) {
        int cmp = strcmp(prev_paths[i], current[j].path);

        if (cmp < 0) {
            /* previous path missing in current → deleted */
            if (del_count >= del_capacity) {
                del_capacity = del_capacity ? del_capacity * 2 : 8192;
                char **new_del = realloc(deleted, del_capacity * sizeof(char *));
                if (!new_del) break;
                deleted = new_del;
            }
            deleted[del_count++] = strdup(prev_paths[i]);
            i++;
        } else if (cmp > 0) {
            j++;   /* current has extra (new) – ignore here */
        } else {
            i++; j++;   /* match → still exists */
        }
    }

    /* Remaining previous paths are all deleted */
    while (i < prev_count) {
        if (del_count >= del_capacity) {
            del_capacity = del_capacity ? del_capacity * 2 : 8192;
            char **new_del = realloc(deleted, del_capacity * sizeof(char *));
            if (!new_del) break;
            deleted = new_del;
        }
        deleted[del_count++] = strdup(prev_paths[i]);
        i++;
    }

    /* === OUTPUT JSON === */
    printf("[\n");
    for (size_t k = 0; k < del_count; k++) {
        printf("  {\"path\":\"");
        for (char *p = deleted[k]; *p; p++) {
            if (*p == '"' || *p == '\\') putchar('\\');
            putchar(*p);
        }
        printf("\"}");
        if (k < del_count - 1) printf(",");
        printf("\n");
    }
    printf("]\n");

    /* Cleanup */
    for (size_t k = 0; k < del_count; k++) free(deleted[k]);
    free(deleted);

    for (size_t k = 0; k < prev_count; k++) free(prev_paths[k]);
    free(prev_paths);

    free(current);

    /* Helpful message */
    printf("\n# %zu files/directories deleted since last snapshot.\n", del_count);
    printf("# To create updated snapshot for next scan:\n");
    printf("#   sudo %s --snapshot > new_snapshot.txt\n", argv[0]);
    printf("#   mv new_snapshot.txt %s\n", prev_file);

    return 0;
}
