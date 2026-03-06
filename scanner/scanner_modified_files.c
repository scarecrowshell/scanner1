#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>
#include <stdbool.h>
#include <openssl/evp.h>   /* use EVP API */
#include <openssl/sha.h>   /* for digest length constant */

/* Tagged struct so 'struct SnapshotEntry' exists for path_cmp */
typedef struct SnapshotEntry {
    char     path[PATH_MAX];
    long long size;
    time_t   mtime;
    time_t   ctime;
    time_t   atime;        /* collected but ignored for "modified" detection */
    mode_t   mode;         /* permissions */
    uid_t    uid;
    gid_t    gid;
    char     sha256[65];   /* hex or empty string for non-regular files */
    char     type[32];
} SnapshotEntry;

/* Comparator for qsort by path */
static int path_cmp(const void *a, const void *b) {
    return strcmp(((const SnapshotEntry *)a)->path,
                  ((const SnapshotEntry *)b)->path);
}

/* Compute SHA-256 only for regular files using EVP (non-deprecated) */
static void compute_sha256(const char *path, char *digest) {
    digest[0] = '\0';
    FILE *fp = fopen(path, "rb");
    if (!fp) return;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) { fclose(fp); return; }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        fclose(fp);
        return;
    }

    unsigned char buf[8192];
    size_t len;
    while ((len = fread(buf, 1, sizeof(buf), fp)) > 0) {
        if (EVP_DigestUpdate(mdctx, buf, len) != 1) {
            EVP_MD_CTX_free(mdctx);
            fclose(fp);
            return;
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashlen = 0;
    if (EVP_DigestFinal_ex(mdctx, hash, &hashlen) != 1) {
        EVP_MD_CTX_free(mdctx);
        fclose(fp);
        return;
    }

    EVP_MD_CTX_free(mdctx);
    fclose(fp);

    /* Convert to hex (only first SHA256_DIGEST_LENGTH bytes) */
    for (unsigned int i = 0; i < hashlen && i < SHA256_DIGEST_LENGTH; ++i) {
        sprintf(digest + i * 2, "%02x", hash[i]);
    }
    digest[64] = '\0';
}

/* Human-readable type */
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

/* Recursive scan – collect metadata + hash (regular files only) */
static void scan_dir(const char *dir, SnapshotEntry **entries, size_t *count, size_t *capacity) {
    DIR *d = opendir(dir);
    if (!d) return;   /* silent on permission errors */

    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;

        char full[PATH_MAX];
        int needed = snprintf(full, sizeof(full), "%s/%s", dir, e->d_name);
        if (needed < 0 || needed >= (int)sizeof(full)) continue;

        struct stat st;
        if (lstat(full, &st) < 0) continue;

        if (*count >= *capacity) {
            *capacity = *capacity ? *capacity * 2 : 32768;
            SnapshotEntry *new_e = realloc(*entries, *capacity * sizeof(SnapshotEntry));
            if (!new_e) {
                closedir(d);
                return;
            }
            *entries = new_e;
        }

        SnapshotEntry *ent = &(*entries)[*count];
        (void)snprintf(ent->path, sizeof(ent->path), "%s", full);

        ent->size  = st.st_size;
        ent->mtime = st.st_mtime;
        ent->ctime = st.st_ctime;
        ent->atime = st.st_atime;
        ent->mode  = st.st_mode & 07777;
        ent->uid   = st.st_uid;
        ent->gid   = st.st_gid;
        (void)snprintf(ent->type, sizeof(ent->type), "%s", get_file_type(st.st_mode));

        if (S_ISREG(st.st_mode)) {
            compute_sha256(full, ent->sha256);
        } else {
            ent->sha256[0] = '\0';
        }

        (*count)++;

        /* Recurse only real directories */
        if (S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) {
            scan_dir(full, entries, count, capacity);
        }
    }
    closedir(d);
}

/* Print one line for --snapshot mode */
static void print_snapshot_line(const SnapshotEntry *e) {
    char mode_str[6];
    snprintf(mode_str, sizeof(mode_str), "%04o", e->mode);
    printf("%s|%lld|%ld|%ld|%ld|%s|%u|%u|%s|%s\n",
           e->path, e->size, (long)e->mtime, (long)e->ctime, (long)e->atime,
           mode_str, (unsigned)e->uid, (unsigned)e->gid, e->sha256, e->type);
}

/* Load previous snapshot */
static int load_snapshot(const char *filename, SnapshotEntry **entries, size_t *count) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        fprintf(stderr, "Cannot open snapshot '%s'\n", filename);
        return -1;
    }

    size_t capacity = 0;
    *count = 0;
    char line[PATH_MAX + 512];

    while (fgets(line, sizeof(line), f)) {
        if (*count >= capacity) {
            capacity = capacity ? capacity * 2 : 32768;
            SnapshotEntry *new_e = realloc(*entries, capacity * sizeof(SnapshotEntry));
            if (!new_e) {
                fclose(f);
                return -1;
            }
            *entries = new_e;
        }

        SnapshotEntry *ent = &(*entries)[*count];
        char mode_str[16];

        if (sscanf(line, "%[^|]|%lld|%ld|%ld|%ld|%15[^|]|%u|%u|%64s|%31[^\n]",
                   ent->path, &ent->size, (long *)&ent->mtime, (long *)&ent->ctime, (long *)&ent->atime,
                   mode_str, &ent->uid, &ent->gid, ent->sha256, ent->type) == 10) {
            ent->mode = (mode_t)strtol(mode_str, NULL, 8);
            (*count)++;
        }
    }
    fclose(f);
    return 0;
}

/* Check if file was modified (content or metadata) */
static bool is_modified(const SnapshotEntry *old, const SnapshotEntry *cur) {
    if (old->size != cur->size) return true;
    if (old->mtime != cur->mtime) return true;
    if (old->ctime != cur->ctime) return true;
    if (old->mode != cur->mode) return true;
    if (old->uid != cur->uid) return true;
    if (old->gid != cur->gid) return true;
    if (strcmp(old->type, cur->type) != 0) return true;

    /* Hash comparison only when both are regular files */
    if (old->sha256[0] && cur->sha256[0]) {
        if (strcmp(old->sha256, cur->sha256) != 0) return true;
    } else if (old->sha256[0] || cur->sha256[0]) {
        return true;   /* one became regular or vice-versa */
    }
    return false;
}

/* Print one JSON object (same format as newfiles_scanner) */
static void print_json_object(const SnapshotEntry *e) {
    char mode_str[6];
    snprintf(mode_str, sizeof(mode_str), "%04o", e->mode);

    printf("  {\"path\":\"");
    for (const char *p = e->path; *p; ++p) {
        if (*p == '"' || *p == '\\') putchar('\\');
        putchar(*p);
    }
    printf("\",\"size\":%lld,\"mode\":\"%s\",\"uid\":%u,\"gid\":%u,"
           "\"mtime\":%ld,\"ctime\":%ld,\"atime\":%ld,\"type\":\"%s\",\"sha256\":\"%s\"}",
           e->size, mode_str, (unsigned)e->uid, (unsigned)e->gid,
           (long)e->mtime, (long)e->ctime, (long)e->atime, e->type, e->sha256);
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
        fprintf(stderr, "  %s --snapshot                  # Generate baseline snapshot (one line per file)\n", argv[0]);
        fprintf(stderr, "  %s <previous_snapshot.txt>     # Detect modified files → JSON\n", argv[0]);
        fprintf(stderr, "\nWorkflow:\n");
        fprintf(stderr, "  sudo %s --snapshot > snapshot.txt\n", argv[0]);
        fprintf(stderr, "  ... time passes ...\n");
        fprintf(stderr, "  sudo %s snapshot.txt\n\n", argv[0]);
        return 1;
    }

    const char *dirs[] = {
        "/etc", "/bin", "/sbin", "/usr/bin", "/lib",
        "/var", "/tmp", "/home", "/root", NULL
    };

    SnapshotEntry *current = NULL;
    size_t curr_count = 0;
    size_t curr_capacity = 0;

    for (int i = 0; dirs[i]; i++) {
        scan_dir(dirs[i], &current, &curr_count, &curr_capacity);
    }

    if (curr_count == 0) {
        free(current);
        printf("[]\n");
        return 0;
    }

    qsort(current, curr_count, sizeof(SnapshotEntry), path_cmp);

    if (generate_snapshot) {
        for (size_t i = 0; i < curr_count; i++) {
            print_snapshot_line(&current[i]);
        }
        free(current);
        return 0;
    }

    /* === MODIFIED DETECTION MODE === */
    SnapshotEntry *prev = NULL;
    size_t prev_count = 0;
    if (load_snapshot(prev_file, &prev, &prev_count) < 0) {
        free(current);
        return 1;
    }
    qsort(prev, prev_count, sizeof(SnapshotEntry), path_cmp);

    printf("[\n");
    size_t modified_count = 0;
    size_t i = 0, j = 0;
    while (i < prev_count && j < curr_count) {
        int cmp = strcmp(prev[i].path, current[j].path);

        if (cmp < 0) {
            i++;   /* deleted - ignore here */
        } else if (cmp > 0) {
            j++;   /* new - ignore here */
        } else {
            /* same path - check for modification */
            if (is_modified(&prev[i], &current[j])) {
                if (modified_count > 0) printf(",\n");
                print_json_object(&current[j]);
                modified_count++;
            }
            i++;
            j++;
        }
    }
    printf("\n]\n");

    printf("# %zu files modified (content or metadata) since last snapshot.\n", modified_count);
    printf("# To update snapshot for next run:\n");
    printf("#   sudo %s --snapshot > new_snapshot.txt\n", argv[0]);
    printf("#   mv new_snapshot.txt %s\n", prev_file);

    free(prev);
    free(current);
    return 0;
}
