// scanner_file_hashes.c (EVP-based SHA-256, avoids deprecated APIs)
#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <openssl/evp.h>

typedef struct {
    char path[PATH_MAX];
    char sha256[EVP_MAX_MD_SIZE * 2 + 1];  /* hex string + null */
} FileHash;

/* Comparator for qsort by path (alphabetical) */
static int path_cmp(const void *a, const void *b) {
    return strcmp(((const FileHash *)a)->path,
                  ((const FileHash *)b)->path);
}

/* Compute SHA-256 hex digest of a file using EVP (modern OpenSSL) */
static int compute_sha256(const char *path, char *digest) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) { fclose(fp); return -1; }

    const EVP_MD *md = EVP_sha256();
    if (!md) { EVP_MD_CTX_free(mdctx); fclose(fp); return -1; }

    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        fclose(fp);
        return -1;
    }

    unsigned char buffer[8192];
    size_t len;
    while ((len = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, len) != 1) {
            EVP_MD_CTX_free(mdctx);
            fclose(fp);
            return -1;
        }
    }

    if (ferror(fp)) {
        EVP_MD_CTX_free(mdctx);
        fclose(fp);
        return -1;
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        fclose(fp);
        return -1;
    }

    EVP_MD_CTX_free(mdctx);
    fclose(fp);

    for (unsigned int i = 0; i < hash_len; ++i) {
        sprintf(digest + i * 2, "%02x", hash[i]);
    }
    digest[hash_len * 2] = '\0';
    return 0;
}

/* Recursive scanner function – only hash regular files */
static void scan_dir(const char *dir, FileHash **hashes, size_t *count, size_t *capacity) {
    DIR *d = opendir(dir);
    if (!d) {
        /* cannot open directory – skip silently */
        return;
    }

    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;

        char full[PATH_MAX];
        int rc = snprintf(full, sizeof(full), "%s/%s", dir, e->d_name);
        if (rc < 0) continue;

        struct stat st;
        if (lstat(full, &st) < 0) continue;

        /* If regular file, compute hash */
        if (S_ISREG(st.st_mode)) {
            /* Grow array if needed */
            if (*count >= *capacity) {
                *capacity = *capacity ? *capacity * 2 : 8192;
                FileHash *new_hashes = realloc(*hashes, *capacity * sizeof(FileHash));
                if (!new_hashes) {
                    closedir(d);
                    return;
                }
                *hashes = new_hashes;
            }

            /* safe copy of path */
            size_t plen = strlen(full);
            if (plen >= sizeof((*hashes)[*count].path)) plen = sizeof((*hashes)[*count].path) - 1;
            memcpy((*hashes)[*count].path, full, plen);
            (*hashes)[*count].path[plen] = '\0';

            if (compute_sha256(full, (*hashes)[*count].sha256) == 0) {
                (*count)++;
            } else {
                /* failed to read/hash — skip this file */
            }
        }

        /* Recurse if directory (not symlink) */
        if (S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) {
            scan_dir(full, hashes, count, capacity);
        }
    }

    closedir(d);
}

/*
   Scanner: SHA-256 hash of files for integrity checking
   Recursively scans a directory (default: current, or from argv[1])
   Only computes for regular files (skips dirs, symlinks, devices, etc.)
   Uses OpenSSL EVP API (modern, not deprecated).
*/
void scan_file_hashes(const char *start_dir)
{
    FileHash *hashes = NULL;
    size_t capacity = 0;
    size_t count = 0;

    scan_dir(start_dir, &hashes, &count, &capacity);

    if (count == 0) {
        free(hashes);
        printf("[]\n");
        return;
    }

    /* Sort by path for consistent output */
    qsort(hashes, count, sizeof(FileHash), path_cmp);

    /* Output JSON */
    printf("[\n");
    for (size_t i = 0; i < count; i++) {
        /* Escape quotes/backslashes in path for JSON */
        printf("  {\"path\":\"");
        for (char *p = hashes[i].path; *p; p++) {
            if (*p == '"' || *p == '\\') putchar('\\');
            putchar(*p);
        }
        printf("\",\"sha256\":\"%s\"}", hashes[i].sha256);

        if (i < count - 1) printf(",");
        printf("\n");
    }
    printf("]\n");

    free(hashes);
}

int main(int argc, char **argv)
{
    const char *dir = (argc > 1) ? argv[1] : ".";
    scan_file_hashes(dir);
    return 0;
}
