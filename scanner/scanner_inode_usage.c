#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mntent.h>     /* for getmntent */
#include <sys/statvfs.h> /* for statvfs */

/* Tagged struct so 'struct InodeUsage' is defined before use in mount_cmp */
typedef struct InodeUsage {
    char mount_point[256]; /* mount point path */
    unsigned long long total_inodes; /* total inodes */
    unsigned long long used_inodes;  /* used inodes */
    unsigned long long free_inodes;  /* free inodes */
    double inode_percent;            /* used inodes / total * 100 */
} InodeUsage;

/* Comparator for qsort by mount point */
static int mount_cmp(const void *a, const void *b) {
    return strcmp(((const struct InodeUsage *)a)->mount_point,
                  ((const struct InodeUsage *)b)->mount_point);
}

/*
   Scanner: Inode usage per mount
   Iterates /etc/mtab (via getmntent) for mounts, then statvfs for inode stats.
   Includes percentages (0 if total==0 to avoid div0).
   Output: JSON array of objects → replace with DB insert loop
   Note: Run as root for accurate stats on all mounts.
*/
void scan_inode_usage_per_mount(void)
{
    FILE *mtab = setmntent("/etc/mtab", "r");
    if (!mtab) {
        perror("setmntent /etc/mtab");
        printf("[]\n");
        return;
    }

    InodeUsage *usages = NULL;
    size_t capacity = 0;
    size_t count = 0;

    struct mntent *ent;
    while ((ent = getmntent(mtab))) {
        /* Skip pseudo-filesystems without inodes (proc, sysfs, etc.) */
        struct statvfs st;
        if (statvfs(ent->mnt_dir, &st) < 0) continue;

        if (st.f_files == 0) continue;  /* no real inodes */

        /* Grow array */
        if (count >= capacity) {
            capacity = capacity ? capacity * 2 : 512;
            InodeUsage *new_usages = realloc(usages, capacity * sizeof(InodeUsage));
            if (!new_usages) continue;
            usages = new_usages;
        }

        strncpy(usages[count].mount_point, ent->mnt_dir, sizeof(usages[count].mount_point) - 1);
        usages[count].mount_point[sizeof(usages[count].mount_point) - 1] = '\0';

        usages[count].total_inodes = st.f_files;
        usages[count].free_inodes  = st.f_ffree;
        usages[count].used_inodes  = usages[count].total_inodes - usages[count].free_inodes;

        usages[count].inode_percent = usages[count].total_inodes > 0 ?
                                      (double)usages[count].used_inodes / usages[count].total_inodes * 100.0 : 0.0;

        count++;
    }

    endmntent(mtab);

    if (count == 0) {
        free(usages);
        printf("[]\n");
        return;
    }

    /* Sort by mount_point */
    qsort(usages, count, sizeof(InodeUsage), mount_cmp);

    /* === OUTPUT – replace this block with your database insert === */
    printf("[\n");
    for (size_t i = 0; i < count; i++) {
        printf("  {\"mount_point\":\"%s\","
               "\"total_inodes\":%llu,\"used_inodes\":%llu,\"free_inodes\":%llu,\"inode_percent\":%.2f}",
               usages[i].mount_point,
               usages[i].total_inodes, usages[i].used_inodes, usages[i].free_inodes, usages[i].inode_percent);

        if (i < count - 1) printf(",");
        printf("\n");
    }
    printf("]\n");

    /* Example DB-style replacement:
    for (size_t i = 0; i < count; i++) {
        db_insert_inode_usage(usages[i].mount_point,
                              usages[i].total_inodes, usages[i].used_inodes, usages[i].free_inodes,
                              usages[i].inode_percent);
    }
    */

    free(usages);
}

int main(void)
{
    scan_inode_usage_per_mount();
    return 0;
}
