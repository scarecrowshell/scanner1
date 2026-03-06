#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mntent.h>     /* for getmntent */
#include <sys/statvfs.h> /* for statvfs */

/* Tagged struct so 'struct DiskUsage' is defined before use in mount_cmp */
typedef struct DiskUsage {
    char mount_point[256]; /* mount point path */
    unsigned long long total_bytes; /* total size */
    unsigned long long used_bytes;  /* used size */
    unsigned long long free_bytes;  /* free size */
    double usage_percent;           /* used / total * 100 */
    unsigned long long total_inodes; /* total inodes */
    unsigned long long used_inodes;  /* used inodes */
    unsigned long long free_inodes;  /* free inodes */
    double inode_percent;            /* used inodes / total * 100 */
} DiskUsage;

/* Comparator for qsort by mount point */
static int mount_cmp(const void *a, const void *b) {
    return strcmp(((const struct DiskUsage *)a)->mount_point,
                  ((const struct DiskUsage *)b)->mount_point);
}

/*
   Scanner: Disk usage per mount
   Iterates /etc/mtab (via getmntent) for mounts, then statvfs for usage stats.
   Includes bytes and inodes + percentages (0 if total==0 to avoid div0).
   Output: JSON array of objects → replace with DB insert loop
   Note: Run as root for accurate stats on all mounts.
*/
void scan_disk_usage_per_mount(void)
{
    FILE *mtab = setmntent("/etc/mtab", "r");
    if (!mtab) {
        perror("setmntent /etc/mtab");
        printf("[]\n");
        return;
    }

    DiskUsage *usages = NULL;
    size_t capacity = 0;
    size_t count = 0;

    struct mntent *ent;
    while ((ent = getmntent(mtab))) {
        /* Skip pseudo-filesystems without disk usage (proc, sysfs, etc.) */
        struct statvfs st;
        if (statvfs(ent->mnt_dir, &st) < 0) continue;

        if (st.f_blocks == 0) continue;  /* no real storage */

        /* Grow array */
        if (count >= capacity) {
            capacity = capacity ? capacity * 2 : 512;
            DiskUsage *new_usages = realloc(usages, capacity * sizeof(DiskUsage));
            if (!new_usages) continue;
            usages = new_usages;
        }

        /* copy mount point safely */
        strncpy(usages[count].mount_point, ent->mnt_dir, sizeof(usages[count].mount_point) - 1);
        usages[count].mount_point[sizeof(usages[count].mount_point) - 1] = '\0';

        unsigned long long block_size = st.f_frsize ? st.f_frsize : st.f_bsize;
        usages[count].total_bytes = st.f_blocks * block_size;
        usages[count].free_bytes  = st.f_bfree * block_size;
        usages[count].used_bytes  = usages[count].total_bytes - usages[count].free_bytes;

        usages[count].usage_percent = usages[count].total_bytes > 0 ?
                                      (double)usages[count].used_bytes / usages[count].total_bytes * 100.0 : 0.0;

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
    qsort(usages, count, sizeof(DiskUsage), mount_cmp);

    /* === OUTPUT – replace this block with your database insert === */
    printf("[\n");
    for (size_t i = 0; i < count; i++) {
        printf("  {\"mount_point\":\"%s\","
               "\"total_bytes\":%llu,\"used_bytes\":%llu,\"free_bytes\":%llu,\"usage_percent\":%.2f,"
               "\"total_inodes\":%llu,\"used_inodes\":%llu,\"free_inodes\":%llu,\"inode_percent\":%.2f}",
               usages[i].mount_point,
               usages[i].total_bytes, usages[i].used_bytes, usages[i].free_bytes, usages[i].usage_percent,
               usages[i].total_inodes, usages[i].used_inodes, usages[i].free_inodes, usages[i].inode_percent);

        if (i < count - 1) printf(",");
        printf("\n");
    }
    printf("]\n");

    free(usages);
}

int main(void)
{
    scan_disk_usage_per_mount();
    return 0;
}
