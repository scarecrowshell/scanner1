#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Tagged struct so 'struct MountInfo' is defined before use in mount_cmp */
typedef struct MountInfo {
    char device[256];      /* device or filesystem name */
    char mount_point[256]; /* mount point path */
    char fs_type[64];      /* filesystem type (ext4, tmpfs, etc.) */
    char options[512];     /* mount options (rw,relatime,...) */
} MountInfo;

/* Comparator for qsort by mount point */
static int mount_cmp(const void *a, const void *b) {
    return strcmp(((const struct MountInfo *)a)->mount_point,
                  ((const struct MountInfo *)b)->mount_point);
}

/*
   Scanner: Mounted filesystems (mount points, type, options)
   Parses /proc/mounts (most reliable source on Linux)
   Output: JSON array of objects → replace with DB insert loop
   Note: Run as root for full visibility if needed, but usually readable by all.
*/
void scan_mounted_filesystems(void)
{
    FILE *fp = fopen("/proc/mounts", "re");
    if (!fp) {
        perror("fopen /proc/mounts");
        printf("[]\n");
        return;
    }

    MountInfo *mounts = NULL;
    size_t capacity = 0;
    size_t count = 0;

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        /* Format: device mount_point fs_type options dump pass */
        char device[256], mount_point[256], fs_type[64], options[512];
        if (sscanf(line, "%255s %255s %63s %511s %*d %*d",
                   device, mount_point, fs_type, options) != 4) {
            continue;
        }

        /* Grow array */
        if (count >= capacity) {
            capacity = capacity ? capacity * 2 : 512;
            MountInfo *new_mounts = realloc(mounts, capacity * sizeof(MountInfo));
            if (!new_mounts) continue;
            mounts = new_mounts;
        }

        strncpy(mounts[count].device, device, sizeof(mounts[count].device) - 1);
        mounts[count].device[sizeof(mounts[count].device) - 1] = '\0';

        strncpy(mounts[count].mount_point, mount_point, sizeof(mounts[count].mount_point) - 1);
        mounts[count].mount_point[sizeof(mounts[count].mount_point) - 1] = '\0';

        strncpy(mounts[count].fs_type, fs_type, sizeof(mounts[count].fs_type) - 1);
        mounts[count].fs_type[sizeof(mounts[count].fs_type) - 1] = '\0';

        strncpy(mounts[count].options, options, sizeof(mounts[count].options) - 1);
        mounts[count].options[sizeof(mounts[count].options) - 1] = '\0';

        count++;
    }

    fclose(fp);

    if (count == 0) {
        free(mounts);
        printf("[]\n");
        return;
    }

    /* Sort by mount_point for consistent output */
    qsort(mounts, count, sizeof(MountInfo), mount_cmp);

    /* === OUTPUT – replace this block with your database insert === */
    printf("[\n");
    for (size_t i = 0; i < count; i++) {
        printf("  {\"device\":\"%s\",\"mount_point\":\"%s\",\"fs_type\":\"%s\",\"options\":\"%s\"}",
               mounts[i].device, mounts[i].mount_point, mounts[i].fs_type, mounts[i].options);

        if (i < count - 1) printf(",");
        printf("\n");
    }
    printf("]\n");

    free(mounts);
}

int main(void)
{
    scan_mounted_filesystems();
    return 0;
}
