#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

/* Comparator for qsort by PID */
static int pid_cmp(const void *a, const void *b) {
    return (*(const int *)a) - (*(const int *)b);
}

typedef struct {
    int  pid;
    char comm[17];                    /* short name from /proc/pid/comm */
    uid_t ruid, euid, suid, fsuid;    /* real, effective, saved, fs UID */
    gid_t rgid, egid, sgid, fsgid;    /* real, effective, saved, fs GID */
} ProcCred;

/*
   Scanner: User/group/UID/GID info for all running processes
   Reads /proc/<pid>/status for Uid/Gid lines + /proc/<pid>/comm
   Output: JSON array → replace with your DB insert loop
*/
void scan_process_credentials(void)
{
    DIR *proc = opendir("/proc");
    if (!proc) {
        perror("opendir /proc");
        return;
    }

    ProcCred *creds = NULL;
    size_t capacity = 0;
    size_t count = 0;

    struct dirent *ent;
    while ((ent = readdir(proc)) != NULL) {
        if (ent->d_type != DT_DIR) continue;
        if (!isdigit((unsigned char)ent->d_name[0])) continue;

        int pid = atoi(ent->d_name);
        if (pid <= 0) continue;

        /* Build /proc/<pid>/status path */
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/status", pid);

        FILE *fp = fopen(path, "re");
        if (!fp) continue;

        ProcCred info = { .pid = pid };

        char line[256];
        int uid_found = 0, gid_found = 0;

        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "Uid:", 4) == 0) {
                if (sscanf(line + 4, "%u %u %u %u",
                           &info.ruid, &info.euid, &info.suid, &info.fsuid) == 4) {
                    uid_found = 1;
                }
            }
            else if (strncmp(line, "Gid:", 4) == 0) {
                if (sscanf(line + 4, "%u %u %u %u",
                           &info.rgid, &info.egid, &info.sgid, &info.fsgid) == 4) {
                    gid_found = 1;
                }
            }
            else if (strncmp(line, "Name:", 5) == 0) {
                /* Optional: grab comm from here too (but we prefer /proc/pid/comm) */
            }
        }
        fclose(fp);

        if (!uid_found || !gid_found) continue;

        /* Get short comm name from /proc/<pid>/comm (cleaner than parsing Name:) */
        snprintf(path, sizeof(path), "/proc/%d/comm", pid);
        FILE *fc = fopen(path, "re");
        if (fc) {
            if (fgets(info.comm, sizeof(info.comm), fc)) {
                size_t len = strlen(info.comm);
                if (len > 0 && info.comm[len-1] == '\n')
                    info.comm[len-1] = '\0';
            } else {
                info.comm[0] = '\0';
            }
            fclose(fc);
        } else {
            info.comm[0] = '\0';
        }

        /* Grow array */
        if (count >= capacity) {
            capacity = capacity ? capacity * 2 : 8192;
            ProcCred *new_creds = realloc(creds, capacity * sizeof(ProcCred));
            if (!new_creds) continue;  /* skip on failure */
            creds = new_creds;
        }

        creds[count++] = info;
    }

    closedir(proc);

    if (count == 0) {
        free(creds);
        printf("[]\n");
        return;
    }

    /* Sort by PID for consistent output */
    qsort(creds, count, sizeof(ProcCred), pid_cmp);

    /* === OUTPUT – replace this block with your database logic === */
    printf("[\n");
    for (size_t i = 0; i < count; i++) {
        printf("  {\"pid\":%d,\"comm\":\"%s\","
               "\"ruid\":%u,\"euid\":%u,\"suid\":%u,\"fsuid\":%u,"
               "\"rgid\":%u,\"egid\":%u,\"sgid\":%u,\"fsgid\":%u}",
               creds[i].pid, creds[i].comm,
               creds[i].ruid, creds[i].euid, creds[i].suid, creds[i].fsuid,
               creds[i].rgid, creds[i].egid, creds[i].sgid, creds[i].fsgid);

        if (i < count - 1) printf(",");
        printf("\n");
    }
    printf("]\n");

    /* Example DB-style replacement:
    for (size_t i = 0; i < count; i++) {
        db_insert_cred(creds[i].pid,
                       creds[i].comm,
                       creds[i].ruid, creds[i].euid, creds[i].suid, creds[i].fsuid,
                       creds[i].rgid, creds[i].egid, creds[i].sgid, creds[i].fsgid);
    }
    */

    free(creds);
}

int main(void)
{
    scan_process_credentials();
    return 0;
}
