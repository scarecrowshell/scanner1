#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

/* Comparator for qsort */
static int pid_cmp(const void *a, const void *b)
{
    return (*(const int *)a) - (*(const int *)b);
}

/* 
   Your scanner function.
   Call this from your main scanner loop.
   It collects all PIDs and prints them as JSON.
   Replace the printf block with your DB insert code.
*/
void scan_all_running_pids(void)
{
    DIR *proc = opendir("/proc");
    if (!proc) {
        perror("opendir /proc");
        return;
    }

    /* 4096 is way more than enough on any normal system */
    int pids[4096];
    int count = 0;

    struct dirent *ent;
    while ((ent = readdir(proc)) != NULL && count < 4096) {
        /* Every process PID appears as a numeric directory in /proc */
        if (ent->d_type == DT_DIR && isdigit((unsigned char)ent->d_name[0])) {
            pids[count++] = atoi(ent->d_name);
        }
    }

    closedir(proc);

    /* Optional: sort the list so the output is always in the same order */
    qsort(pids, count, sizeof(int), pid_cmp);

    /* === OUTPUT FOR DATABASE === */
    /* You can replace this whole block with your DB code */
    printf("[");                                 /* start JSON array */
    for (int i = 0; i < count; i++) {
        printf("%d", pids[i]);
        if (i < count - 1)
            printf(",");
    }
    printf("]\n");                               /* end JSON array */
    /* Example of what you might do instead:
       for (int i = 0; i < count; i++) {
           insert_into_db("running_pids", pids[i]);
       }
    */
}

int main(void)
{
    scan_all_running_pids();
    return 0;
}
