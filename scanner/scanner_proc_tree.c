#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdbool.h>

/* Max reasonable number of processes on most systems */
#define MAX_PROCS 32768

typedef struct {
    int pid;
    int ppid;
    char name[17];      /* TASK_COMM_LEN = 16 + '\0' */
} ProcInfo;

typedef struct ChildNode {
    int pid;
    struct ChildNode *next;
} ChildNode;

static ProcInfo procs[MAX_PROCS];
static int proc_count = 0;

static ChildNode *children[MAX_PROCS];   /* indexed by pid → list of children */
static bool visited[MAX_PROCS];

/* Comparator: sort by PID */
static int pid_cmp(const void *a, const void *b) {
    return (*(const int *)a) - (*(const int *)b);
}

/* Find ProcInfo index by pid (binary search after sorting) */
static int find_proc_index(int pid) {
    int low = 0, high = proc_count - 1;
    while (low <= high) {
        int mid = (low + high) / 2;
        if (procs[mid].pid == pid) return mid;
        if (procs[mid].pid < pid) low = mid + 1;
        else high = mid - 1;
    }
    return -1;
}

/* Read PPID and comm from /proc/<pid>/stat and /proc/<pid>/comm */
static bool read_proc_info(int pid, ProcInfo *info) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);

    FILE *fp = fopen(path, "re");
    if (!fp) return false;

    /* We only need fields: pid (1), comm (2), state (3), ppid (4) */
    char comm[17];
    int dummy;
    if (fscanf(fp, "%d (%16[^)]) %*c %d",
               &info->pid, comm, &info->ppid) != 3) {
        fclose(fp);
        return false;
    }
    fclose(fp);

    strncpy(info->name, comm, sizeof(info->name) - 1);
    info->name[sizeof(info->name) - 1] = '\0';

    return true;
}

/* Build the tree: parent → list of direct children */
static void build_process_tree(void) {
    DIR *proc = opendir("/proc");
    if (!proc) {
        perror("opendir /proc");
        return;
    }

    struct dirent *ent;
    while ((ent = readdir(proc)) != NULL) {
        if (ent->d_type != DT_DIR) continue;
        if (!isdigit((unsigned char)ent->d_name[0])) continue;

        int pid = atoi(ent->d_name);
        if (pid <= 0 || pid >= MAX_PROCS) continue;

        ProcInfo info;
        if (!read_proc_info(pid, &info)) continue;

        procs[proc_count++] = info;

        /* Add this pid as child of its ppid */
        if (info.ppid > 0 && info.ppid < MAX_PROCS) {
            ChildNode *node = malloc(sizeof(ChildNode));
            if (!node) continue;
            node->pid = pid;
            node->next = children[info.ppid];
            children[info.ppid] = node;
        }
    }

    closedir(proc);

    /* Sort procs by pid for fast lookup */
    qsort(procs, proc_count, sizeof(ProcInfo), pid_cmp);
}

/* Recursive tree printer */
static void print_tree(int pid, int depth, bool is_last) {
    if (pid <= 0 || pid >= MAX_PROCS) return;

    int idx = find_proc_index(pid);
    if (idx < 0) return;

    visited[pid] = true;

    /* Indentation + branch symbol */
    for (int i = 0; i < depth; i++) {
        printf("  ");
    }
    printf("%s─ ", is_last ? "└" : "├");

    printf("%d %s\n", pid, procs[idx].name);

    /* Count children for knowing who is last */
    int child_count = 0;
    ChildNode *child = children[pid];
    while (child) { child_count++; child = child->next; }

    int pos = 0;
    child = children[pid];
    while (child) {
        bool last = (++pos == child_count);
        print_tree(child->pid, depth + 1, last);
        child = child->next;
    }
}

/*
   Scanner: Parent PID + basic process tree view
   Output: indented tree starting from PID 1
*/
void scan_parent_pid_and_tree(void)
{
    memset(children, 0, sizeof(children));
    memset(visited, 0, sizeof(visited));
    proc_count = 0;

    build_process_tree();

    if (proc_count == 0) {
        printf("No processes found.\n");
        return;
    }

    printf("Process Tree (starting from PID 1):\n");
    print_tree(1, 0, true);   /* root is almost always 1 */

    /* Optional: show orphan processes (ppid not found or 0) */
    printf("\nPossible orphans / kernel threads (not attached to tree):\n");
    for (int i = 0; i < proc_count; i++) {
        if (!visited[procs[i].pid] && procs[i].pid != 1) {
            printf("  %d %s (ppid %d)\n", procs[i].pid, procs[i].name, procs[i].ppid);
        }
    }

    /* Cleanup */
    for (int i = 0; i < MAX_PROCS; i++) {
        ChildNode *c = children[i];
        while (c) {
            ChildNode *next = c->next;
            free(c);
            c = next;
        }
    }
}

int main(void)
{
    scan_parent_pid_and_tree();
    return 0;
}
