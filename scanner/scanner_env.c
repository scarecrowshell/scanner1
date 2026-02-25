#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdbool.h>

/* Comparator for qsort by PID */
static int pid_cmp(const void *a, const void *b) {
    return (*(const int *)a) - (*(const int *)b);
}

typedef struct {
    int    pid;
    char   comm[17];
    char **env_vars;          /* dynamic array of "KEY=VALUE" strings */
    size_t env_count;
    size_t env_capacity;
} ProcEnv;

static void add_env_var(ProcEnv *p, const char *var) {
    if (p->env_count >= p->env_capacity) {
        p->env_capacity = p->env_capacity ? p->env_capacity * 2 : 64;
        char **new_env = realloc(p->env_vars, p->env_capacity * sizeof(char *));
        if (!new_env) return;
        p->env_vars = new_env;
    }

    p->env_vars[p->env_count] = strdup(var);
    if (p->env_vars[p->env_count]) p->env_count++;
}

static void free_procenv(ProcEnv *p) {
    for (size_t i = 0; i < p->env_count; i++) {
        free(p->env_vars[i]);
    }
    free(p->env_vars);
    p->env_vars = NULL;
    p->env_count = p->env_capacity = 0;
}

/*
   Scanner: Environment variables for all running processes
   Reads /proc/<pid>/environ (null-separated bytes) and splits into "KEY=VALUE" strings
   Note: requires root or same-user to read other processes' env (sensitive data!)
   Output: JSON array of {pid, comm, env: ["KEY1=VALUE1", "KEY2=VALUE2", ...]}
*/
void scan_environment_variables(void)
{
    DIR *proc = opendir("/proc");
    if (!proc) {
        perror("opendir /proc");
        return;
    }

    ProcEnv *processes = NULL;
    size_t capacity = 0;
    size_t count = 0;

    struct dirent *ent;
    while ((ent = readdir(proc)) != NULL) {
        if (ent->d_type != DT_DIR) continue;
        if (!isdigit((unsigned char)ent->d_name[0])) continue;

        int pid = atoi(ent->d_name);
        if (pid <= 0) continue;

        /* Get comm */
        char comm_path[64];
        snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
        FILE *fc = fopen(comm_path, "re");
        char comm[17] = "[unknown]";
        if (fc) {
            if (fgets(comm, sizeof(comm), fc)) {
                size_t len = strlen(comm);
                if (len > 0 && comm[len-1] == '\n') comm[len-1] = '\0';
            }
            fclose(fc);
        }

        /* Open /proc/<pid>/environ */
        char env_path[64];
        snprintf(env_path, sizeof(env_path), "/proc/%d/environ", pid);

        FILE *fe = fopen(env_path, "re");
        if (!fe) continue;  /* no access or process gone */

        /* Read the entire null-separated file */
        fseek(fe, 0, SEEK_END);
        long size = ftell(fe);
        fseek(fe, 0, SEEK_SET);

        if (size <= 0) {
            fclose(fe);
            continue;
        }

        char *buffer = malloc(size + 1);  /* +1 for safety */
        if (!buffer) {
            fclose(fe);
            continue;
        }

        size_t read_size = fread(buffer, 1, size, fe);
        fclose(fe);

        if (read_size == 0) {
            free(buffer);
            continue;
        }

        buffer[read_size] = '\0';  /* ensure null-terminated */

        ProcEnv info = { .pid = pid, .env_count = 0, .env_capacity = 0, .env_vars = NULL };
        /* replaced strncpy with snprintf to avoid truncation warning */
        snprintf(info.comm, sizeof(info.comm), "%s", comm);

        /* Split by null bytes */
        char *start = buffer;
        char *end;
        while (start < buffer + read_size) {
            end = start;
            while (*end != '\0' && end < buffer + read_size) end++;
            if (end > start) {  /* non-empty var */
                char var[1024];  /* reasonable max per var */
                size_t len = end - start;
                if (len >= sizeof(var)) len = sizeof(var) - 1;
                strncpy(var, start, len);
                var[len] = '\0';
                add_env_var(&info, var);
            }
            start = end + 1;  /* skip null */
        }

        free(buffer);

        if (info.env_count == 0) {
            free_procenv(&info);
            continue;
        }

        /* Grow main array */
        if (count >= capacity) {
            capacity = capacity ? capacity * 2 : 8192;
            ProcEnv *new_proc = realloc(processes, capacity * sizeof(ProcEnv));
            if (!new_proc) {
                free_procenv(&info);
                continue;
            }
            processes = new_proc;
        }

        processes[count++] = info;
    }

    closedir(proc);

    if (count == 0) {
        free(processes);
        printf("[]\n");
        return;
    }

    /* Sort by PID */
    qsort(processes, count, sizeof(ProcEnv), pid_cmp);

    /* === OUTPUT – replace this block with your DB insert === */
    printf("[\n");
    for (size_t i = 0; i < count; i++) {
        printf("  {\"pid\":%d,\"comm\":\"%s\",\"env\":[",
               processes[i].pid, processes[i].comm);

        for (size_t j = 0; j < processes[i].env_count; j++) {
            /* Escape quotes and backslashes in value (for JSON safety) */
            printf("\"");
            for (char *p = processes[i].env_vars[j]; *p; p++) {
                if (*p == '"' || *p == '\\') putchar('\\');
                putchar(*p);
            }
            printf("\"");
            if (j < processes[i].env_count - 1) printf(",");
        }

        printf("]}");
        if (i < count - 1) printf(",");
        printf("\n");
    }
    printf("]\n");

    /* Example DB replacement: insert pid, comm, then for each env_var: insert(pid, env_var) */

    /* Cleanup */
    for (size_t i = 0; i < count; i++) {
        free_procenv(&processes[i]);
    }
    free(processes);
}

int main(void)
{
    scan_environment_variables();
    return 0;
}
