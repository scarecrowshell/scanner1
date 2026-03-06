/* scanner_init_scripts.c
 *
 * Lists files in /etc/init.d/ (sysv) and /etc/init/ "*.conf" (upstart),
 * with parsed description if available. Skips if systemd detected.
 *
 * Output: JSON array of objects {name,type,path,description} sorted by name.
 *
 * Notes:
 *  - Run as root for full access if needed.
 */

#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <limits.h> /* PATH_MAX */
#include <sys/stat.h>
#include <errno.h>

typedef struct Service {
    char name[256];
    char type[16]; /* "sysv" or "upstart" */
    char path[PATH_MAX];
    char description[512];
} Service;

/* Minimal JSON escape for " \ \n \r \t */
static char *json_escape(const char *s) {
    if (!s) return NULL;
    size_t len = strlen(s);
    /* worst-case each char becomes two -> allocate len*2+1 */
    char *out = malloc(len * 2 + 1);
    if (!out) return NULL;
    char *p = out;
    for (const char *q = s; *q; q++) {
        switch (*q) {
            case '"': *p++ = '\\'; *p++ = '"'; break;
            case '\\': *p++ = '\\'; *p++ = '\\'; break;
            case '\n': *p++ = '\\'; *p++ = 'n'; break;
            case '\r': *p++ = '\\'; *p++ = 'r'; break;
            case '\t': *p++ = '\\'; *p++ = 't'; break;
            default: *p++ = *q; break;
        }
    }
    *p = '\0';
    return out;
}

static void print_json_field(const char *label, const char *value, int needs_comma) {
    char *esc = json_escape(value ? value : "");
    if (!esc) esc = strdup("");
    printf(" \"%s\":\"%s\"%s", label, esc, needs_comma ? "," : "");
    free(esc);
}

/* Trim leading/trailing whitespace in-place */
static void trim(char *str) {
    if (!str) return;
    char *start = str;
    while (*start && isspace((unsigned char)*start)) start++;
    if (*start == '\0') { str[0] = '\0'; return; }
    char *end = start + strlen(start) - 1;
    while (end > start && isspace((unsigned char)*end)) end--;
    size_t newlen = (size_t)(end - start) + 1;
    memmove(str, start, newlen);
    str[newlen] = '\0';
}

static int has_conf_suffix(const char *name) {
    size_t n = strlen(name);
    if (n < 5) return 0;
    return strcmp(name + n - 5, ".conf") == 0;
}

/* Add services from dir_path with type svc_type.
 * Returns 0 on success (including "dir missing" which is non-fatal),
 * returns -1 on fatal allocation failure.
 */
static int add_services(const char *dir_path, const char *svc_type, Service **services, size_t *count, size_t *capacity) {
    DIR *dir = opendir(dir_path);
    if (!dir) {
        return 0; /* Not fatal: directory may not exist on modern systems */
    }

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        if (strcmp(svc_type, "upstart") == 0 && !has_conf_suffix(ent->d_name)) continue;

        char fullpath[PATH_MAX];
        if (snprintf(fullpath, sizeof(fullpath), "%s/%s", dir_path, ent->d_name) >= (int)sizeof(fullpath)) {
            continue; /* path too long */
        }

        struct stat st;
        if (stat(fullpath, &st) < 0) continue;
        if (!S_ISREG(st.st_mode)) continue;

        /* Grow array */
        if (*count >= *capacity) {
            size_t newcap = *capacity ? (*capacity) * 2 : 128;
            Service *ns = realloc(*services, newcap * sizeof(Service));
            if (!ns) { closedir(dir); return -1; }
            *services = ns;
            *capacity = newcap;
        }

        Service *svc = &(*services)[*count];

        /* Use snprintf for safe copy of name/type/path */
        snprintf(svc->name, sizeof(svc->name), "%s", ent->d_name);
        snprintf(svc->type, sizeof(svc->type), "%s", svc_type);
        snprintf(svc->path, sizeof(svc->path), "%s", fullpath);
        svc->description[0] = '\0';

        /* Parse description if readable; copy safely into svc->description */
        FILE *f = fopen(svc->path, "r");
        if (f) {
            char line[1024];
            if (strcmp(svc_type, "sysv") == 0) {
                int in_info = 0;
                while (fgets(line, sizeof(line), f)) {
                    if (strstr(line, "### BEGIN INIT INFO")) in_info = 1;
                    if (in_info && strstr(line, "### END INIT INFO")) break;
                    if (in_info && strncmp(line, "# Description:", 14) == 0) {
                        char *desc_start = line + 14;
                        trim(desc_start);
                        /* safe copy: limit to sizeof(description)-1 */
                        size_t max = sizeof(svc->description) - 1;
                        size_t want = strlen(desc_start);
                        if (want > max) want = max;
                        if (want) memcpy(svc->description, desc_start, want);
                        svc->description[want] = '\0';
                        break;
                    }
                }
            } else if (strcmp(svc_type, "upstart") == 0) {
                while (fgets(line, sizeof(line), f)) {
                    if (strncmp(line, "description ", 12) == 0) {
                        char *desc_start = line + 12;
                        trim(desc_start);
                        if (*desc_start == '"') desc_start++;
                        trim(desc_start);
                        size_t len = strlen(desc_start);
                        if (len > 0 && desc_start[len - 1] == '"') desc_start[len - 1] = '\0';
                        trim(desc_start);
                        size_t max = sizeof(svc->description) - 1;
                        size_t want = strlen(desc_start);
                        if (want > max) want = max;
                        if (want) memcpy(svc->description, desc_start, want);
                        svc->description[want] = '\0';
                        break;
                    }
                }
            }
            fclose(f);
        }

        (*count)++;
    }

    closedir(dir);
    return 0;
}

static int name_cmp(const void *a, const void *b) {
    const Service *pa = (const Service *)a;
    const Service *pb = (const Service *)b;
    return strcmp(pa->name, pb->name);
}

void scan_init_scripts(void) {
    /* If systemd is PID 1, skip */
    FILE *comm = fopen("/proc/1/comm", "r");
    if (comm) {
        char line[64];
        if (fgets(line, sizeof(line), comm)) {
            if (strstr(line, "systemd")) { fclose(comm); printf("[]\n"); return; }
        }
        fclose(comm);
    }

    Service *services = NULL;
    size_t count = 0, capacity = 0;

    if (add_services("/etc/init.d", "sysv", &services, &count, &capacity) < 0) { fprintf(stderr, "alloc failure\n"); free(services); return; }
    if (add_services("/etc/init", "upstart", &services, &count, &capacity) < 0) { fprintf(stderr, "alloc failure\n"); free(services); return; }

    if (count == 0) { free(services); printf("[]\n"); return; }

    qsort(services, count, sizeof(Service), name_cmp);

    printf("[\n");
    for (size_t i = 0; i < count; i++) {
        printf("  {");
        print_json_field("name", services[i].name, 1);
        print_json_field("type", services[i].type, 1);
        print_json_field("path", services[i].path, 1);
        print_json_field("description", services[i].description, 0);
        printf(" }%s\n", (i + 1 < count) ? "," : "");
    }
    printf("]\n");

    free(services);
}

int main(void) {
    scan_init_scripts();
    return 0;
}
