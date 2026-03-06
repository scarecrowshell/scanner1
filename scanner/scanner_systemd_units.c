#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h> /* for WIFEXITED, WEXITSTATUS */

/* Struct for Systemd unit */
typedef struct Unit {
    char id[256];
    char load_state[32];
    char active_state[32];
    char sub_state[32];
    char description[512];
    char unit_file_state[32];
} Unit;

/* Comparator for qsort by id */
static int unit_cmp(const void *a, const void *b) {
    const struct Unit *pa = a;
    const struct Unit *pb = b;
    return strcmp(pa->id, pb->id);
}

/* Helper: Add unique unit name to list */
static int add_unique_name(char ***names, size_t *count, size_t *capacity, const char *unit) {
    for (size_t i = 0; i < *count; i++) {
        if (strcmp((*names)[i], unit) == 0) return 0;
    }
    if (*count >= *capacity) {
        *capacity = *capacity ? *capacity * 2 : 128;
        char **new_names = realloc(*names, *capacity * sizeof(char *));
        if (!new_names) return -1;
        *names = new_names;
    }
    (*names)[*count] = strdup(unit);
    if (!(*names)[*count]) return -1;
    (*count)++;
    return 0;
}

/* Helper: Collect unit names from systemctl output */
static int collect_units_from_command(const char *cmd, char ***names, size_t *count, size_t *capacity) {
    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        char unit[256];
        if (sscanf(line, "%255s", unit) != 1) continue;
        if (add_unique_name(names, count, capacity, unit) != 0) {
            pclose(fp);
            return -1;
        }
    }

    int status = pclose(fp);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return -1; /* Continue anyway if one command fails */
    }
    return 0;
}

/*
Scanner: Systemd units (active, failed, enabled)
Collects unique units that are active, failed, or enabled (including all types: service, timer, etc.).
Uses systemctl list-units and list-unit-files to gather names, then 'show' for details.
Filters to include only those matching the criteria.
Output: JSON array of {id, load_state, active_state, sub_state, description, unit_file_state}.
Note: Run as root for full list. If no systemd or failures, outputs [].
*/
void scan_systemd_units(void) {
    char **names = NULL;
    size_t count = 0;
    size_t capacity = 0;

    /* Collect active units */
    collect_units_from_command("systemctl list-units --state=active --plain --no-legend --no-pager", &names, &count, &capacity);

    /* Collect failed units */
    collect_units_from_command("systemctl list-units --state=failed --plain --no-legend --no-pager", &names, &count, &capacity);

    /* Collect enabled units */
    collect_units_from_command("systemctl list-unit-files --state=enabled --plain --no-legend --no-pager", &names, &count, &capacity);

    if (count == 0) {
        printf("[]\n");
        goto cleanup;
    }

    /* Sort names for consistent order */
    qsort(names, count, sizeof(char *), (int (*)(const void *, const void *))strcmp);

    /* Gather details */
    Unit *units = malloc(count * sizeof(Unit));
    if (!units) {
        printf("[]\n");
        goto cleanup;
    }
    size_t ucount = 0;

    for (size_t i = 0; i < count; i++) {
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "systemctl show -p Id -p LoadState -p ActiveState -p SubState -p Description -p UnitFileState --value %s", names[i]);

        FILE *fp = popen(cmd, "r");
        if (!fp) continue;

        char id[256] = "", load[32] = "", active[32] = "", sub[32] = "", desc[512] = "", ufs[32] = "";
        if (fgets(id, sizeof(id), fp) &&
            fgets(load, sizeof(load), fp) &&
            fgets(active, sizeof(active), fp) &&
            fgets(sub, sizeof(sub), fp) &&
            fgets(desc, sizeof(desc), fp) &&
            fgets(ufs, sizeof(ufs), fp)) {

            id[strcspn(id, "\n")] = 0;
            load[strcspn(load, "\n")] = 0;
            active[strcspn(active, "\n")] = 0;
            sub[strcspn(sub, "\n")] = 0;
            desc[strcspn(desc, "\n")] = 0;
            ufs[strcspn(ufs, "\n")] = 0;

            /* Include if active, failed, or enabled */
            if (strcmp(active, "active") == 0 ||
                strcmp(active, "failed") == 0 ||
                strstr(ufs, "enabled") != NULL) {

                snprintf(units[ucount].id, sizeof(units[ucount].id), "%s", id);
                snprintf(units[ucount].load_state, sizeof(units[ucount].load_state), "%s", load);
                snprintf(units[ucount].active_state, sizeof(units[ucount].active_state), "%s", active);
                snprintf(units[ucount].sub_state, sizeof(units[ucount].sub_state), "%s", sub);
                snprintf(units[ucount].description, sizeof(units[ucount].description), "%s", desc);
                snprintf(units[ucount].unit_file_state, sizeof(units[ucount].unit_file_state), "%s", ufs);
                ucount++;
            }
        }
        pclose(fp);
    }

    if (ucount == 0) {
        printf("[]\n");
        free(units);
        goto cleanup;
    }

    /* Sort by id */
    qsort(units, ucount, sizeof(Unit), unit_cmp);

    /* Output JSON */
    printf("[\n");
    for (size_t i = 0; i < ucount; i++) {
        printf(" {\"id\":\"%s\",\"load_state\":\"%s\",\"active_state\":\"%s\",\"sub_state\":\"%s\",\"description\":\"%s\",\"unit_file_state\":\"%s\"}",
               units[i].id, units[i].load_state, units[i].active_state, units[i].sub_state, units[i].description, units[i].unit_file_state);
        if (i < ucount - 1) printf(",");
        printf("\n");
    }
    printf("]\n");

    /* Example DB-style replacement:
    for (size_t i = 0; i < ucount; i++) {
        db_insert_systemd_unit(units[i].id, units[i].load_state, units[i].active_state,
                               units[i].sub_state, units[i].description, units[i].unit_file_state);
    }
    */

    free(units);

cleanup:
    for (size_t i = 0; i < count; i++) free(names[i]);
    free(names);
}

int main(void) {
    scan_systemd_units();
    return 0;
}
