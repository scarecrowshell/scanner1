#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h> /* for WIFEXITED, WEXITSTATUS */

/*
Helper: Capture command output if successful (exit 0)
Returns malloc'd string or NULL on failure (incl. non-zero exit).
*/
static char *capture_command(const char *cmd) {
    FILE *fp = popen(cmd, "r");
    if (!fp) return NULL;

    char *buffer = NULL;
    size_t size = 0;

    char chunk[1024];
    while (1) {
        size_t nread = fread(chunk, 1, sizeof(chunk), fp);
        if (nread == 0) {
            if (feof(fp)) break;
            if (ferror(fp)) {
                free(buffer);
                pclose(fp);
                return NULL;
            }
        }
        if (size + nread + 1 > size) { /* Grow */
            char *newbuf = realloc(buffer, size ? size * 2 : 4096);
            if (!newbuf) {
                free(buffer);
                pclose(fp);
                return NULL;
            }
            buffer = newbuf;
        }
        memcpy(buffer + size, chunk, nread);
        size += nread;
        buffer[size] = '\0';
    }

    int status = pclose(fp);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        free(buffer);
        return NULL;
    }

    return buffer;
}

/*
Helper: Escape string for JSON (minimal: ", \, \n, \r, \t)
Returns malloc'd escaped string.
*/
static char *json_escape(const char *str) {
    size_t len = strlen(str);
    char *esc = malloc(len * 2 + 1); /* Worst case */
    if (!esc) return NULL;

    char *p = esc;
    for (; *str; str++) {
        switch (*str) {
            case '"': *p++ = '\\'; *p++ = '"'; break;
            case '\\': *p++ = '\\'; *p++ = '\\'; break;
            case '\n': *p++ = '\\'; *p++ = 'n'; break;
            case '\r': *p++ = '\\'; *p++ = 'r'; break;
            case '\t': *p++ = '\\'; *p++ = 't'; break;
            default: *p++ = *str; break;
        }
    }
    *p = '\0';
    return esc;
}

/*
Scanner: eBPF programs attached to sockets (if any)
Captures 'bpftool prog show --json --pretty' as snapshot (includes all progs, user can filter socket_filter).
Output: JSON array with one object {type, snapshot} or [] if bpftool fails/not installed.
Note: Run as root for full details. Assumes bpftool in PATH.
Look for "type": "socket_filter" and "attached" in snapshot for socket attachments.
*/
void scan_ebpf_programs(void)
{
    char *snap = capture_command("bpftool prog show --json --pretty");
    if (!snap) {
        printf("[]\n");
        return;
    }

    char *esc = json_escape(snap);
    free(snap);
    if (!esc) {
        printf("[]\n");
        return;
    }

    printf("[{\"type\":\"ebpf\",\"snapshot\":\"%s\"}]\n", esc);
    free(esc);

    /* Example DB-style replacement:
    db_insert_ebpf_snapshot(snap);
    */
}

int main(void)
{
    scan_ebpf_programs();
    return 0;
}
