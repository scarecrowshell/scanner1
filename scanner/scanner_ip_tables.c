#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> /* for access (optional, but used for hint) */
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
        char *newbuf = realloc(buffer, size + nread + 1);
        if (!newbuf) {
            free(buffer);
            pclose(fp);
            return NULL;
        }
        buffer = newbuf;
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
Scanner: iptables / nftables rules (snapshot)
Tries nftables first (modern), falls back to iptables (legacy).
Captures full output as text snapshot.
Output: JSON array with one object {type, snapshot} or [] if neither available.
Note: Run as root for full rules (some require privileges).
Assumes nft at /usr/sbin/nft, iptables-save at /sbin/iptables-save, but uses direct exec (popen finds in PATH).
*/
void scan_iptables_nftables_rules(void)
{
    char *snap = capture_command("nft list ruleset");
    const char *type = NULL;

    if (snap) {
        type = "nftables";
    } else {
        snap = capture_command("iptables-save");
        if (snap) {
            type = "iptables";
        }
    }

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

    printf("[{\"type\":\"%s\",\"snapshot\":\"%s\"}]\n", type, esc);
    free(esc);

    /* Example DB-style replacement:
    db_insert_rules_snapshot(type, snap);
    */
}

int main(void)
{
    scan_iptables_nftables_rules();
    return 0;
}
