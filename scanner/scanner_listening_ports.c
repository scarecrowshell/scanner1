#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>     /* for readlink */
#include <limits.h>     /* for PATH_MAX */

/* Tagged struct so 'struct ListeningPort' is defined before use in pid_cmp */
typedef struct ListeningPort {
    int   pid;
    char  comm[17];           /* short process name */
    unsigned short port;      /* listening port (host byte order) */
    char  local_ip[32];       /* listening IP (e.g., "0.0.0.0" or "127.0.0.1") */
    char  inode[32];          /* socket inode for reference */
} ListeningPort;

/* Comparator for qsort by PID, then port */
static int pid_cmp(const void *a, const void *b) {
    const struct ListeningPort *pa = a;
    const struct ListeningPort *pb = b;
    if (pa->pid != pb->pid) return pa->pid - pb->pid;
    return pa->port - pb->port;
}

/*
   Scanner: Listening TCP ports (with process PID/comm)
   Parses /proc/net/tcp for LISTEN (state 0A) entries, collects inode.
   Then scans all /proc/<pid>/fd to match socket:[inode] and associate PID/comm.
   Output: JSON array of {pid, comm, port, local_ip, inode} for each listening socket.
   Note: Run as root to see all (some /proc/pid/fd restricted).
   Only IPv4 for simplicity; add IPv6 from /proc/net/tcp6 if needed.
*/
void scan_listening_tcp_ports(void)
{
    /* Step 1: Parse /proc/net/tcp for listening sockets + inodes */
    FILE *tcp = fopen("/proc/net/tcp", "re");
    if (!tcp) {
        perror("fopen /proc/net/tcp");
        printf("[]\n");
        return;
    }

    char line[1024];
    char **listen_inodes = NULL;
    size_t inode_capacity = 0;
    size_t inode_count = 0;

    /* Skip header */
    fgets(line, sizeof(line), tcp);

    while (fgets(line, sizeof(line), tcp)) {
        unsigned int local_ip_hex, state_hex;
        unsigned short local_port_hex;
        char inode_str[32];

        if (sscanf(line, "%*d: %8X:%4hX %*8X:%*4X %2X %*s %*s %*s %*s %*s %31s",
                   &local_ip_hex, &local_port_hex, &state_hex, inode_str) != 4) {
            continue;
        }

        if (state_hex != 0x0A) continue;  /* not LISTEN */

        /* Grow inode array */
        if (inode_count >= inode_capacity) {
            inode_capacity = inode_capacity ? inode_capacity * 2 : 128;
            char **new_inodes = realloc(listen_inodes, inode_capacity * sizeof(char *));
            if (!new_inodes) break;
            listen_inodes = new_inodes;
        }

        listen_inodes[inode_count++] = strdup(inode_str);
    }
    fclose(tcp);

    if (inode_count == 0) {
        free(listen_inodes);
        printf("[]\n");
        return;
    }

    /* Step 2: Scan all processes to find who owns each inode */
    ListeningPort *ports = NULL;
    size_t port_capacity = 0;
    size_t port_count = 0;

    DIR *proc = opendir("/proc");
    if (!proc) {
        perror("opendir /proc");
        for (size_t i = 0; i < inode_count; i++) free(listen_inodes[i]);
        free(listen_inodes);
        printf("[]\n");
        return;
    }

    struct dirent *ent;
    while ((ent = readdir(proc)) != NULL) {
        if (ent->d_type != DT_DIR) continue;
        if (!isdigit((unsigned char)ent->d_name[0])) continue;

        int pid = atoi(ent->d_name);

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

        /* Scan /proc/pid/fd for socket:[inode] */
        char fd_path[64];
        snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd", pid);
        DIR *fddir = opendir(fd_path);
        if (!fddir) continue;

        struct dirent *fdent;
        while ((fdent = readdir(fddir)) != NULL) {
            if (!isdigit((unsigned char)fdent->d_name[0])) continue;

            char link_path[128];
            /* --- FIX: bound the fdent->d_name write to avoid truncation warning --- */
            size_t fd_path_len = strlen(fd_path);
            int max_name_len = (int)sizeof(link_path) - (int)fd_path_len - 2;
            if (max_name_len < 0) max_name_len = 0;
            snprintf(link_path, sizeof(link_path), "%s/%.*s", fd_path, max_name_len, fdent->d_name);

            char target[PATH_MAX + 1];
            ssize_t tlen = readlink(link_path, target, PATH_MAX);
            if (tlen < 0) continue;
            target[tlen] = '\0';

            /* Check if socket:[inode] */
            char inode_str[32];
            if (sscanf(target, "socket:[%31[^]]", inode_str) != 1) continue;

            /* Match against listening inodes */
            for (size_t k = 0; k < inode_count; k++) {
                if (strcmp(inode_str, listen_inodes[k]) == 0) {
                    /* Found match – now get IP/port from /proc/net/tcp (re-parse for this inode) */
                    FILE *tcp2 = fopen("/proc/net/tcp", "re");
                    if (!tcp2) continue;

                    fgets(line, sizeof(line), tcp2);  /* skip header */

                    while (fgets(line, sizeof(line), tcp2)) {
                        unsigned int local_ip_hex, state_hex;
                        unsigned short local_port_hex;
                        char match_inode[32];

                        if (sscanf(line, "%*d: %8X:%4hX %*8X:%*4X %2X %*s %*s %*s %*s %*s %31s",
                                   &local_ip_hex, &local_port_hex, &state_hex, match_inode) != 4) continue;

                        if (state_hex != 0x0A || strcmp(match_inode, inode_str) != 0) continue;

                        /* Convert IP hex to dotted (IPv4) */
                        char local_ip[32];
                        snprintf(local_ip, sizeof(local_ip), "%d.%d.%d.%d",
                                 local_ip_hex & 0xFF,
                                 (local_ip_hex >> 8) & 0xFF,
                                 (local_ip_hex >> 16) & 0xFF,
                                 (local_ip_hex >> 24) & 0xFF);

                        /* Grow ports array */
                        if (port_count >= port_capacity) {
                            port_capacity = port_capacity ? port_capacity * 2 : 256;
                            ListeningPort *new_ports = realloc(ports, port_capacity * sizeof(ListeningPort));
                            if (!new_ports) break;
                            ports = new_ports;
                        }

                        ports[port_count].pid = pid;
                        strncpy(ports[port_count].comm, comm, sizeof(ports[port_count].comm) - 1);
                        ports[port_count].comm[sizeof(ports[port_count].comm) - 1] = '\0';
                        ports[port_count].port = local_port_hex;
                        strncpy(ports[port_count].local_ip, local_ip, sizeof(ports[port_count].local_ip) - 1);
                        ports[port_count].local_ip[sizeof(ports[port_count].local_ip) - 1] = '\0';
                        strncpy(ports[port_count].inode, inode_str, sizeof(ports[port_count].inode) - 1);
                        ports[port_count].inode[sizeof(ports[port_count].inode) - 1] = '\0';

                        port_count++;
                        break;  /* found this inode */
                    }
                    fclose(tcp2);
                    break;  /* move to next FD */
                }
            }
        }
        closedir(fddir);
    }

    closedir(proc);

    for (size_t i = 0; i < inode_count; i++) free(listen_inodes[i]);
    free(listen_inodes);

    if (port_count == 0) {
        free(ports);
        printf("[]\n");
        return;
    }

    /* Sort by PID then port */
    qsort(ports, port_count, sizeof(ListeningPort), pid_cmp);

    /* === OUTPUT – replace this block with your database insert === */
    printf("[\n");
    for (size_t i = 0; i < port_count; i++) {
        printf("  {\"pid\":%d,\"comm\":\"%s\",\"port\":%hu,\"local_ip\":\"%s\",\"inode\":\"%s\"}",
               ports[i].pid, ports[i].comm, ports[i].port, ports[i].local_ip, ports[i].inode);

        if (i < port_count - 1) printf(",");
        printf("\n");
    }
    printf("]\n");

    free(ports);
}

int main(void)
{
    scan_listening_tcp_ports();
    return 0;
}
