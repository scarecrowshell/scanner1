#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>     /* for readlink */
#include <limits.h>     /* for PATH_MAX */

/* Tagged struct so 'struct Connection' is defined before use in pid_cmp */
typedef struct Connection {
    int   pid;
    char  comm[17];           /* short process name */
    unsigned short local_port; /* local port (host byte order) */
    char  local_ip[32];       /* local IP (e.g., "127.0.0.1") */
    unsigned short remote_port; /* remote port (host byte order) */
    char  remote_ip[32];      /* remote IP (e.g., "8.8.8.8") */
    char  inode[32];          /* socket inode for reference */
} Connection;

/* Comparator for qsort by PID, then local_port */
static int pid_cmp(const void *a, const void *b) {
    const struct Connection *pa = a;
    const struct Connection *pb = b;
    if (pa->pid != pb->pid) return pa->pid - pb->pid;
    return pa->local_port - pb->local_port;
}

/*
Scanner: Established TCP connections (with process PID/comm)
Parses /proc/net/tcp for established entries (state 01), collects inode, local/remote IP/port.
Then scans all /proc/<pid>/fd to match socket:[inode] and associate PID/comm.
Output: JSON array of {pid, comm, local_ip, local_port, remote_ip, remote_port, inode} for each established TCP connection.
Note: Run as root to see all (some /proc/pid/fd restricted).
Only IPv4 for simplicity; add IPv6 from /proc/net/tcp6 if needed.
*/
void scan_established_tcp_connections(void)
{
    /* Step 1: Parse /proc/net/tcp for established connections + inodes */
    FILE *tcp = fopen("/proc/net/tcp", "re");
    if (!tcp) {
        perror("fopen /proc/net/tcp");
        printf("[]\n");
        return;
    }

    char line[1024];
    Connection *connections = NULL;
    size_t conn_capacity = 0;
    size_t conn_count = 0;

    /* Skip header */
    fgets(line, sizeof(line), tcp);

    while (fgets(line, sizeof(line), tcp)) {
        unsigned int local_ip_hex;
        unsigned short local_port_hex;
        unsigned int remote_ip_hex;
        unsigned short remote_port_hex;
        unsigned int st_hex;
        char inode_str[32];

        if (sscanf(line, "%*d: %8X:%4hX %8X:%4hX %2X %*s %*s %*s %*s %*s %31s",
                &local_ip_hex, &local_port_hex, &remote_ip_hex, &remote_port_hex, &st_hex, inode_str) != 6) {
            continue;
        }

        if (st_hex != 0x01) continue;  /* Only established (TCP_ESTABLISHED) */

        /* Convert IPs to dotted decimal */
        char local_ip[32];
        snprintf(local_ip, sizeof(local_ip), "%d.%d.%d.%d",
                local_ip_hex & 0xFF,
                (local_ip_hex >> 8) & 0xFF,
                (local_ip_hex >> 16) & 0xFF,
                (local_ip_hex >> 24) & 0xFF);

        char remote_ip[32];
        snprintf(remote_ip, sizeof(remote_ip), "%d.%d.%d.%d",
                remote_ip_hex & 0xFF,
                (remote_ip_hex >> 8) & 0xFF,
                (remote_ip_hex >> 16) & 0xFF,
                (remote_ip_hex >> 24) & 0xFF);

        /* Grow connections array */
        if (conn_count >= conn_capacity) {
            conn_capacity = conn_capacity ? conn_capacity * 2 : 128;
            Connection *new_conns = realloc(connections, conn_capacity * sizeof(Connection));
            if (!new_conns) break;
            connections = new_conns;
        }

        connections[conn_count].pid = 0;  /* To be filled */
        memset(connections[conn_count].comm, 0, sizeof(connections[conn_count].comm));
        connections[conn_count].local_port = local_port_hex;
        /* --- FIX: use snprintf to safely copy and ensure NUL termination --- */
        snprintf(connections[conn_count].local_ip, sizeof(connections[conn_count].local_ip), "%s", local_ip);
        connections[conn_count].remote_port = remote_port_hex;
        snprintf(connections[conn_count].remote_ip, sizeof(connections[conn_count].remote_ip), "%s", remote_ip);
        snprintf(connections[conn_count].inode, sizeof(connections[conn_count].inode), "%s", inode_str);

        conn_count++;
    }
    fclose(tcp);

    if (conn_count == 0) {
        free(connections);
        printf("[]\n");
        return;
    }

    /* Step 2: Scan all processes to find who owns each inode */
    DIR *proc = opendir("/proc");
    if (!proc) {
        perror("opendir /proc");
        free(connections);
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
            /* Bound the written fd name to avoid snprintf truncation warning */
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

            /* Match against connections */
            for (size_t k = 0; k < conn_count; k++) {
                if (connections[k].pid == 0 && strcmp(inode_str, connections[k].inode) == 0) {
                    connections[k].pid = pid;
                    /* --- FIX: use snprintf to safely copy comm and ensure NUL termination --- */
                    snprintf(connections[k].comm, sizeof(connections[k].comm), "%s", comm);
                    break;  /* Assume one owner per inode */
                }
            }
        }
        closedir(fddir);
    }

    closedir(proc);

    /* Sort by PID then local_port */
    qsort(connections, conn_count, sizeof(Connection), pid_cmp);

    /* === OUTPUT – replace this block with your database insert === */
    printf("[\n");
    for (size_t i = 0; i < conn_count; i++) {
        /* Skip if pid not found (e.g., permission issues) */
        if (connections[i].pid == 0) continue;

        printf("  {\"pid\":%d,\"comm\":\"%s\",\"local_ip\":\"%s\",\"local_port\":%hu,\"remote_ip\":\"%s\",\"remote_port\":%hu,\"inode\":\"%s\"}",
            connections[i].pid, connections[i].comm, connections[i].local_ip, connections[i].local_port,
            connections[i].remote_ip, connections[i].remote_port, connections[i].inode);

        if (i < conn_count - 1) printf(",");
        printf("\n");
    }
    printf("]\n");

    /* Example DB-style replacement:
    for (size_t i = 0; i < conn_count; i++) {
        if (connections[i].pid == 0) continue;
        db_insert_established_tcp_conn(connections[i].pid, connections[i].comm,
                                       connections[i].local_ip, connections[i].local_port,
                                       connections[i].remote_ip, connections[i].remote_port,
                                       connections[i].inode);
    }
    */

    free(connections);
}

int main(void)
{
    scan_established_tcp_connections();
    return 0;
}
