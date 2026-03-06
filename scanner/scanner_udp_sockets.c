#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h> /* for readlink */
#include <limits.h> /* for PATH_MAX */

/* Tagged struct so 'struct Socket' is defined before use in pid_cmp */
typedef struct Socket {
    int pid;
    char comm[17]; /* short process name */
    unsigned short local_port; /* local port (host byte order) */
    char local_ip[32]; /* local IP (e.g., "127.0.0.1") */
    unsigned short remote_port; /* remote port (host byte order) */
    char remote_ip[32]; /* remote IP (e.g., "8.8.8.8") */
    char inode[32]; /* socket inode for reference */
} Socket;

/* Comparator for qsort by PID, then local_port */
static int pid_cmp(const void *a, const void *b) {
    const struct Socket *pa = a;
    const struct Socket *pb = b;
    if (pa->pid != pb->pid) return pa->pid - pb->pid;
    return pa->local_port - pb->local_port;
}

/*
Scanner: UDP sockets (with process PID/comm)
Parses /proc/net/udp for all entries, collects inode, local/remote IP/port.
Then scans all /proc/<pid>/fd to match socket:[inode] and associate PID/comm.
Output: JSON array of {pid, comm, local_ip, local_port, remote_ip, remote_port, inode} for each UDP socket.
Note: Run as root to see all (some /proc/pid/fd restricted).
Only IPv4 for simplicity; add IPv6 from /proc/net/udp6 if needed.
Remote IP/port may be "0.0.0.0:0" for unbound/listening sockets.
*/
void scan_udp_sockets(void)
{
    /* Step 1: Parse /proc/net/udp for all sockets + inodes */
    FILE *udp = fopen("/proc/net/udp", "re");
    if (!udp) {
        perror("fopen /proc/net/udp");
        printf("[]\n");
        return;
    }
    char line[1024];
    Socket *sockets = NULL;
    size_t sock_capacity = 0;
    size_t sock_count = 0;
    /* Skip header */
    fgets(line, sizeof(line), udp);
    while (fgets(line, sizeof(line), udp)) {
        unsigned int local_ip_hex;
        unsigned short local_port_hex;
        unsigned int remote_ip_hex;
        unsigned short remote_port_hex;
        char inode_str[32];
        /* Corrected sscanf: skip to inode properly (7 skips after st) */
        if (sscanf(line, "%*d: %8X:%4hX %8X:%4hX %*2X %*s %*s %*s %*s %*s %*s %*s %31s",
                &local_ip_hex, &local_port_hex, &remote_ip_hex, &remote_port_hex, inode_str) != 5) {
            continue;
        }
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
        /* Grow sockets array */
        if (sock_count >= sock_capacity) {
            sock_capacity = sock_capacity ? sock_capacity * 2 : 128;
            Socket *new_socks = realloc(sockets, sock_capacity * sizeof(Socket));
            if (!new_socks) break;
            sockets = new_socks;
        }
        sockets[sock_count].pid = 0; /* To be filled */
        memset(sockets[sock_count].comm, 0, sizeof(sockets[sock_count].comm));
        sockets[sock_count].local_port = local_port_hex;
        snprintf(sockets[sock_count].local_ip, sizeof(sockets[sock_count].local_ip), "%s", local_ip);
        sockets[sock_count].remote_port = remote_port_hex;
        snprintf(sockets[sock_count].remote_ip, sizeof(sockets[sock_count].remote_ip), "%s", remote_ip);
        snprintf(sockets[sock_count].inode, sizeof(sockets[sock_count].inode), "%s", inode_str);
        sock_count++;
    }
    fclose(udp);
    if (sock_count == 0) {
        free(sockets);
        printf("[]\n");
        return;
    }
    /* Step 2: Scan all processes to find who owns each inode */
    DIR *proc = opendir("/proc");
    if (!proc) {
        perror("opendir /proc");
        free(sockets);
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
            /* Match against sockets */
            for (size_t k = 0; k < sock_count; k++) {
                if (sockets[k].pid == 0 && strcmp(inode_str, sockets[k].inode) == 0) {
                    sockets[k].pid = pid;
                    snprintf(sockets[k].comm, sizeof(sockets[k].comm), "%s", comm);
                    break; /* Assume one owner per inode */
                }
            }
        }
        closedir(fddir);
    }
    closedir(proc);
    /* Sort by PID then local_port */
    qsort(sockets, sock_count, sizeof(Socket), pid_cmp);
    /* === OUTPUT – replace this block with your database insert === */
    printf("[\n");
    for (size_t i = 0; i < sock_count; i++) {
        /* Skip if pid not found (e.g., permission issues) */
        if (sockets[i].pid == 0) continue;
        printf(" {\"pid\":%d,\"comm\":\"%s\",\"local_ip\":\"%s\",\"local_port\":%hu,\"remote_ip\":\"%s\",\"remote_port\":%hu,\"inode\":\"%s\"}",
            sockets[i].pid, sockets[i].comm, sockets[i].local_ip, sockets[i].local_port,
            sockets[i].remote_ip, sockets[i].remote_port, sockets[i].inode);
        if (i < sock_count - 1) printf(",");
        printf("\n");
    }
    printf("]\n");
    /* Example DB-style replacement:
    for (size_t i = 0; i < sock_count; i++) {
        if (sockets[i].pid == 0) continue;
        db_insert_udp_socket(sockets[i].pid, sockets[i].comm,
                             sockets[i].local_ip, sockets[i].local_port,
                             sockets[i].remote_ip, sockets[i].remote_port,
                             sockets[i].inode);
    }
    */
    free(sockets);
}

int main(void)
{
    scan_udp_sockets();
    return 0;
}
