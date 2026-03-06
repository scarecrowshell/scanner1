#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <unistd.h> /* for close */

/* Struct for network interface info */
typedef struct Interface {
    char name[IF_NAMESIZE];
    char ip[INET_ADDRSTRLEN];
    char mac[18]; /* xx:xx:xx:xx:xx:xx\0 */
    char status[32];
} Interface;

/* Comparator for qsort by name */
static int name_cmp(const void *a, const void *b) {
    const struct Interface *pa = a;
    const struct Interface *pb = b;
    return strcmp(pa->name, pb->name);
}

/*
Scanner: Network interfaces (name, IP, MAC, status)
Uses getifaddrs to list interfaces and IPv4 addresses (first one per interface).
Uses ioctl to get MAC address.
Status based on IFF_UP flag (simple "up" or "down").
Output: JSON array of {name, ip, mac, status} for each interface.
Note: IPv4 only for simplicity (ip="" if none). MAC "unknown" if ioctl fails.
Run as root if needed for some interfaces.
*/
void scan_network_interfaces(void)
{
    struct ifaddrs *ifap = NULL;
    if (getifaddrs(&ifap) != 0) {
        perror("getifaddrs");
        printf("[]\n");
        return;
    }

    Interface *interfaces = NULL;
    size_t intf_capacity = 0;
    size_t intf_count = 0;

    /* Collect unique interfaces and set ip/status */
    for (struct ifaddrs *ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name) continue;

        /* Check if interface already added */
        size_t idx;
        int exists = 0;
        for (idx = 0; idx < intf_count; idx++) {
            if (strcmp(interfaces[idx].name, ifa->ifa_name) == 0) {
                exists = 1;
                break;
            }
        }

        if (!exists) {
            /* Grow array */
            if (intf_count >= intf_capacity) {
                intf_capacity = intf_capacity ? intf_capacity * 2 : 128;
                Interface *new_intfs = realloc(interfaces, intf_capacity * sizeof(Interface));
                if (!new_intfs) {
                    freeifaddrs(ifap);
                    free(interfaces);
                    printf("[]\n");
                    return;
                }
                interfaces = new_intfs;
            }

            /* Add new interface */
            memset(&interfaces[intf_count], 0, sizeof(Interface));
            snprintf(interfaces[intf_count].name, sizeof(interfaces[intf_count].name), "%s", ifa->ifa_name);
            interfaces[intf_count].ip[0] = '\0';
            interfaces[intf_count].mac[0] = '\0';
            strcpy(interfaces[intf_count].status, (ifa->ifa_flags & IFF_UP) ? "up" : "down");
            idx = intf_count++;
        }

        /* Set IPv4 address if available and not set yet */
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET && strlen(interfaces[idx].ip) == 0) {
            inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr,
                      interfaces[idx].ip, sizeof(interfaces[idx].ip));
        }
    }
    freeifaddrs(ifap);

    if (intf_count == 0) {
        free(interfaces);
        printf("[]\n");
        return;
    }

    /* Get MAC addresses using ioctl */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
    } else {
        for (size_t i = 0; i < intf_count; i++) {
            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interfaces[i].name);
            if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
                // perror("ioctl"); /* Uncomment if debugging */
                strcpy(interfaces[i].mac, "unknown");
                continue;
            }
            unsigned char *hw = (unsigned char *)ifr.ifr_hwaddr.sa_data;
            snprintf(interfaces[i].mac, sizeof(interfaces[i].mac),
                     "%02x:%02x:%02x:%02x:%02x:%02x",
                     hw[0], hw[1], hw[2], hw[3], hw[4], hw[5]);
        }
        close(sock);
    }

    /* Sort by name */
    qsort(interfaces, intf_count, sizeof(Interface), name_cmp);

    /* Output JSON */
    printf("[\n");
    for (size_t i = 0; i < intf_count; i++) {
        printf(" {\"name\":\"%s\",\"ip\":\"%s\",\"mac\":\"%s\",\"status\":\"%s\"}",
               interfaces[i].name, interfaces[i].ip, interfaces[i].mac, interfaces[i].status);
        if (i < intf_count - 1) printf(",");
        printf("\n");
    }
    printf("]\n");

    /* Example DB-style replacement:
    for (size_t i = 0; i < intf_count; i++) {
        db_insert_network_interface(interfaces[i].name, interfaces[i].ip,
                                    interfaces[i].mac, interfaces[i].status);
    }
    */

    free(interfaces);
}

int main(void)
{
    scan_network_interfaces();
    return 0;
}
