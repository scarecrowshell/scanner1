#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/route.h> /* for rt_flags */

/* Struct for routing entry */
typedef struct Route {
    char iface[32];
    char destination[INET_ADDRSTRLEN];
    char gateway[INET_ADDRSTRLEN];
    char netmask[INET_ADDRSTRLEN];
    char flags[16]; /* e.g., "UG" */
    int metric;
} Route;

/* Comparator for qsort by iface, then destination */
static int route_cmp(const void *a, const void *b) {
    const struct Route *pa = a;
    const struct Route *pb = b;
    int cmp = strcmp(pa->iface, pb->iface);
    if (cmp != 0) return cmp;
    return strcmp(pa->destination, pb->destination);
}

/*
Scanner: Routing table (iface, destination, gateway, netmask, flags, metric)
Parses /proc/net/route for IPv4 routes.
Converts hex IPs to dotted decimal.
Flags as string (e.g., "UG" for up/gateway).
Output: JSON array of {iface, destination, gateway, netmask, flags, metric} for each route.
Note: Only active routes (flags & RTF_UP). IPv4 only.
*/
void scan_routing_table(void)
{
    FILE *route = fopen("/proc/net/route", "re");
    if (!route) {
        perror("fopen /proc/net/route");
        printf("[]\n");
        return;
    }

    Route *routes = NULL;
    size_t route_capacity = 0;
    size_t route_count = 0;

    char line[1024];
    /* Skip header */
    fgets(line, sizeof(line), route);
    while (fgets(line, sizeof(line), route)) {
        char iface[32];
        unsigned int dest_hex, gate_hex, mask_hex;
        unsigned int flags_hex;
        int ref, use, metric;
        if (sscanf(line, "%31s %8X %8X %4X %d %d %d %8X",
                   iface, &dest_hex, &gate_hex, &flags_hex, &ref, &use, &metric, &mask_hex) != 8) {
            continue;
        }
        if (!(flags_hex & RTF_UP)) continue; /* Skip down routes */

        /* Convert hex to dotted IP */
        struct in_addr addr;
        char dest_ip[INET_ADDRSTRLEN];
        addr.s_addr = htonl(dest_hex);
        inet_ntop(AF_INET, &addr, dest_ip, sizeof(dest_ip));

        char gate_ip[INET_ADDRSTRLEN];
        addr.s_addr = htonl(gate_hex);
        inet_ntop(AF_INET, &addr, gate_ip, sizeof(gate_ip));

        char mask_ip[INET_ADDRSTRLEN];
        addr.s_addr = htonl(mask_hex);
        inet_ntop(AF_INET, &addr, mask_ip, sizeof(mask_ip));

        /* Flags string */
        char flags_str[16] = "";
        if (flags_hex & RTF_UP) strcat(flags_str, "U");
        if (flags_hex & RTF_GATEWAY) strcat(flags_str, "G");
        if (flags_hex & RTF_HOST) strcat(flags_str, "H");
        if (flags_hex & RTF_REINSTATE) strcat(flags_str, "R");
        if (flags_hex & RTF_DYNAMIC) strcat(flags_str, "D");
        if (flags_hex & RTF_MODIFIED) strcat(flags_str, "M");

        /* Grow routes array */
        if (route_count >= route_capacity) {
            route_capacity = route_capacity ? route_capacity * 2 : 128;
            Route *new_routes = realloc(routes, route_capacity * sizeof(Route));
            if (!new_routes) break;
            routes = new_routes;
        }

        snprintf(routes[route_count].iface, sizeof(routes[route_count].iface), "%s", iface);
        snprintf(routes[route_count].destination, sizeof(routes[route_count].destination), "%s", dest_ip);
        snprintf(routes[route_count].gateway, sizeof(routes[route_count].gateway), "%s", gate_ip);
        snprintf(routes[route_count].netmask, sizeof(routes[route_count].netmask), "%s", mask_ip);
        snprintf(routes[route_count].flags, sizeof(routes[route_count].flags), "%s", flags_str);
        routes[route_count].metric = metric;
        route_count++;
    }
    fclose(route);

    if (route_count == 0) {
        free(routes);
        printf("[]\n");
        return;
    }

    /* Sort by iface then destination */
    qsort(routes, route_count, sizeof(Route), route_cmp);

    /* Output JSON */
    printf("[\n");
    for (size_t i = 0; i < route_count; i++) {
        printf(" {\"iface\":\"%s\",\"destination\":\"%s\",\"gateway\":\"%s\",\"netmask\":\"%s\",\"flags\":\"%s\",\"metric\":%d}",
               routes[i].iface, routes[i].destination, routes[i].gateway, routes[i].netmask, routes[i].flags, routes[i].metric);
        if (i < route_count - 1) printf(",");
        printf("\n");
    }
    printf("]\n");

    /* Example DB-style replacement:
    for (size_t i = 0; i < route_count; i++) {
        db_insert_route(routes[i].iface, routes[i].destination, routes[i].gateway,
                        routes[i].netmask, routes[i].flags, routes[i].metric);
    }
    */

    free(routes);
}

int main(void)
{
    scan_routing_table();
    return 0;
}
