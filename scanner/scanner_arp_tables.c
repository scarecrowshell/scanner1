#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/* Struct for ARP entry */
typedef struct ArpEntry {
    char ip[INET_ADDRSTRLEN];
    char mac[18]; /* xx:xx:xx:xx:xx:xx\0 */
    char iface[32];
    char flags[16]; /* e.g., "0x2" (hex string) */
} ArpEntry;

/* Comparator for qsort by iface, then ip */
static int arp_cmp(const void *a, const void *b) {
    const struct ArpEntry *pa = a;
    const struct ArpEntry *pb = b;
    int cmp = strcmp(pa->iface, pb->iface);
    if (cmp != 0) return cmp;
    return strcmp(pa->ip, pb->ip);
}

/*
Scanner: ARP table / neighbors (ip, mac, iface, flags)
Parses /proc/net/arp for IPv4 ARP cache entries.
MAC formatted as "xx:xx:xx:xx:xx:xx".
Flags as hex string (e.g., "0x2" for permanent).
Output: JSON array of {ip, mac, iface, flags} for each entry.
Note: Only complete entries (with MAC != "00:00:00:00:00:00"). IPv4 only.
Run as root if needed for full access.
*/
void scan_arp_table(void)
{
    FILE *arp = fopen("/proc/net/arp", "re");
    if (!arp) {
        perror("fopen /proc/net/arp");
        printf("[]\n");
        return;
    }

    ArpEntry *entries = NULL;
    size_t entry_capacity = 0;
    size_t entry_count = 0;

    char line[1024];
    /* Skip header */
    fgets(line, sizeof(line), arp);
    while (fgets(line, sizeof(line), arp)) {
        char ip_str[INET_ADDRSTRLEN];
        char hw_type[16];
        char flags_str[16];
        char mac_str[18];
        char mask[16];
        char iface[32];

        if (sscanf(line, "%15s %15s %15s %17s %15s %31s",
                   ip_str, hw_type, flags_str, mac_str, mask, iface) != 6) {
            continue;
        }

        /* Skip incomplete entries (MAC all zeros) */
        if (strcmp(mac_str, "00:00:00:00:00:00") == 0) continue;

        /* Grow entries array */
        if (entry_count >= entry_capacity) {
            entry_capacity = entry_capacity ? entry_capacity * 2 : 128;
            ArpEntry *new_entries = realloc(entries, entry_capacity * sizeof(ArpEntry));
            if (!new_entries) break;
            entries = new_entries;
        }

        snprintf(entries[entry_count].ip, sizeof(entries[entry_count].ip), "%s", ip_str);
        snprintf(entries[entry_count].mac, sizeof(entries[entry_count].mac), "%s", mac_str);
        snprintf(entries[entry_count].iface, sizeof(entries[entry_count].iface), "%s", iface);
        snprintf(entries[entry_count].flags, sizeof(entries[entry_count].flags), "%s", flags_str);
        entry_count++;
    }
    fclose(arp);

    if (entry_count == 0) {
        free(entries);
        printf("[]\n");
        return;
    }

    /* Sort by iface then ip */
    qsort(entries, entry_count, sizeof(ArpEntry), arp_cmp);

    /* Output JSON */
    printf("[\n");
    for (size_t i = 0; i < entry_count; i++) {
        printf(" {\"ip\":\"%s\",\"mac\":\"%s\",\"iface\":\"%s\",\"flags\":\"%s\"}",
               entries[i].ip, entries[i].mac, entries[i].iface, entries[i].flags);
        if (i < entry_count - 1) printf(",");
        printf("\n");
    }
    printf("]\n");

    /* Example DB-style replacement:
    for (size_t i = 0; i < entry_count; i++) {
        db_insert_arp_entry(entries[i].ip, entries[i].mac, entries[i].iface, entries[i].flags);
    }
    */

    free(entries);
}

int main(void)
{
    scan_arp_table();
    return 0;
}
