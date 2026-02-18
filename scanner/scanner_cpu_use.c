                        #include <stdio.h>
                        #include <dirent.h>
                        #include <stdlib.h>
                        #include <ctype.h>
                        #include <string.h>
                        #include <unistd.h>     /* for sysconf(_SC_CLK_TCK) */

                        #define CLK_TCK sysconf(_SC_CLK_TCK)

                        /* Comparator for qsort by PID */
                        static int pid_cmp(const void *a, const void *b) {
                            return (*(const int *)a) - (*(const int *)b);
                        }

                        typedef struct {
                            int   pid;
                            char  comm[17];               /* short name */
                            unsigned long utime;          /* user mode jiffies (own) */
                            unsigned long stime;          /* kernel mode jiffies (own) */
                            long          cutime;         /* user mode jiffies of reaped children */
                            long          cstime;         /* kernel mode jiffies of reaped children */
                            unsigned long total_own;      /* utime + stime */
                            unsigned long total_with_child; /* utime + stime + cutime + cstime (if reaped) */
                        } ProcCpuTime;

                        /*
                        Scanner: CPU time used (user / system / children) for all processes
                        All values in jiffies (divide by CLK_TCK to get seconds)
                        Output: JSON array → replace with DB insert
                        */
                        void scan_process_cpu_time(void)
                        {
                            if (CLK_TCK <= 0) {
                                fprintf(stderr, "sysconf(_SC_CLK_TCK) failed\n");
                                return;
                            }

                            DIR *proc = opendir("/proc");
                            if (!proc) {
                                perror("opendir /proc");
                                return;
                            }

                            ProcCpuTime *times = NULL;
                            size_t capacity = 0;
                            size_t count = 0;

                            struct dirent *ent;
                            while ((ent = readdir(proc)) != NULL) {
                                if (ent->d_type != DT_DIR) continue;
                                if (!isdigit((unsigned char)ent->d_name[0])) continue;

                                int pid = atoi(ent->d_name);
                                if (pid <= 0) continue;

                                char path[64];
                                snprintf(path, sizeof(path), "/proc/%d/stat", pid);

                                FILE *fp = fopen(path, "re");
                                if (!fp) continue;

                                int dummy_int;
                                char dummy_char;
                                char comm[17] = {0};
                                unsigned long utime = 0, stime = 0;
                                long cutime = 0, cstime = 0;

                                /* We need to skip to fields 14,15,16,17 */
                                /* Format: pid (comm) state ppid ... utime stime cutime cstime ... */
                                int scanned = fscanf(fp,
                                    "%d (%16[^)]) %c %d %*d %*d %*d %*d %*u %*u %*u %*u %*u "
                                    "%lu %lu %ld %ld",
                                    &dummy_int, comm, &dummy_char, &dummy_int,
                                    &utime, &stime, &cutime, &cstime);

                                fclose(fp);

                                if (scanned != 8) continue;  /* parsing failed or process gone */

                                /* Grow array */
                                if (count >= capacity) {
                                    capacity = capacity ? capacity * 2 : 8192;
                                    ProcCpuTime *new_times = realloc(times, capacity * sizeof(ProcCpuTime));
                                    if (!new_times) continue;
                                    times = new_times;
                                }

                                times[count].pid = pid;
                                strncpy(times[count].comm, comm, sizeof(times[count].comm) - 1);
                                times[count].comm[sizeof(times[count].comm) - 1] = '\0';

                                times[count].utime  = utime;
                                times[count].stime  = stime;
                                times[count].cutime = cutime;
                                times[count].cstime = cstime;

                                times[count].total_own        = utime + stime;
                                times[count].total_with_child = utime + stime + (unsigned long)(cutime + cstime);

                                count++;
                            }

                            closedir(proc);

                            if (count == 0) {
                                free(times);
                                printf("[]\n");
                                return;
                            }

                            /* Sort by PID */
                            qsort(times, count, sizeof(ProcCpuTime), pid_cmp);

                            /* === OUTPUT – replace this with your database insert logic === */
                            printf("[\n");
                            for (size_t i = 0; i < count; i++) {
                                printf("  {\"pid\":%d,\"comm\":\"%s\","
                                    "\"user_jiffies\":%lu,\"system_jiffies\":%lu,"
                                    "\"total_own_jiffies\":%lu,"
                                    "\"children_user_jiffies\":%ld,\"children_system_jiffies\":%ld,"
                                    "\"total_with_children_jiffies\":%lu,"
                                    "\"jiffies_per_sec\":%ld}",
                                    times[i].pid, times[i].comm,
                                    times[i].utime, times[i].stime,
                                    times[i].total_own,
                                    times[i].cutime, times[i].cstime,
                                    times[i].total_with_child,
                                    CLK_TCK);

                                if (i < count - 1) printf(",");
                                printf("\n");
                            }
                            printf("]\n");

                            /* Example DB replacement:
                            for (size_t i = 0; i < count; i++) {
                                db_insert_cpu_time(times[i].pid, times[i].comm,
                                                times[i].utime, times[i].stime, times[i].total_own,
                                                times[i].cutime, times[i].cstime,
                                                times[i].total_with_child, CLK_TCK);
                            }
                            */

                            free(times);
                        }

                        int main(void)
                        {
                            scan_process_cpu_time();
                            return 0;
                        }
