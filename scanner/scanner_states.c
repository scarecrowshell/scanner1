                        #include <stdio.h>
                        #include <dirent.h>
                        #include <stdlib.h>
                        #include <ctype.h>
                        #include <string.h>

                        /* Comparator for qsort by PID */
                        static int pid_cmp(const void *a, const void *b) {
                            return (*(const int *)a) - (*(const int *)b);
                        }

                        typedef struct {
                            int   pid;
                            char  comm[17];     /* TASK_COMM_LEN = 16 + '\0' */
                            char  state;        /* single char from /proc/pid/stat field 3 */
                            char  state_desc[48]; /* human-readable explanation */
                        } ProcState;

                        /* Map single-letter state → readable description */
                        static const char *get_state_description(char state) {
                            switch (state) {
                                case 'R': return "Running or runnable (on CPU/run queue)";
                                case 'S': return "Sleeping (interruptible wait)";
                                case 'D': return "Uninterruptible sleep (usually I/O)";
                                case 'Z': return "Zombie (defunct, waiting to be reaped)";
                                case 'T': return "Stopped (job control signal or trace)";
                                case 't': return "Tracing stop (ptrace)";
                                case 'I': return "Idle kernel thread";
                                case 'X': return "Dead (should never be visible)";
                                case 'x': return "Dead (old kernel transitional state)";
                                case 'K': return "Wakekill (rare, old kernels)";
                                case 'W': return "Waking / paging (very old kernels)";
                                default:  return "Unknown / other state";
                            }
                        }

                        /*
                        Scanner: Process state for all running processes
                        Reads state char from /proc/<pid>/stat (field 3)
                        Output: JSON array → easy to insert into DB
                        */
                        void scan_process_states(void)
                        {
                            DIR *proc = opendir("/proc");
                            if (!proc) {
                                perror("opendir /proc");
                                return;
                            }

                            ProcState *states = NULL;
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

                                int real_pid;
                                char comm[17] = {0};
                                char state_char = '?';

                                /* Format: pid (comm) state ... */
                                if (fscanf(fp, "%d (%16[^)]) %c",
                                        &real_pid, comm, &state_char) != 3) {
                                    fclose(fp);
                                    continue;
                                }

                                fclose(fp);

                                /* Grow array if needed */
                                if (count >= capacity) {
                                    capacity = capacity ? capacity * 2 : 8192;
                                    ProcState *new_states = realloc(states, capacity * sizeof(ProcState));
                                    if (!new_states) continue;
                                    states = new_states;
                                }

                                states[count].pid   = pid;
                                strncpy(states[count].comm, comm, sizeof(states[count].comm) - 1);
                                states[count].comm[sizeof(states[count].comm) - 1] = '\0';
                                states[count].state = state_char;
                                strncpy(states[count].state_desc, get_state_description(state_char),
                                        sizeof(states[count].state_desc) - 1);
                                states[count].state_desc[sizeof(states[count].state_desc) - 1] = '\0';

                                count++;
                            }

                            closedir(proc);

                            if (count == 0) {
                                free(states);
                                printf("[]\n");
                                return;
                            }

                            /* Sort by PID for consistent output */
                            qsort(states, count, sizeof(ProcState), pid_cmp);

                            /* === OUTPUT – replace with your DB insert code === */
                            printf("[\n");
                            for (size_t i = 0; i < count; i++) {
                                printf("  {\"pid\":%d,\"comm\":\"%s\",\"state\":\"%c\",\"description\":\"%s\"}",
                                    states[i].pid,
                                    states[i].comm,
                                    states[i].state,
                                    states[i].state_desc);

                                if (i < count - 1) printf(",");
                                printf("\n");
                            }
                            printf("]\n");

                            /* Example DB replacement loop:
                            for (size_t i = 0; i < count; i++) {
                                db_insert_state(states[i].pid,
                                                states[i].comm,
                                                states[i].state,
                                                states[i].state_desc);
                            }
                            */

                            free(states);
                        }

                        int main(void)
                        {
                            scan_process_states();
                            return 0;
                        }
