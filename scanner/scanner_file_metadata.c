#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>

/* File info structure MUST be defined before comparator */
typedef struct {
    char path[PATH_MAX];
    off_t size;
    mode_t mode;
    uid_t uid;
    gid_t gid;
    time_t mtime;
    time_t ctime;
    time_t atime;
} FileInfo;


/* Comparator for qsort by path */
static int path_cmp(const void *a, const void *b) {
    return strcmp(((const FileInfo *)a)->path,
                  ((const FileInfo *)b)->path);
}


/* Recursive scanner */
static void scan_dir(const char *dir, FileInfo **files,
                     size_t *count, size_t *capacity)
{
    DIR *d = opendir(dir);
    if (!d)
        return;

    struct dirent *e;

    while ((e = readdir(d)) != NULL) {

        if (!strcmp(e->d_name,".") || !strcmp(e->d_name,".."))
            continue;

        char full[PATH_MAX];

        if (snprintf(full,sizeof(full),"%s/%s",dir,e->d_name) < 0)
            continue;

        struct stat st;

        if (lstat(full,&st) < 0)
            continue;


        /* Grow array */
        if (*count >= *capacity) {

            *capacity = *capacity ? *capacity*2 : 8192;

            FileInfo *tmp =
                realloc(*files,*capacity*sizeof(FileInfo));

            if (!tmp) {
                closedir(d);
                return;
            }

            *files = tmp;
        }


        /* Safe path copy (no strncpy warning) */

        size_t len = strlen(full);

        if (len >= PATH_MAX)
            len = PATH_MAX-1;

        memcpy((*files)[*count].path,full,len);

        (*files)[*count].path[len] = 0;


        (*files)[*count].size = st.st_size;
        (*files)[*count].mode = st.st_mode & 07777;
        (*files)[*count].uid = st.st_uid;
        (*files)[*count].gid = st.st_gid;
        (*files)[*count].mtime = st.st_mtime;
        (*files)[*count].ctime = st.st_ctime;
        (*files)[*count].atime = st.st_atime;

        (*count)++;


        if (S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode))
            scan_dir(full,files,count,capacity);
    }

    closedir(d);
}



/* Main scanner */
void scan_file_metadata(const char *start_dir)
{
    FileInfo *files=NULL;

    size_t capacity=0;
    size_t count=0;

    scan_dir(start_dir,&files,&count,&capacity);


    if (!count) {

        free(files);

        printf("[]\n");

        return;
    }


    qsort(files,count,sizeof(FileInfo),path_cmp);


    printf("[\n");

    for (size_t i=0;i<count;i++) {

        char mode[6];

        snprintf(mode,sizeof(mode),"%04o",files[i].mode);


        printf("  {\"path\":\"");

        for (char *p=files[i].path;*p;p++){

            if (*p=='"' || *p=='\\')
                putchar('\\');

            putchar(*p);
        }


        printf("\",\"size\":%lld,"
               "\"mode\":\"%s\","
               "\"uid\":%u,"
               "\"gid\":%u,"
               "\"mtime\":%ld,"
               "\"ctime\":%ld,"
               "\"atime\":%ld}",

               (long long)files[i].size,
               mode,
               files[i].uid,
               files[i].gid,
               (long)files[i].mtime,
               (long)files[i].ctime,
               (long)files[i].atime);


        if (i<count-1)
            printf(",");

        printf("\n");
    }

    printf("]\n");


    free(files);
}



int main(int argc,char **argv)
{
    const char *dir = (argc>1) ? argv[1] : ".";

    scan_file_metadata(dir);

    return 0;
}
