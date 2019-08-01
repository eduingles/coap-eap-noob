#include "database.h"

#if EDU_DEBUG
    //Stack guard
    // #include "sys/stack-check.h"
#endif

/**
 * write_db : Write data to database
 * @db_name : database file
 * @key : key
 * @val : value
 * Returns : 1 or -1
**/
int write_db(char *db_name, char *key , char *val)
{
    int db;
    if ((db = cfs_open(db_name, CFS_WRITE | CFS_APPEND)) >= 0) {
        cfs_write(db, key, strlen(key));
        cfs_write(db, ";", 1);
        cfs_write(db, val, strlen(val));
        cfs_write(db, "\n", 1);
        cfs_close(db);
    } else {
        DEBUG_MSG_DB("Could not open database");
        return -1;
    }
    return 1;
}

/**
 * read_db : Read data from database
 * @db_name : database file
 * @key : key
 * @val : value
 * Returns : 1 or -1
**/
int read_db(char *db_name, char *key, char *val)
{
    int db;
    if ((db = cfs_open(db_name, CFS_READ)) >= 0) {
        // Read the entire database
        size_t size = cfs_seek(db, 0, CFS_SEEK_END);
        cfs_seek(db, 0, CFS_SEEK_SET);
        char dst[size];
        cfs_read(db, dst, size);
        cfs_close(db);
        // Find value in database
    	char *current_key = strtok(dst, ";\n");
    	while(current_key != NULL) {
            char *current_val = strtok(NULL, ";\n");
            if (!strcmp(current_key, key)) {
                memcpy(val, current_val, strlen(current_val) + 1);
                return 1;
            }
            current_key = strtok(NULL, ";\n");
    	}
        printf("Value for \"%s\" not found in database \"%s\"\n", key, db_name);
        return -1;
    } else {
        DEBUG_MSG_DB("Could not open database");
        return -1;
    }
}

/**
 * print_db : Print database to stdout
 * @db_name : database file
 * TEMPORARY - FOR DEBUGGING PURPOSES
**/
void print_db(char *db_name)
{
    int db;
    if ((db = cfs_open(db_name, CFS_READ)) >= 0) {
        size_t size = cfs_seek(db, 0, CFS_SEEK_END);
        cfs_seek(db, 0, CFS_SEEK_SET);
        char dst[size];
        cfs_read(db, dst, size);
        cfs_close(db);
        printf("--------------------DATABASE--------------------\n");
        printf("%s", dst);
        printf("------------------------------------------------\n");
    } else {
        DEBUG_MSG_DB("Could not open database");
    }
}
