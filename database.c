#include "database.h"

/**
 * write_db : Write data to database
 * @key : key
 * @val : value
 * Returns : 1 or -1
**/
int write_db(char *key , char *val)
{
    int db;
    if ((db = cfs_open(DB_NAME, CFS_WRITE | CFS_APPEND)) >= 0) {
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
 * write_db_kdf : Write KDF array of bytes to database
 * @val : kdy value
 * Returns : 1 or -1
**/
int write_db_kdf(unsigned char *val)
{
    int db;
    if ((db = cfs_open(DB_NAME_KDF, CFS_WRITE)) >= 0) {
        cfs_write(db, val, 321);
        cfs_close(db);
    } else {
        DEBUG_MSG_DB("Could not open KDF database");
        return -1;
    }
    return 1;
}

/**
 * read_db : Read data from database
 * @key : key
 * @val : value
 * Returns : 1 or -1
**/
int read_db(char *key, char *val)
{
    int db;
    if ((db = cfs_open(DB_NAME, CFS_READ)) >= 0) {
        // Read the entire database
        size_t size = cfs_seek(db, 0, CFS_SEEK_END);
        cfs_seek(db, 0, CFS_SEEK_SET);
        char dst[size];
        cfs_read(db, dst, size);
        cfs_close(db);
        // Find value in database
    	char *current_line = strtok(dst, "\n");
    	while(current_line != NULL) {
            char *current_key = strtok(NULL, ";");
            char *current_val = strtok(NULL, "\n");
            if (!strcmp(current_key, key)) {
                memcpy(val, current_val, strlen(current_val) + 1);
                return 1;
            }
    	}
        return -1;
    } else {
        DEBUG_MSG_DB("Could not open database");
        return -1;
    }
}

/**
 * read_db_kdf : Read data from database
 * @val : value
 * Returns : 1 or -1
**/
int read_db_kdf(unsigned char *val)
{
    int db;
    if ((db = cfs_open(DB_NAME_KDF, CFS_READ)) >= 0) {
        // Read the entire database
        size_t size = cfs_seek(db, 0, CFS_SEEK_END);
        if (size != 321) {
            printf("KDF size not matching: %d - It should be 321\n", size);
            return -1;
        }
        cfs_seek(db, 0, CFS_SEEK_SET);
        cfs_read(db, val, size);
        cfs_close(db);
        return 1;
    } else {
        DEBUG_MSG_DB("Could not open database");
        return -1;
    }

}

/**
 * print_db : Print database to stdout
 * TEMPORARY - FOR DEBUGGING PURPOSES
**/
void print_db(void)
{
    int db;
    if ((db = cfs_open(DB_NAME, CFS_READ)) >= 0) {
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
