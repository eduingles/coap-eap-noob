#include "database.h"

#if EDU_DEBUG
    //Stack guard
    // #include "sys/stack-check.h"
#endif

// TODO: write base64 with the '='

/**
 * write_db : Write data to database
 * @db_name : database file
 * @key : key
 * @val_len : length of the value
 * @val : value
 * Returns : 1 or -1
**/
int write_db(char *db_name, char *key, size_t val_len, char *val)
{
    char len[3];
    sprintf(len, "%d", val_len);
    int db;
    if ((db = cfs_open(db_name, CFS_WRITE | CFS_APPEND)) >= 0) {
        cfs_write(db, key, strlen(key));
        cfs_write(db, ";", 1);
        cfs_write(db, len, strlen(len));
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
        int pos = 0;
        char tmp[CHUNK_SIZE];
        while (1) {
            // Read next chunk
            if (cfs_read(db, tmp, CHUNK_SIZE) <= 0)
                break;
            // Find value in database
            char *current_key = strtok(tmp, ";\n");  // Current key
            char *current_len = strtok(NULL, ";\n"); // Length of the value
            size_t len = atoi(current_len);
            if (!strcmp(current_key, key)) {
                // key + ';' + value length + ';'
                pos += strlen(current_key)+1+strlen(current_len)+1;
                char current_val[len+1];
                cfs_seek(db, pos, CFS_SEEK_SET);
                cfs_read(db, current_val, len);
                current_val[len] = '\0';
                memcpy(val, current_val, strlen(current_val) + 1);
                cfs_close(db);
                return 1;
            } else {
                // key +  ';' + value length + ';' + value + '\n'
                pos += strlen(current_key)+1+strlen(current_len)+1+len+1;
                cfs_seek(db, pos, CFS_SEEK_SET);
            }
        }
        cfs_close(db);
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
        char dst[size+1];
        cfs_read(db, dst, size);
        dst[size] = '\0';
        cfs_close(db);
        printf("--------------------DATABASE--------------------\n");
        printf("%s", dst);
        printf("------------------------------------------------\n");
    } else {
        DEBUG_MSG_DB("Could not open database");
    }
}
