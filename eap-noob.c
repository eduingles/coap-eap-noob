/*
 * EAP peer method: EAP-NOOB
 *  Copyright (c) 2019, Aalto University
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *  * Neither the name of the Aalto University nor the
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL AALTO UNIVERSITY BE LIABLE FOR ANY
 *  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  See CONTRIBUTORS for more information.
 */

#include "eap-noob.h"
#include "include.h"
#include "jsontree.h"
#include "jsonparse.h"
#include "cfs/cfs.h"

/**
 * json_integer_value : Helper method, get int value of keys
 * @json : JSON object
 * @key : key
 * Returns : value corresponding to key
**/
static int json_integer_value(struct jsonparse_state *state, const char *str)
{
    int type;
    while((type = jsonparse_next(state)) != 0) {
        if(type == JSON_TYPE_PAIR_NAME) {
            if(jsonparse_strcmp_value(state, str) == 0) {
                jsonparse_next(state);
                return jsonparse_get_value_as_int(state);
            }
        }
    }
    return -1;
}

/**
 * jsonparse_copy_next : Copy next value fromt a JSON object
 * @js   : json object
 * @str  : destination buffer
 * @size : size of the destination buffer
 **/
void jsonparse_copy_next(struct jsonparse_state *js, char *str, int size)
{
    char t = js->vtype;
    if(t == 'N' || t == '"' || t == '0' || t == 'n' || t == 't' || t == 'f') {
        jsonparse_copy_value(js, str, size);
        return;
    }
    int d = 0;
    int i = 0;
    int v = 0;

    int type = jsonparse_get_type(js);

    char c;
    do {
        c = js->json[js->pos + i - 1];
        switch (c) {
            case '{': case '[':
                d++; v++;
                break;
            case '}': case ']':
                d--; v++;
                break;
            case ',':
                v += 4;
                break;
        }
        str[i++] = c;
    } while (d > 0);
    str[i++] = 0;
    if (strcmp(str, "[]")) v++;
    for(; v > 0; v--)
        jsonparse_next(js);
}

/**
 * initMethodEap :
**/
void initMethodEap()
{
}

/**
 * check :
 * @eapReqData : EAP request data
 * Returns :
**/
uint8_t check(const uint8_t *eapReqData)
{
	return (reqMethod == EAP_NOOB) ? TRUE : FALSE;
}

/**
 * write_db : Write data to database
 * @database : database name
 * @key : key
 * @val : value
 * Returns : 1 or 0
**/
int write_db(char *database, char *key , char *val)
{
    int db;
    if ((db = cfs_open(database, CFS_WRITE | CFS_APPEND)) >= 0) {
        cfs_write(db, key, strlen(key));
        cfs_write(db, ":", 1);
        cfs_write(db, val, strlen(val));
        cfs_write(db, "\n", 1);
        cfs_close(db);
    } else {
        DEBUG("Could not open database");
        return 0;
    }
    return 1;
}

/**
 * eap_noob_req_type_one : Decode request type one
 * @data :
 * @size :
 * Returns :
**/
void eap_noob_req_type_one(char *data, size_t size)
{
    struct jsonparse_state js;
    jsonparse_setup(&js, data, size);
    int type;
    char output[2][512];
    while((type = jsonparse_next(&js)) != 0) {
        if(type == JSON_TYPE_PAIR_NAME) {
            jsonparse_copy_next(&js, output[0], size);
            jsonparse_next(&js);
            jsonparse_copy_next(&js, output[1], size);
            write_db(DB_NAME, output[0], output[1]);
        }
    }
    // TEST //
    char tmp[size];
    int db;
    if ((db = cfs_open(DB_NAME, CFS_READ)) >= 0) {
        cfs_read(db, tmp, size);
        cfs_close(db);
    }
    printf("Database after parsing request 1: \n%s", tmp);
    // TEST //
}

/**
 * eap_noob_process :
 * @eapReqData : EAP request data
 * @methodState :
 * @decision :
**/
void eap_noob_process(const uint8_t *eapReqData, uint8_t *methodState, uint8_t *decision)
{
    if (reqMethod == EAP_NOOB && reqCode == REQUEST_CODE) {
        char *data;
        size_t size;

        size = NTOHS(reqLength) - 5;
        data = (char *) malloc(size);

        memcpy(data, eapReqData+5, NTOHS(reqLength));

        struct jsonparse_state req_obj;
        jsonparse_setup(&req_obj, data, size);

        *(methodState) = CONT;
        *(decision) = FAIL;

        int msgtype;
        msgtype = json_integer_value(&req_obj, "Type");

        switch (msgtype) {
            case EAP_NOOB_TYPE_1:
                DEBUG("Message type 1");
                eap_noob_req_type_one(data, size);
                break;
            case EAP_NOOB_TYPE_2:
            case EAP_NOOB_TYPE_3:
            case EAP_NOOB_TYPE_4:
            case EAP_NOOB_TYPE_5:
            case EAP_NOOB_TYPE_6:
            case EAP_NOOB_TYPE_7:
            default:
                DEBUG("Unknown EAP-NOOB request received");
                break;
        }
        free(data);
	}
}

/**
 * eap_noob_buildResp :
 * @eapReqData : EAP request data
 * @identifier :
**/
void eap_noob_buildResp(uint8_t *eapRespData, const uint8_t identifier)
{
}
