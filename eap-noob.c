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
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL AALTO UNIVERSITY BE LIABLE FOR ANY
 *  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 *  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  See CONTRIBUTORS for more information.
 */

#include "eap-noob.h"
#include "include.h"
#include "jsonparse.h"
#include "cfs/cfs.h"

#include <stdlib.h>

/**
 * json_integer_value : Find the associated value of key
 * @json : JSON object
 * @key : key
 * Returns : The associated value of key, -1 if not found
**/
static int json_integer_value(struct jsonparse_state *js, const char *key)
{
    int type;
    while((type = jsonparse_next(js)) != 0) {
        if(type == JSON_TYPE_PAIR_NAME) {
            if(jsonparse_strcmp_value(js, key) == 0) {
                jsonparse_next(js);
                return jsonparse_get_value_as_int(js);
            }
        }
    }
    return -1;
}

/**
 * jsonparse_copy_next : Copy next value from js to dst
 * @js   : JSON object
 * @dst  : destination array
 * @size : size of the destination array
 **/
static void jsonparse_copy_next(struct jsonparse_state *js, char *dst, int size)
{
    char t = js->vtype;
    if(t == 'N' || t == '"' || t == '0' || t == 'n' || t == 't' || t == 'f') {
        jsonparse_copy_value(js, dst, size);
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
        dst[i++] = c;
    } while (d > 0);
    dst[i++] = 0;
    if (strcmp(dst, "[]")) v++;
    for(; v > 0; v--)
        jsonparse_next(js);
}

/**
 * initMethodEap : Initialise EAP method
**/
void init_eap_noob()
{
    sprintf(nai, "%s", "noob@eap-noob.net");
}

/**
 * check : Check if eapReqData is an EAP-NOOB request
 * @eapReqData : EAP request data
 * Returns : TRUE or FALSE
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
 * Returns : 1 or -1
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
        DEBUG_NOOB("Could not open database");
        return 0;
    }
    return 1;
}

/**
 * eap_noob_read_config : Read configuration file
 * @js : JSON object
 **/
// static void eap_noob_read_config(struct jsonparse_state *js)
// {
//     int conf_file;
//     if ((conf_file = cfs_open(DB_NAME, CFS_READ)) >= 0) {
//         size_t size
//         size = cfs_seek(conf_file, 0, CFS_SEEK_END);
//         cfs_seek(conf_file, 0, CFS_SEEK_SET);
//         char dst[s];
//         cfs_read(conf_file, dst, s);
//         cfs_close(conf_file);
//         jsonparse_setup(&js, eapReqData, size);
//     }
// }

/**
 * print_db : Print database to stdout
 * TEMPORARY - FOR DEBUGGING PURPOSES
**/
static void print_db()
{
    int db;
    if ((db = cfs_open(DB_NAME, CFS_READ)) >= 0) {
        size_t s = cfs_seek(db, 0, CFS_SEEK_END);
        cfs_seek(db, 0, CFS_SEEK_SET);
        char dst[s];
        cfs_read(db, dst, s);
        cfs_close(db);
        printf("Database after parsing request \n%s\n", dst);
    }
}

/**
 * eap_noob_req_type_one : Decode request type one, send response
 * @eapReqData : EAP request data
 * @size : size of eapReqData
 * @id : method identifier
 * @eapRespData : EAP response data
**/
void eap_noob_req_type_one(char *eapReqData, const size_t size, const uint8_t id, uint8_t *eapRespData)
{
    // Parse request
    struct jsonparse_state js;
    jsonparse_setup(&js, eapReqData, size);
    int type;
    char peerid[24];
    char tmp[2][100];
    while((type = jsonparse_next(&js)) != 0) {
        if(type == JSON_TYPE_PAIR_NAME) {
            jsonparse_copy_next(&js, tmp[0], size);
            jsonparse_next(&js);
            jsonparse_copy_next(&js, tmp[1], size);
            if (!strcmp(tmp[0], "PeerId"))
                strcpy(peerid, tmp[1]);
            write_db(DB_NAME, tmp[0], tmp[1]);
        }
    }
    // Build response
    // TODO: read response values from configuration file
    char tmpResponseType1[200];
    sprintf(tmpResponseType1, "%s%s%s", "{\"Type\":1,\"Verp\":1,\"PeerId\":\"", peerid, "\",\"Cryptosuitep\":1,\"Dirp\":1,\"PeerInfo\":{\"Make\":\"Acme\",\"Type\":\"None\",\"Serial\":\"DU-9999\",\"SSID\":\"Noob1\",\"BSSID\":\"6c:19:8f:83:c2:80\"}}");

    ((struct eap_msg *)eapRespData)->code = RESPONSE_CODE;
    ((struct eap_msg *)eapRespData)->id = (uint8_t)id;
    ((struct eap_msg *)eapRespData)->length = HTONS((sizeof(struct eap_msg) + strlen(tmpResponseType1)) + 1);
    ((struct eap_msg *)eapRespData)->method = (uint8_t)EAP_NOOB;

    sprintf((char *)eapRespData + 5, "%s", (char *)tmpResponseType1);
    eapKeyAvailable = FALSE;
}

/**
 * eap_noob_req_type_two : Decode request type two, send response
 * @eapReqData : EAP request data
 * @size : size of eapReqData
 * @id : method identifier
 * @eapRespData : EAP response data
**/
void eap_noob_req_type_two(char *eapReqData, const size_t size, const uint8_t id, uint8_t *eapRespData)
{
    // Parse request
    struct jsonparse_state js;
    jsonparse_setup(&js, eapReqData, size);
    int type;
    char peerid[24];
    char tmp[2][100];
    while((type = jsonparse_next(&js)) != 0) {
        if(type == JSON_TYPE_PAIR_NAME) {
            jsonparse_copy_next(&js, tmp[0], size);
            jsonparse_next(&js);
            jsonparse_copy_next(&js, tmp[1], size);
            if (!strcmp(tmp[0], "PeerId"))
                strcpy(peerid, tmp[1]);
            else if (
                !strcmp(tmp[0], "PKs") ||
                !strcmp(tmp[0], "Ns")  ||
                !strcmp(tmp[0], "SleepTime")
            )
                write_db(DB_NAME, tmp[0], tmp[1]);
        }
    }

    // Build response
    // TODO: read response values from configuration file
    char tmpResponseType2[200];
    sprintf(tmpResponseType2, "%s%s%s", "{\"Type\":2,\"PeerId\":\"", peerid, "\",\"PKp\":{\"kty\":\"EC\",\"crv\":\"Curve25519\",\"x\":\"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08\"},\"Np\":\"HIvB6g0n2btpxEcU7YXnWB-451ED6L6veQQd6ugiPFU\"}");

    ((struct eap_msg *)eapRespData)->code = RESPONSE_CODE;
    ((struct eap_msg *)eapRespData)->id = (uint8_t)id;
    ((struct eap_msg *)eapRespData)->length = HTONS((sizeof(struct eap_msg) + strlen(tmpResponseType2)) + 1);
    ((struct eap_msg *)eapRespData)->method = (uint8_t)EAP_NOOB;

    sprintf((char *)eapRespData + 5, "%s", (char *)tmpResponseType2);
    eapKeyAvailable = FALSE;

    // Update NAI
    sprintf(nai, "%s%s", peerid, "+s1@noob.example.com");
}

/**
 * eap_noob_req_type_three : Decode request type three, send response
 * @eapReqData : EAP request data
 * @size : size of eapReqData
 * @id : method identifier
 * @eapRespData : EAP response data
**/
void eap_noob_req_type_three(char *eapReqData, const size_t size, const uint8_t id, uint8_t *eapRespData)
{
    // Parse request
    struct jsonparse_state js;
    jsonparse_setup(&js, eapReqData, size);
    int type;
    char peerid[24];
    char tmp[2][100];
    while((type = jsonparse_next(&js)) != 0) {
        if(type == JSON_TYPE_PAIR_NAME) {
            jsonparse_copy_next(&js, tmp[0], size);
            jsonparse_next(&js);
            jsonparse_copy_next(&js, tmp[1], size);
            if (!strcmp(tmp[0], "PeerId"))
                strcpy(peerid, tmp[1]);
            // TODO: update SleepTime
        }
    }
    // Build response
    char tmpResponseType3[50];
    sprintf(tmpResponseType3, "%s%s%s", "{\"Type\":3,\"PeerId\":\"", peerid, "\"}");

    ((struct eap_msg *)eapRespData)->code = RESPONSE_CODE;
    ((struct eap_msg *)eapRespData)->id = (uint8_t)id;
    ((struct eap_msg *)eapRespData)->length = HTONS((sizeof(struct eap_msg) + strlen(tmpResponseType3)) + 1);
    ((struct eap_msg *)eapRespData)->method = (uint8_t)EAP_NOOB;

    sprintf((char *)eapRespData + 5, "%s", (char *)tmpResponseType3);
    eapKeyAvailable = FALSE;
}

/**
 * eap_noob_process : Process EAP-NOOB requests
 * @eapReqData : EAP request data
 * @methodState : method state
 * @decision : FAIL or SUCC
**/
void eap_noob_process(const uint8_t *eapReqData, uint8_t *methodState, uint8_t *decision, uint8_t *eapRespData)
{
    if (reqMethod == EAP_NOOB && reqCode == REQUEST_CODE) {
        struct eap_msg *resp;

        size_t size;
        size = NTOHS(reqLength) - 5;

        struct jsonparse_state req_obj;
        jsonparse_setup(&req_obj, (char *)eapReqData+5, size);

        *(methodState) = CONT;
        *(decision) = FAIL;

        int msgtype;
        msgtype = json_integer_value(&req_obj, "Type");
        if (msgtype < 0)
            DEBUG_NOOB("Invalid request type");

        switch (msgtype) {
            case EAP_NOOB_TYPE_1:
                DEBUG_NOOB("Message type 1");
                eap_noob_req_type_one((char *)eapReqData+5, size, reqId, eapRespData);
                break;
            case EAP_NOOB_TYPE_2:
                DEBUG_NOOB("Message type 2");
                eap_noob_req_type_two((char *)eapReqData+5, size, reqId, eapRespData);
                break;
            case EAP_NOOB_TYPE_3:
                DEBUG_NOOB("Message type 3");
                eap_noob_req_type_three((char *)eapReqData+5, size, reqId, eapRespData);
                break;
            case EAP_NOOB_TYPE_4:
                *(methodState) = MAY_CONT;
                *(decision) = COND_SUCC;
            case EAP_NOOB_TYPE_5:
            case EAP_NOOB_TYPE_6:
            case EAP_NOOB_TYPE_7:
                *(methodState) = MAY_CONT;
                *(decision) = COND_SUCC;
            case EAP_NOOB_TYPE_0:
                ERROR_NOOB("Received error code", json_integer_value(&req_obj, "ErrorCode"));
                break;
            default:
                ERROR_NOOB("Unknown request received:", msgtype);
                break;
        }
	}
}
