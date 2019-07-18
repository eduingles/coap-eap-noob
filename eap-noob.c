/*
 * EAP peer method: EAP-NOOB
 *  Copyright (c) 2019, Aalto University
 *  Copyright (c) 2019, University of Murcia
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *  * Neither the name of the Aalto University nor the name of the University
 *    of Murcia nor the names of its contributors may be used to endorse or
 *    promote products derived from this software without specific prior
 *    written permission.
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

static char nai [MAX_NAI_LEN];
static char PeerId [MAX_PEER_ID_LEN];
static char RealM [] = "noob.example.com";

static const unsigned char base64_table[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * base64_encode : Base64 encoding
 * @src : data to be encoded
 * @len : length of the data to be encoded
 * @out_len : pointer to output length variable, or NULL if not used
 * Returns :
 */
static uint8_t base64_encode(const unsigned char *src, size_t len, size_t *out_len, unsigned char *dst)
{
    unsigned char *pos;
    const unsigned char *end, *in;
    size_t olen;

    olen = len * 4 / 3 + 4; // 3-byte blocks to 4-byte
    olen += olen / 72;      // line feeds
    olen++;                 // null termination
    if (olen < len)
        return 0;           // integer overflow

    unsigned char out[olen];
    if (out == NULL)
        return 0;

    end = src + len;
    in = src;
    pos = out;

    while (end - in >= 3) {
        *pos++ = base64_table[in[0] >> 2];
        *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
        *pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
        *pos++ = base64_table[in[2] & 0x3f];
        in += 3;
    }
    if (end - in) {
        *pos++ = base64_table[in[0] >> 2];
        if (end-in == 1) {
            *pos++ = base64_table[(in[0] & 0x03) << 4];
            *pos++ = '=';
        } else {
            *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
            *pos++ = base64_table[(in[1] & 0x0f) << 2];
        }
    }
    *pos = '\0';
    if (out_len)
        *out_len = pos - out;

    memcpy(dst, out, *out_len+1);
    return 1;
}

/**
 * base64_decode - Base64 decoding
 * @src : data to be decoded
 * @len : length of the data to be decoded
 * @out_len : pointer to output length variable
 * Returns : allocated buffer of out_len bytes of decoded data, or NULL on failure
 *
 * Caller is responsible for freeing the returned buffer.
 */
static uint8_t base64_decode(const unsigned char *src, size_t len, size_t *out_len, unsigned char *dst)
{
    unsigned char dtable[256], *pos, block[4], tmp;
    size_t i, count, olen;
    int pad = 0;

    memset(dtable, 0x80, 256);
    for (i = 0; i < sizeof(base64_table) - 1; i++)
        dtable[base64_table[i]] = (unsigned char) i;
    dtable['='] = 0;

    count = 0;
    for (i = 0; i < len; i++) {
        if (dtable[src[i]] != 0x80)
        count++;
    }

    if (count == 0 || count % 4) // Check padding
        return 0;

    olen = count / 4 * 3;
    unsigned char out[olen];
    pos = out;
    if (out == NULL)
        return 0;

    count = 0;
    for (i = 0; i < len; i++) {
        tmp = dtable[src[i]];
        if (tmp == 0x80)
            continue;

        if (src[i] == '=')
            pad++;
        block[count] = tmp;
        count++;
        if (count == 4) {
            *pos++ = (block[0] << 2) | (block[1] >> 4);
            *pos++ = (block[1] << 4) | (block[2] >> 2);
            *pos++ = (block[2] << 6) | block[3];
            count = 0;
            if (pad) {
                if (pad == 1)
                    pos--;
                else if (pad == 2)
                    pos -= 2;
                else /* Invalid padding */
                    return 0;
            break;
            }
        }
    }

    *out_len = pos - out;
    memcpy(dst, out, *out_len+1);
    return 1;
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

    // int type = jsonparse_get_type(js);
    jsonparse_get_type(js);

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
 * initMethodEap : Initialise EAP method
**/
void init_eap_noob()
{
    // Set default NAI
    sprintf(nai, "%s%s", "noob@", DEFAULT_REALM);
}

/**
 * eap_noob_build_identity : Build EAP-NOOB identity
 * @eapRespData : EAP response data
**/
void eap_noob_build_identity(char *eapRespData) {
    memcpy(eapRespData, nai, strlen(nai)+1);
}

/**
 * write_db : Write data to database
 * @key : key
 * @val : value
 * Returns : 1 or -1
**/
static int write_db(char *key , char *val)
{
    int db;
    if ((db = cfs_open(DB_NAME, CFS_WRITE | CFS_APPEND)) >= 0) {
        cfs_write(db, key, strlen(key));
        cfs_write(db, ":", 1);
        cfs_write(db, val, strlen(val));
        cfs_write(db, "\n", 1);
        cfs_close(db);
    } else {
        DEBUG_NOOB("Could not open database");
        return -1;
    }
    return 1;
}

/**
 * print_db : Print database to stdout
 * TEMPORARY - FOR DEBUGGING PURPOSES
**/
static void print_db()
{
    int db;
    if ((db = cfs_open(DB_NAME, CFS_READ)) >= 0) {
        size_t size = cfs_seek(db, 0, CFS_SEEK_END);
        cfs_seek(db, 0, CFS_SEEK_SET);
        char dst[size];
        cfs_read(db, dst, size);
        cfs_close(db);
        printf("Database after parsing request \n%s\n", dst);
    }
}

/**
 * value_in_array : Check if a value exists in an array
 * @val : value
 * @arr : array
 * Returns : 1 or -1
**/
static int value_in_array(uint8_t val, char *arr)
{
    int i;
    for (i = 1; i < strlen(arr)-1; i++) {
        uint8_t tmp = arr[i] - '0';
        if (tmp == val)
            return 1;
    }
    return -1;
}

const char* error_info[] = {
    "Invalid NAI",
    "Invalid message structure",
    "Invalid data",
    "Unexpected message type",
    "Invalid ECDHE key",
    "Unwanted peer",
    "State mismatch, user action required",
    "Unrecognized OOB message identifier",
    "Unexpected peer identifier",
    "Unrecognized Kz identifier",
    "No mutually supported protocol version",
    "No mutually supported cryptosuite",
    "No mutually supported OOB direction",
    "HMAC verification failure",
    "Application-specific error",
    "Invalid server info",
    "Invalid server URL",
    "Invalid peer info"
};

const int error_code[] = {
    1001, 1002, 1003, 1004, 1007,
    2001, 2002, 2003, 2004, 2005,
    3001, 3002, 3003,
    4001,
    5001, 5002, 5003, 5004
};

/**
 * eap_noob_err_msg : Prepare error message
 * @id : method identifier
 * @eapRespData : EAP response data
 * @error : error code
**/
void eap_noob_err_msg(uint8_t *eapRespData, uint8_t error, size_t *eapRespLen)
{
    // Build error message
    char tmpResponseType0[200];
    sprintf(tmpResponseType0, "%s%s%s%d%s%s%s",
        "{\"Type\":0,\"PeerId\":\"",PeerId,"\",\"ErrorCode\":",
        error_code[error],",\"ErrorInfo\":\"",error_info[error],"\"}"
    );

    DEBUG_NOOB(error_info[error]);
    ERROR_NOOB("Sending error code", error_code[error]);

    *eapRespLen = strlen(tmpResponseType0);
    memcpy(eapRespData, tmpResponseType0, *eapRespLen + 1); //  + 1 => \0
    eapKeyAvailable = FALSE;
}

/**
 * eap_noob_rsp_type_one : Prepare response type one
 * @id : method identifier
 * @eapRespData : EAP response data
 * @dirp : negotiated OOB direction
**/
void eap_noob_rsp_type_one(uint8_t *eapRespData, int dirp, size_t *eapRespLen)
{
    char tmpResponseType1[200];
    sprintf(tmpResponseType1, "%s%d%s%s%s%d%s%d%s%s%s",
        "{\"Type\":1,\"Verp\":",VERS,",\"PeerId\":\"",PeerId,
        "\",\"Cryptosuitep\":",CSUIT,",\"Dirp\":",dirp,",\"PeerInfo\":",
        PEER_INFO,"}"
    );

    *eapRespLen = strlen(tmpResponseType1);
    memcpy(eapRespData, tmpResponseType1, *eapRespLen + 1); //  + 1 => \0
    eapKeyAvailable = FALSE;
}

/**
 * eap_noob_rsp_type_two : Prepare response type two
 * @id : method identifier
 * @eapRespData : EAP response data
**/
void eap_noob_rsp_type_two(uint8_t *eapRespData, size_t *eapRespLen)
{
    unsigned char pk_str1[32];
    DEBUG_NOOB("PK.X hex: ");
    // for(int i = 0 ;i < 8;i++){ //Big endian (order: 0,1,2,3)
    int i;
    for(i = 7; i >= 0; i--) { //Little endian (order: 3,2,1,0)
        printf("%lX", client_pk.x[i]);
        pk_str1[i*4+3] = client_pk.x[i] >> 24;
        pk_str1[i*4+2] = client_pk.x[i] >> 16;
        pk_str1[i*4+1] = client_pk.x[i] >> 8;
        pk_str1[i*4+0] = client_pk.x[i];
    }
    printf("\n");
    // pk_str1[32] = '\0';

    // printf("A PK.X char: ");
    // for (int i = 0; i < 32; i++)
    //     printf("%u", pk_str1[i]);
    // printf("\n");

    size_t len_b64_x = 0;
    unsigned char pk_x_b64[45];
    base64_encode(pk_str1, 32, &len_b64_x, pk_x_b64);
    // printf("pk_x_b64 %d: %s\n", len_b64_x, pk_x_b64);

    unsigned char pk_str2[32];
    DEBUG_NOOB("PK.Y hex: ");
    // for(int i = 0 ;i < 8;i++){ //Big endian (order: 0,1,2,3)
    for(i = 7; i >= 0; i--) { //Little endian (order: 3,2,1,0)
        printf("%lX", client_pk.y[i]);
        pk_str2[i*4+3] = client_pk.y[i] >> 24;
        pk_str2[i*4+2] = client_pk.y[i] >> 16;
        pk_str2[i*4+1] = client_pk.y[i] >> 8;
        pk_str2[i*4+0] = client_pk.y[i];
    }
    printf("\n");
    // pk_str2[32] = '\0';

    // printf("A PK.Y char: ");
    // for (int i = 0; i < 32; i++)
    //     printf("%u", pk_str2[i]);
    // printf("\n");

    size_t len_b64_y = 0;
    unsigned char pk_y_b64[45];
    base64_encode(pk_str2, 32, &len_b64_y, pk_y_b64);
    // printf("pk_y_b64 %d: %s\n", len_b64_y, pk_y_b64);

    // Generate nonce
    char Np[33];
    for (i = 0; i < 32; i++)
        Np[i] = base64_table[random_rand() % 64];
    Np[i] = '\0';
    // Base64 encode the nonce
    unsigned char Np_b64[45];
    size_t len_b64_Np = 0;
    base64_encode(Np, 32, &len_b64_Np, Np_b64);

    char tmpResponseType2[250];
    sprintf(tmpResponseType2, "%s%s%s%s%s%s%s%s%s",
        "{\"Type\":2,\"PeerId\":\"", PeerId,
        "\",\"PKp\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"", pk_x_b64,
        "\", \"y\":\"", pk_y_b64,
        "\"},\"Np\":\"", Np_b64, "\"}"
    );

    *eapRespLen = strlen(tmpResponseType2);
    memcpy(eapRespData, tmpResponseType2, *eapRespLen + 1);

    // Update NAI
    sprintf(nai, "%s+s1@%s", PeerId, RealM);

    printf("EAP-NOOB: Response type 2: %s\n", tmpResponseType2);
}

/**
 * eap_noob_rsp_type_three : Prepare response type three
 * @id : method identifier
 * @eapRespData : EAP response data
**/
void eap_noob_rsp_type_three(uint8_t *eapRespData, size_t *eapRespLen)
{
    char tmpResponseType3[80];
    sprintf(tmpResponseType3, "%s%s%s",
        "{\"Type\":3,\"PeerId\":\"",PeerId,"\"}"
    );

    *eapRespLen = strlen(tmpResponseType3);
    memcpy(eapRespData, tmpResponseType3, *eapRespLen + 1); //  + 1 => \0
    eapKeyAvailable = FALSE;
}

/**
 * eap_noob_req_type_one : Decode request type one
 * @eapReqData : EAP request data
 * @size : size of eapReqData
 * @id : method identifier
 * @eapRespData : EAP response data
**/
void eap_noob_req_type_one(char *eapReqData, const size_t size, uint8_t *eapRespData, size_t *eapRespLen)
{
    // Parse request
    struct jsonparse_state js_req;
    jsonparse_setup(&js_req, eapReqData, size);
    int type, dirp, dirs;
    char tmp[2][100];
    while((type = jsonparse_next(&js_req)) != 0) {
        if(type == JSON_TYPE_PAIR_NAME) {
            jsonparse_copy_next(&js_req, tmp[0], size);
            jsonparse_next(&js_req);
            jsonparse_copy_next(&js_req, tmp[1], size);
            if (!strcmp(tmp[0], "PeerId")) {
                strcpy(PeerId, tmp[1]);
            } else if(!strcmp(tmp[0], "Vers")) {
                if (value_in_array(VERS, tmp[1]) == -1) {
                    eap_noob_err_msg(eapRespData, E3001, eapRespLen);
                    return;
                }
            } else if(!strcmp(tmp[0], "Cryptosuites")) {
                if (value_in_array(CSUIT, tmp[1]) == -1) {
                    eap_noob_err_msg(eapRespData, E3002, eapRespLen);
                    return;
                }
            } else if(!strcmp(tmp[0], "Dirs")) {
                dirs = tmp[1][0] - '0';
                if (dirs == OOBDIR)
                    dirp = dirs;
                else if (dirs == 3)
                    dirp = OOBDIR;
                else if (OOBDIR == 3)
                    dirp = dirs;
                else {
                    eap_noob_err_msg(eapRespData, E3003, eapRespLen);
                    return;
                }
            }
            write_db(tmp[0], tmp[1]);
        }
    }
    // Build response
    eap_noob_rsp_type_one(eapRespData, dirp, eapRespLen);
}

/**
 * eap_noob_req_type_two : Decode request type two
 * @eapReqData : EAP request data
 * @size : size of eapReqData
 * @id : method identifier
 * @eapRespData : EAP response data
**/
void eap_noob_req_type_two(char *eapReqData, const size_t size, uint8_t *eapRespData, size_t *eapRespLen)
{
    // Parse request
    struct jsonparse_state js_req;
    jsonparse_setup(&js_req, eapReqData, size);
    int type;
    char tmp[2][130];

    while((type = jsonparse_next(&js_req)) != 0) {
        if(type == JSON_TYPE_PAIR_NAME) {
            jsonparse_copy_next(&js_req, tmp[0], size);
            jsonparse_next(&js_req);
            jsonparse_copy_next(&js_req, tmp[1], size);
            if (!strcmp(tmp[0], "PeerId")) {
                if (strcmp(PeerId, tmp[1])) {
                    eap_noob_err_msg(eapRespData, E2004, eapRespLen);
                    return;
                }
            } else if (!strcmp(tmp[0], "PKs")) {
                write_db(tmp[0], tmp[1]);
                struct jsonparse_state pks;
                jsonparse_setup(&pks, tmp[1], strlen(tmp[1]));
                while((type = jsonparse_next(&pks)) != 0) {
                    if(type == JSON_TYPE_PAIR_NAME) {
                        jsonparse_copy_next(&pks, tmp[0], size);
                        jsonparse_next(&pks);
                        jsonparse_copy_next(&pks, tmp[1], size);
                        if (!strcmp(tmp[0], "x")) {
                            size_t len_x = 0;
                            unsigned char x[33];
                            sprintf(tmp[1], "%s""=", tmp[1]);
                            base64_decode((unsigned char *)tmp[1], strlen(tmp[1]), &len_x, x);
                            memcpy(server_pk.x,x, 32);
                        } else if (!strcmp(tmp[0], "y")) {
                            size_t len_y = 0;
                            unsigned char y[33];
                            sprintf(tmp[1], "%s""=", tmp[1]);
                            base64_decode((unsigned char *)tmp[1], strlen(tmp[1]), &len_y, y);
                            memcpy(server_pk.y,y, 32);
                        }
                    }
                }
            } else if (!strcmp(tmp[0], "Ns") || !strcmp(tmp[0], "SleepTime") ) {
                write_db(tmp[0], tmp[1]);
            }
        }
    }
    process_start(&ecc_derive_secret, NULL);

    // Build response
    eap_noob_rsp_type_two(eapRespData, eapRespLen);
}

/**
 * eap_noob_req_type_three : Decode request type three
 * @eapReqData : EAP request data
 * @size : size of eapReqData
 * @id : method identifier
 * @eapRespData : EAP response data
**/
void eap_noob_req_type_three(char *eapReqData, const size_t size, uint8_t *eapRespData, size_t *eapRespLen)
{
    // Parse request
    struct jsonparse_state js_req;
    jsonparse_setup(&js_req, eapReqData, size);
    int type;
    char tmp[2][100];
    while((type = jsonparse_next(&js_req)) != 0) {
        if(type == JSON_TYPE_PAIR_NAME) {
            jsonparse_copy_next(&js_req, tmp[0], size);
            jsonparse_next(&js_req);
            jsonparse_copy_next(&js_req, tmp[1], size);
            if (!strcmp(tmp[0], "PeerId")) {
                if (strcmp(PeerId, tmp[1])) {
                    eap_noob_err_msg(eapRespData, E2004, eapRespLen);
                    return;
                }
            }
            // TODO: update SleepTime
        }
    }
    // Build response
    eap_noob_rsp_type_three(eapRespData, eapRespLen);
}

/**
 * eap_noob_process : Process EAP-NOOB requests
 * @eapReqData : EAP request data
 * @methodState : method state
 * @decision : FAIL or SUCC
 * @eapRespData : EAP response data. Only payload
 * @eapRespLen : EAP payload length
**/
void eap_noob_process(const uint8_t *eapReqData, size_t eapReqLen, uint8_t *methodState, uint8_t *decision, uint8_t *eapRespData, size_t *eapRespLen)
{
    *(methodState) = CONT;
    *(decision) = FAIL;

    size_t size;
    size = eapReqLen;
    struct jsonparse_state req_obj;
    jsonparse_setup(&req_obj, (char *)eapReqData, size);

    int msgtype;
    msgtype = json_integer_value(&req_obj, "Type");
    if (msgtype < 0)
        DEBUG_NOOB("Invalid request type");

    switch (msgtype) {
        case EAP_NOOB_TYPE_1:
            DEBUG_NOOB("Message type 1");
            eap_noob_req_type_one((char*)eapReqData, size, eapRespData, eapRespLen);
            break;
        case EAP_NOOB_TYPE_2:
            DEBUG_NOOB("Message type 2");
            eap_noob_req_type_two((char*)eapReqData, size, eapRespData, eapRespLen);
            break;
        case EAP_NOOB_TYPE_3:
            DEBUG_NOOB("Message type 3");
            eap_noob_req_type_three((char*)eapReqData, size, eapRespData, eapRespLen);
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
