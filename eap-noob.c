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
static char PeerId [MAX_PEERID_LEN];
static char RealM [] = "noob.example.com";

/* EAP-NOOB error codes */
const int error_code[] = {
    1001, 1002, 1003, 1004, 1007,
    2001, 2002, 2003, 2004,
    3001, 3002, 3003,
    4001,
    5001, 5002, 5003, 5004
};

/* EAP-NOOB error messages */
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
    "No mutually supported protocol version",
    "No mutually supported cryptosuite",
    "No mutually supported OOB direction",
    "HMAC verification failure",
    "Application-specific error",
    "Invalid server info",
    "Invalid server URL",
    "Invalid peer info"
};

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
void init_eap_noob(void)
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

/**
 * generate_nonce : Generate fresh nonce
 * @size : size of the nonce
 * @dst : destination array
 **/
void generate_nonce(size_t size, unsigned char *dst)
{
    char nonce[size];
    int i;
    for (i = 0; i < size-1; i++)
        nonce[i] = base64_table[random_rand() % 64];
    nonce[i] = '\0';

    printf("DEBUG: generated nonce %s\n", nonce);
    // Base64 encode the nonce
    size_t len_b64_nonce = 0;
    base64_encode((const unsigned char*)nonce, size, &len_b64_nonce, dst);
}

/**
 * generate_noob : Generate fresh 16 byte nonce and save it to the database
 **/
void generate_noob(void)
{
    unsigned char noob[23];
    generate_nonce(16, noob);
    noob[22] = '\0'; // Get rid of padding character ('=') at the end
    write_db("Noob", (char *)noob);
}

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

#if NOOB_DEBUG
    DEBUG_MSG_NOOB(error_info[error]);
    ERROR_MSG_NOOB("Sending error code", error_code[error]);
#endif

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

#if NOOB_DEBUG
    printf("EAP-NOOB: Sending response %s\n", tmpResponseType1);
#endif
}

/**
 * eap_noob_rsp_type_two : Prepare response type two
 * @id : method identifier
 * @eapRespData : EAP response data
**/
void eap_noob_rsp_type_two(uint8_t *eapRespData, size_t *eapRespLen)
{
    unsigned char pk_str1[32];
    int i;
    for(i = 7; i >= 0; i--) { //Little endian (order: 3,2,1,0)
        pk_str1[i*4+3] = client_pk.x[i] >> 24;
        pk_str1[i*4+2] = client_pk.x[i] >> 16;
        pk_str1[i*4+1] = client_pk.x[i] >> 8;
        pk_str1[i*4+0] = client_pk.x[i];
    }

    size_t len_b64_x = 0;
    unsigned char pk_x_b64[45];
    base64_encode(pk_str1, 32, &len_b64_x, pk_x_b64);
    write_db("Xp", (char *)pk_x_b64);

    unsigned char pk_str2[32];
    for(i = 7; i >= 0; i--) { //Little endian (order: 3,2,1,0)
        pk_str2[i*4+3] = client_pk.y[i] >> 24;
        pk_str2[i*4+2] = client_pk.y[i] >> 16;
        pk_str2[i*4+1] = client_pk.y[i] >> 8;
        pk_str2[i*4+0] = client_pk.y[i];
    }

    size_t len_b64_y = 0;
    unsigned char pk_y_b64[44];
    base64_encode(pk_str2, 32, &len_b64_y, pk_y_b64);
    write_db("Yp", (char *)pk_y_b64);

    // Generate nonce
    unsigned char Np_b64[44];
    generate_nonce(32, Np_b64);
    write_db("Np", (char *)Np_b64);

    char tmpResponseType2[250];
    sprintf(tmpResponseType2, "%s%s%s%s%s%s%s%s%s",
        "{\"Type\":2,\"PeerId\":\"", PeerId,
        "\",\"PKp\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"", pk_x_b64,
        "\", \"y\":\"", pk_y_b64,
        "\"},\"Np\":\"", Np_b64, "\"}"
    );

    *eapRespLen = strlen(tmpResponseType2);
    memcpy(eapRespData, tmpResponseType2, *eapRespLen + 1); //  + 1 => \0

    // Update NAI
    sprintf(nai, "%s+s1@%s", PeerId, RealM);

#if NOOB_DEBUG
    printf("EAP-NOOB: Sending response %s\n", tmpResponseType2);
#endif
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

#if NOOB_DEBUG
    printf("EAP-NOOB: Sending response %s\n", tmpResponseType3);
#endif
}

/**
 * eap_noob_rsp_type_four : Prepare response type four
 * @id : method identifier
 * @eapRespData : EAP response data
**/
void eap_noob_rsp_type_four(uint8_t *eapRespData, size_t *eapRespLen)
{
    char tmpResponseType4[140];
    char MACp[44];
    // TODO: calculate MACp
    // read_db("MACp", MACp);
    sprintf(tmpResponseType4, "%s%s%s%s%s",
        "{\"Type\":4,\"PeerId\":\"",PeerId,"\",\"MACp\":\"",MACp,"\"}"
    );

    *eapRespLen = strlen(tmpResponseType4);
    memcpy(eapRespData, tmpResponseType4, *eapRespLen + 1); //  + 1 => \0
    eapKeyAvailable = TRUE;

    // Update NAI
    sprintf(nai, "%s+s4@%s", PeerId, RealM);

#if NOOB_DEBUG
    printf("EAP-NOOB: Sending response %s\n", tmpResponseType4);
#endif
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
                    // Error: No mutually supported protocol version
                    eap_noob_err_msg(eapRespData, E3001, eapRespLen);
                    return;
                }
            } else if(!strcmp(tmp[0], "Cryptosuites")) {
                if (value_in_array(CSUIT, tmp[1]) == -1) {
                    // Error: No mutually supported cryptosuite
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
                    // Error: No mutually supported OOB direction
                    eap_noob_err_msg(eapRespData, E3003, eapRespLen);
                    return;
                }
            }
            write_db(tmp[0], tmp[1]);
        }
    }
    // Convert values to store them in the database
    char Verp[2];
    char Cryptosuitep[2];
    char Dirp[2];
    sprintf(Verp, "%d", VERS);
    sprintf(Cryptosuitep, "%d", CSUIT);
    sprintf(Dirp, "%d", dirp);

    write_db("Verp", Verp);
    write_db("Cryptosuitep", Cryptosuitep);
    write_db("Dirp", Dirp);
    write_db("PeerInfo", PEER_INFO);

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
                    // Error: Unexpected peer identifier
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
                            write_db("Xs", tmp[1]);
                            size_t len_x = 0;
                            unsigned char x[33];
                            sprintf(tmp[1], "%s""=", tmp[1]);
                            base64_decode((unsigned char *)tmp[1], strlen(tmp[1]), &len_x, x);
                            memcpy(server_pk.x,x, 32);
                        } else if (!strcmp(tmp[0], "y")) {
                            write_db("Ys", tmp[1]);
                            size_t len_y = 0;
                            unsigned char y[33];
                            sprintf(tmp[1], "%s""=", tmp[1]);
                            base64_decode((unsigned char *)tmp[1], strlen(tmp[1]), &len_y, y);
                            memcpy(server_pk.y,y, 32);
                        }
                    }
                }
            } else if (!strcmp(tmp[0], "Ns")) {
                write_db(tmp[0], tmp[1]);
            } else if (!strcmp(tmp[0], "SleepTime")) {
                // TODO: set SleepTime
            }
        }
    }
    // Generate new Noob
    generate_noob();
    // Derive shared secret key and build OOB message
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
                    // Error: Unexpected peer identifier
                    eap_noob_err_msg(eapRespData, E2004, eapRespLen);
                    return;
                }
            } else if (!strcmp(tmp[0], "SleepTime")) {
                // TODO: update SleepTime
            }
        }
    }
    // Build response
    eap_noob_rsp_type_three(eapRespData, eapRespLen);
}

/**
 * eap_noob_req_type_four : Decode request type four
 * @eapReqData : EAP request data
 * @size : size of eapReqData
 * @id : method identifier
 * @eapRespData : EAP response data
**/
void eap_noob_req_type_four(char *eapReqData, const size_t size, uint8_t *eapRespData, size_t *eapRespLen)
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
                    // Error: Unexpected peer identifier
                    eap_noob_err_msg(eapRespData, E2004, eapRespLen);
                    return;
                }
            } else if (!strcmp(tmp[0], "NoobId")) {
                char NoobId[23];
            	read_db("NoobId", NoobId);
                if (strcmp(NoobId, tmp[1])) {
                    // Error: Unrecognized OOB message identifier
                    eap_noob_err_msg(eapRespData, E2003, eapRespLen);
                    return;
                }
            } else if (!strcmp(tmp[0], "MACs")) {
                char MACs[44];
                // TODO: calculate MACs
                // read_db("MACs", MACs);
                if (strcmp(MACs, tmp[1])) {
                    // Error: HMAC verification failure
                    eap_noob_err_msg(eapRespData, E4001, eapRespLen);
                    return;
                }
            }
        }
    }
    // Build response
    eap_noob_rsp_type_four(eapRespData, eapRespLen);
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
    // Parse request payload to get message type
    size_t size;
    size = eapReqLen;
    struct jsonparse_state req_obj;
    jsonparse_setup(&req_obj, (char *)eapReqData, size);
    int msgtype;
    msgtype = json_integer_value(&req_obj, "Type");

#if NOOB_DEBUG
    printf("EAP-NOOB: Received request %s\n", eapReqData);
#endif

    switch (msgtype) {
        case EAP_NOOB_TYPE_1: // Initial Exchange
            eap_noob_req_type_one((char*)eapReqData, size, eapRespData, eapRespLen);
            break;
        case EAP_NOOB_TYPE_2: // Initial Exchange
            eap_noob_req_type_two((char*)eapReqData, size, eapRespData, eapRespLen);
            break;
        case EAP_NOOB_TYPE_3: // Waiting Exchange
            eap_noob_req_type_three((char*)eapReqData, size, eapRespData, eapRespLen);
            break;
        case EAP_NOOB_TYPE_4: // Completion Exchange
            eap_noob_req_type_four((char*)eapReqData, size, eapRespData, eapRespLen);
            *(methodState) = MAY_CONT;
            *(decision) = COND_SUCC;
            break;
        case EAP_NOOB_TYPE_5: // Reconnect Exchange
        case EAP_NOOB_TYPE_6: // Reconnect Exchange
        case EAP_NOOB_TYPE_7: // Reconnect Exchange
            *(methodState) = MAY_CONT;
            *(decision) = COND_SUCC;
        case EAP_NOOB_TYPE_8: // Completion Exchange
            // TODO: implement S2P OOB direction
        case EAP_NOOB_TYPE_0: // Error message
            ERROR_MSG_NOOB("Received error code", json_integer_value(&req_obj, "ErrorCode"));
            break;
        default:
            ERROR_MSG_NOOB("Unknown request received:", msgtype);
            break;
    }
}
