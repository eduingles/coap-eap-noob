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


static const unsigned char base64_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * base64_encode - Base64 encode
 * @src: Data to be encoded
 * @len: Length of the data to be encoded
 * @out_len: Pointer to output length variable, or %NULL if not used
 * Returns: Allocated buffer of out_len bytes of encoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer. Returned buffer is
 * nul terminated to make it easier to use as a C string. The nul terminator is
 * not included in out_len.
 */
void base64_encode(const unsigned char *src, size_t len,
			      size_t *out_len, unsigned char *dst)
{
	unsigned char *pos;
	const unsigned char *end, *in;
	size_t olen;
	int line_len;

	olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
	olen += olen / 72; /* line feeds */
	olen++; /* nul termination */
	if (olen < len){
		return NULL; /* integer overflow */
    }
	unsigned char out[olen];
	if (out == NULL){
		return NULL;
    }

	end = src + len;
	in = src;
	pos = out;
	line_len = 0;
	while (end - in >= 3) {
		*pos++ = base64_table[in[0] >> 2];
		*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
		*pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
		*pos++ = base64_table[in[2] & 0x3f];
		in += 3;
		line_len += 4;
		if (line_len >= 72) {
		// 	*pos++ = '\n';
			line_len = 0;
		}
	}

	if (end - in) {
		*pos++ = base64_table[in[0] >> 2];
		if (end - in == 1) {
			*pos++ = base64_table[(in[0] & 0x03) << 4];
			// *pos++ = '=';
		} else {
			*pos++ = base64_table[((in[0] & 0x03) << 4) |
					      (in[1] >> 4)];
			*pos++ = base64_table[(in[1] & 0x0f) << 2];
		}
		// *pos++ = '=';
		// line_len += 4;
	}

	// if (line_len)
		// *pos++ = '\n';

	*pos = '\0';
	if (out_len){
		*out_len = pos - out;
    }
    uint16_t strlen_tmp = *out_len;
    // sprintf(dst,"%s", out);
    // memcpy(dst, out, sizeof(char)* strlen_tmp );
    memcpy(dst, out, *out_len+1);

    printf("Base64 result: %s\n", dst);
	// return out;
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
    sprintf(nai, "%s%s", "noob@", DEFAULT_REALM);
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

/**
 * eap_noob_err_msg : Prepare error message
 * @id : method identifier
 * @eapRespData : EAP response data
 * @error : error code
**/
void eap_noob_err_msg(const uint8_t id, uint8_t *eapRespData, uint8_t error)
{
    // Build error message
    char tmpResponseType0[200];
    sprintf(tmpResponseType0, "%s%s%s%d%s%s%s", "{\"Type\":0,\"PeerId\":\"", PeerId, "\",\"ErrorCode\":",error_code[error],",\"ErrorInfo\":\"", error_info[error],"\"}");

    DEBUG_NOOB(error_info[error]);
    ERROR_NOOB("Sending error code", error_code[error]);

    ((struct eap_msg *)eapRespData)->code = RESPONSE_CODE;
    ((struct eap_msg *)eapRespData)->id = (uint8_t)id;
    ((struct eap_msg *)eapRespData)->length = HTONS((sizeof(struct eap_msg) + strlen(tmpResponseType0)) + 1);
    ((struct eap_msg *)eapRespData)->method = (uint8_t)EAP_NOOB;

    sprintf((char *)eapRespData + 5, "%s", (char *)tmpResponseType0);
    eapKeyAvailable = FALSE;
}

/**
 * eap_noob_rsp_type_one : Prepare response type one
 * @eapReqData : EAP request data
 * @size : size of eapReqData
 * @id : method identifier
 * @eapRespData : EAP response data
 * @dirp : negotiated OOB direction
**/
void eap_noob_rsp_type_one(char *eapReqData, const size_t size, const uint8_t id, uint8_t *eapRespData, int dirp)
{
    char tmpResponseType1[200];
    sprintf(tmpResponseType1, "%s%d%s%s%s%d%s%d%s%s%s", "{\"Type\":1,\"Verp\":", VERS, ",\"PeerId\":\"", PeerId, "\",\"Cryptosuitep\":", CSUIT,",\"Dirp\":", dirp,",\"PeerInfo\":", PEER_INFO,"}");

    ((struct eap_msg *)eapRespData)->code = RESPONSE_CODE;
    ((struct eap_msg *)eapRespData)->id = (uint8_t)id;
    ((struct eap_msg *)eapRespData)->length = HTONS((sizeof(struct eap_msg) + strlen(tmpResponseType1)) + 1);
    ((struct eap_msg *)eapRespData)->method = (uint8_t)EAP_NOOB;

    sprintf((char *)eapRespData + 5, "%s", (char *)tmpResponseType1);
    eapKeyAvailable = FALSE;
}

/**
 * eap_noob_rsp_type_two : Prepare response type two
 * @eapReqData : EAP request data
 * @size : size of eapReqData
 * @id : method identifier
 * @eapRespData : EAP response data
**/
void eap_noob_rsp_type_two(char *eapReqData, const size_t size, const uint8_t id, uint8_t *eapRespData)
{
    // TODO: generate fresh nonce
    // TODO: update cryptosuite
    char tmpResponseType2[400];
    sprintf(tmpResponseType2, "%s%s%s", "{\"Type\":2,\"PeerId\":\"", PeerId, "\",\"PKp\":{\"kty\":\"EC\",\"crv\":\"Curve25519\",\"x\":\"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08\"},\"Np\":\"HIvB6g0n2btpxEcU7YXnWB-451ED6L6veQQd6ugiPFU\"}");

    ((struct eap_msg *)eapRespData)->code = RESPONSE_CODE;
    ((struct eap_msg *)eapRespData)->id = (uint8_t)id;
    ((struct eap_msg *)eapRespData)->length = HTONS((sizeof(struct eap_msg) + strlen(tmpResponseType2)) + 1);
    ((struct eap_msg *)eapRespData)->method = (uint8_t)EAP_NOOB;

    sprintf((char *)eapRespData + 5, "%s", (char *)tmpResponseType2);
    eapKeyAvailable = FALSE;

    // Update NAI
    sprintf(nai, "%s%s", PeerId, "+s1@noob.example.com");
}

/**
 * eap_noob_rsp_type_three : Prepare response type three
 * @eapReqData : EAP request data
 * @size : size of eapReqData
 * @id : method identifier
 * @eapRespData : EAP response data
**/
void eap_noob_rsp_type_three(char *eapReqData, const size_t size, const uint8_t id, uint8_t *eapRespData)
{
    char tmpResponseType3[50];
    sprintf(tmpResponseType3, "%s%s%s", "{\"Type\":3,\"PeerId\":\"", PeerId, "\"}");

    ((struct eap_msg *)eapRespData)->code = RESPONSE_CODE;
    ((struct eap_msg *)eapRespData)->id = (uint8_t)id;
    ((struct eap_msg *)eapRespData)->length = HTONS((sizeof(struct eap_msg) + strlen(tmpResponseType3)) + 1);
    ((struct eap_msg *)eapRespData)->method = (uint8_t)EAP_NOOB;

    sprintf((char *)eapRespData + 5, "%s", (char *)tmpResponseType3);
    eapKeyAvailable = FALSE;
}

/**
 * eap_noob_req_type_one : Decode request type one
 * @eapReqData : EAP request data
 * @size : size of eapReqData
 * @id : method identifier
 * @eapRespData : EAP response data
**/
void eap_noob_req_type_one(char *eapReqData, const size_t size, const uint8_t id, uint8_t *eapRespData)
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
                    eap_noob_err_msg(id, eapRespData, E3001);
                    return;
                }
            } else if(!strcmp(tmp[0], "Cryptosuites")) {
                if (value_in_array(CSUIT, tmp[1]) == -1) {
                    eap_noob_err_msg(id, eapRespData, E3002);
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
                    eap_noob_err_msg(id, eapRespData, E3003);
                    return;
                }
            }
            write_db(tmp[0], tmp[1]);
        }
    }
    // Build response
    eap_noob_rsp_type_one(eapReqData, size, id, eapRespData, dirp);
}

/**
 * eap_noob_req_type_two : Decode request type two
 * @eapReqData : EAP request data
 * @size : size of eapReqData
 * @id : method identifier
 * @eapRespData : EAP response data
**/
void eap_noob_req_type_two(char *eapReqData, const size_t size, const uint8_t id, uint8_t *eapRespData)
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
                    eap_noob_err_msg(id, eapRespData, E2004);
                    return;
                }
            }
            else if (
                !strcmp(tmp[0], "PKs") ||
                !strcmp(tmp[0], "Ns")  ||
                !strcmp(tmp[0], "SleepTime")
            )
                write_db(tmp[0], tmp[1]);
        }
    }

    // Build response





    char pk_str[82];
    uint16_t len_b64;
    unsigned char pk_x_b64[120];
    unsigned char pk_y_b64[120];
    int length = 0;

    printf("PK.x: ");    
    for(int i = 7 ;i>=0;i--){
        printf("%u",client_pk.x[i]);
        length += sprintf(pk_str+length,"%u", client_pk.x[i]);
    }
    printf("\n");
    base64_encode(pk_str, length, &len_b64, pk_x_b64);
    printf("pk_x_b64 %d: %s\n", length, pk_x_b64);

    length = 0;
    printf("PK.y: ");    
    for(int i = 7 ;i>=0;i--){
        printf("%u",client_pk.y[i]);
        length += sprintf(pk_str+length,"%u", client_pk.y[i]);
    }
    printf("\n");

    base64_encode(pk_str, length, &len_b64, pk_y_b64);
    printf("pk_y_b64 %d: %s\n", len_b64, pk_y_b64);

    // TODO: generate fresh nonce
    // TODO: update cryptosuite
    char tmpResponseType2[370];
    sprintf(tmpResponseType2, "%s%s%s%s%s%s%s", "{\"Type\":2,\"PeerId\":\"", PeerId, "\",\"PKp\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"", pk_x_b64, "\", \"y\":\"", pk_y_b64, "\"},\"Np\":\"HIvB6g0n2btpxEcU7YXnWB-451ED6L6veQQd6ugiPFU\"}");
    
    // Curve25519 example
    // sprintf(tmpResponseType2, "%s%s%s", "{\"Type\":2,\"PeerId\":\"", PeerId, "\",\"PKp\":{\"kty\":\"EC\",\"crv\":\"Curve25519\",\"x\":\"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08\"},\"Np\":\"HIvB6g0n2btpxEcU7YXnWB-451ED6L6veQQd6ugiPFU\"}");

    printf("JSON Peer response %s\n",tmpResponseType2);

    ((struct eap_msg *)eapRespData)->code = RESPONSE_CODE;
    ((struct eap_msg *)eapRespData)->id = (uint8_t)id;
    ((struct eap_msg *)eapRespData)->length = HTONS((sizeof(struct eap_msg) + strlen(tmpResponseType2)) + 1);
    ((struct eap_msg *)eapRespData)->method = (uint8_t)EAP_NOOB;

    sprintf((char *)eapRespData + 5, "%s", (char *)tmpResponseType2);
    eapKeyAvailable = FALSE;

    // Update NAI
    sprintf(nai, "%s%s", PeerId, "+s1@noob.example.com");





    // eap_noob_rsp_type_two(eapReqData, size, id, eapRespData);
}

/**
 * eap_noob_req_type_three : Decode request type three
 * @eapReqData : EAP request data
 * @size : size of eapReqData
 * @id : method identifier
 * @eapRespData : EAP response data
**/
void eap_noob_req_type_three(char *eapReqData, const size_t size, const uint8_t id, uint8_t *eapRespData)
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
                    eap_noob_err_msg(id, eapRespData, E2004);
                    return;
                }
            }
            // TODO: update SleepTime
        }
    }
    // Build response
    eap_noob_rsp_type_three(eapReqData, size, id, eapRespData);
}

/**
 * eap_noob_process : Process EAP-NOOB requests
 * @eapReqData : EAP request data
 * @methodState : method state
 * @decision : FAIL or SUCC
 * @eapRespData : EAP response data
**/
void eap_noob_process(const uint8_t *eapReqData, uint8_t *methodState, uint8_t *decision, uint8_t *eapRespData)
{
    if (reqMethod == EAP_NOOB && reqCode == REQUEST_CODE) {
        *(methodState) = CONT;
        *(decision) = FAIL;

        size_t size;
        size = NTOHS(reqLength) - 5;

        struct jsonparse_state req_obj;
        jsonparse_setup(&req_obj, (char *)eapReqData+5, size);

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
