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
#include "aes.h"
#include "jsontree.h"
#include "jsonparse.h"

#define reqId ((struct eap_msg *)eapReqData)->id
#define reqMethod ((struct eap_msg *)eapReqData)->method
#define reqCode ((struct eap_msg *)eapReqData)->code
#define reqLength ((struct eap_msg *)eapReqData)->length

static uint8_t data[1024];

/**
 * json_integer_value : Helper method, get int value of keys
 * @json : JSON object
 * @key : key
 * Returns : value corresponding to key
**/
int json_integer_value(struct jsonparse_state *state, const char *str)
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
 * eap_noob_process :
 * @eapReqData : EAP request data
 * @methodState :
 * @decision :
**/
void eap_noob_process(const uint8_t *eapReqData, uint8_t *methodState, uint8_t *decision)
{
    if (reqMethod == EAP_NOOB && reqCode == REQUEST_CODE) {
        memcpy(data, eapReqData+5, NTOHS(reqLength));

        struct jsonparse_state req_obj;
        jsonparse_setup(&req_obj, data, strlen(data));

        *(methodState) = CONT;
        *(decision) = FAIL;

        int msgtype;
        msgtype = json_integer_value(&req_obj, "Type");

        switch (msgtype) {
            case EAP_NOOB_TYPE_1:
                printf("Message type 1:\n\n");
                printf("%s\n", data);
                break;
            case EAP_NOOB_TYPE_2:
            case EAP_NOOB_TYPE_3:
            case EAP_NOOB_TYPE_4:
            case EAP_NOOB_TYPE_5:
            case EAP_NOOB_TYPE_6:
            case EAP_NOOB_TYPE_7:
            default:
                printf("EAP-NOOB: Unknown EAP-NOOB request received");
                break;
        }
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
