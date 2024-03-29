/* Copyright (c) 2012, Pedro Moreno Sánchez
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the University of Murcia nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */


#include "eap-peer.h"

#if EDU_DEBUG
//Stack guard
// #include "sys/stack-check.h"
#endif

#define reqIdPeer ((struct eap_msg *)msg)->id
#define reqMethodPeer ((struct eap_msg *)msg)->method
#define reqLengthPeer ((struct eap_msg *)msg)->length

//Build the Identity message
static void buildIdentity(const uint8_t id){
	char nai[MAX_NAI_LEN];
	eap_noob_build_identity(nai);

	((struct eap_msg*) eapRespData)->code = RESPONSE_CODE;
	((struct eap_msg*) eapRespData)->id = id;
	((struct eap_msg*) eapRespData)->length = HTONS(sizeof(struct eap_msg) + strlen(nai) + 1);
	((struct eap_msg*) eapRespData)->method = IDENTITY;
	memcpy(eapRespData + 5, nai, strlen(nai)+1);
}

/**
 * eap_peer_sm_step : EAP peer state machine step function
 * @msg : EAP request data
**/
void eap_peer_sm_step(const uint8_t* msg){

	//INITIALIZE STATE
	if (eapRestart){

		selectedMethod = NONE;
		methodState = NONE;
		decision = FAIL;
		lastId = NONE;
		eapSuccess = FALSE;
		eapFail = FALSE;
		eapKeyAvailable = FALSE;

		//Initialition out of standard
		eapReq = FALSE;
		eapResp = FALSE;
		eapNoResp = FALSE;
		memset (eapRespData, 0, EAP_MSG_LEN);
		// initMethodEap();

		eapRestart=FALSE;
		return;
	}

	//IDLE STATE
	if (msg == NULL){
		return;
	}

	//RECEIVED STATE
	if (eapReq){
		//parseEapReq(msg);
		//if ((type_received == RxSUCCESS) && (reqIdPeer == lastId) && (decision!=FAIL)){
		if ( ( ((struct eap_msg *)msg)->code == SUCCESS_CODE) && (reqIdPeer == lastId) && (decision!=FAIL)){
			goto _SUCCESS;
		}

		//else if (methodState!=CONT && ( ((type_received == RxFAILURE) && decision != UNCOND_SUCC) || (type_received == RxSUCCESS && decision==FAIL) ) && (reqIdPeer == lastId) ){
		else if (methodState!=CONT && ( (( ((struct eap_msg *)msg)->code == FAILURE_CODE) && decision != UNCOND_SUCC) || (( ((struct eap_msg *)msg)->code == SUCCESS_CODE) && decision==FAIL) ) && (reqIdPeer == lastId) ){
			goto _FAILURE;
		}

		//else if (type_received == RxREQ && reqIdPeer == lastId){
		else if (( ((struct eap_msg *)msg)->code == REQUEST_CODE) && reqIdPeer == lastId){
			//RETRANSMIT STATE
			goto _SEND_RESPONSE;
		}

		//else if ((type_received == RxREQ) && (reqIdPeer!=lastId) && (selectedMethod == NONE) && (reqMethodPeer==IDENTITY)){
		else if (( ((struct eap_msg *)msg)->code == REQUEST_CODE) && (reqIdPeer!=lastId) && (selectedMethod == NONE) && (reqMethodPeer==IDENTITY)){
			//processIdentity(msg); //TODO: Deploy this. It can be avoided?
			buildIdentity( reqIdPeer );
			goto _SEND_RESPONSE;
		}

		//else if ((type_received == RxREQ) && (reqIdPeer!=lastId) && (selectedMethod == NONE) && (reqMethodPeer != IDENTITY) ){
		else if (( ((struct eap_msg *)msg)->code == REQUEST_CODE) && (reqIdPeer!=lastId) && (selectedMethod == NONE) && (reqMethodPeer != IDENTITY) ){
			//GET_METHOD STATE
			//if (allowMethod(reqMethodPeer)){
			if (reqMethodPeer == EAP_PSK){ //We can do this because only EAP-PSK is supported
				selectedMethod = reqMethodPeer;
				methodState = INIT;
			} else if (reqMethodPeer == EAP_NOOB) {
                selectedMethod = reqMethodPeer;
                methodState = INIT;
            } else {
				//TODO: It is necessary build a Nak message here
                printf("Req: %d\n", reqMethodPeer);
			}
			if (selectedMethod == reqMethodPeer) goto _METHOD;
			else goto _SEND_RESPONSE;
		}

		//else if ((type_received == RxREQ) && (reqIdPeer!=lastId) && (reqMethodPeer==selectedMethod) && (methodState != DONE)){
		else if (( ((struct eap_msg *)msg)->code == REQUEST_CODE) && (reqIdPeer!=lastId) && (reqMethodPeer==selectedMethod) && (methodState != DONE)){
			goto _METHOD;
		}


		else goto _DISCARD;


	}
	else if ((altAccept && decision != FAIL)) goto _SUCCESS;

	else if (altReject || (altAccept && methodState != CONT && decision == FAIL)) goto _FAILURE;

	else goto _DISCARD;

_FAILURE:
	//FAILURE STATE
    printf("EAP-PEER: FAILURE STATE\n");
	eapFail = TRUE;
	return;

_SUCCESS:
	//SUCCESS STATE
    printf("EAP-PEER: SUCCESS STATE\n");
	eapSuccess = TRUE;
	return;

_METHOD:
	//METHOD STATE
    printf("EAP-PEER: METHOD STATE\n");
	/* Condition removed. _METHOD is called if this condition is TRUE:
	 && ((struct eap_msg *)eapRespData)->code == REQUEST_CODE
	*/
	if (((struct eap_msg *)msg)->method == EAP_NOOB) {
		((struct eap_msg *)eapRespData)->code = RESPONSE_CODE;
		((struct eap_msg *)eapRespData)->id = reqIdPeer;
		((struct eap_msg *)eapRespData)->method = (uint8_t)EAP_NOOB;

		uint8_t eapPayload[EAP_MSG_LEN]; // EAP Payload
		size_t eapRespLen = 0; // EAP Payload Length

		eap_noob_process(msg+5, NTOHS(reqLengthPeer) - 5, &methodState, &decision, eapPayload, &eapRespLen);

		((struct eap_msg *)eapRespData)->length = HTONS(sizeof(struct eap_msg)+ eapRespLen + 1);
		memcpy(eapRespData + 5, eapPayload, eapRespLen+1);


		goto _SEND_RESPONSE;
	} else if (((struct eap_msg *)msg)->method == EAP_PSK) {
        goto _DISCARD; // TODO: add support for EAP-PSK
    }
	else goto _DISCARD;

_SEND_RESPONSE:
	//SEND_RESPONSE STATE
	printf("EAP-PEER: SEND_RESPONSE STATE\n");
	lastId = reqIdPeer;
	eapReq = FALSE;
	eapResp = TRUE;
	return;

_DISCARD:
	//DISCARD STATE
	printf("EAP-PEER: DISCARD STATE\n");
	eapReq = FALSE;
	eapNoResp = TRUE;
	return;
}
