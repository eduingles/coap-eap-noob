/*
 *  Copyright (c) 2019, University of Murcia
 *
 *  Copyright (C) Dan García Carrillo.
 *  Copyright (C) Eduardo Inglés Sánchez.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University of Murcia nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"

#include "uthash.h"
#include "eax.h" //do_omac()

// ECC implementation
#include "include.h"
#include "ecc_pubkey.h"
#include "sys/process.h" // process_start()

// CoAP Library (Contiki - Erbium)
#include "os/net/app-layer/coap/coap.h"
#include "os/net/app-layer/coap/coap.c"

#include <string.h>

#define DEBUG DEBUG_PRINT
// #include "net/ipv6/uip-debug.h" // print_local_addresses() y PRINT6ADDR()

#define START_INTERVAL      5 * CLOCK_SECOND
#define SEND_INTERVAL	    5 * CLOCK_SECOND

#include "eap-peer.h"


static struct uip_udp_conn *client_conn;
static uint32_t currentPort;
#define UDP_CLIENT_PORT 3000
#define UDP_SERVER_PORT 5683
/*---------------------------------------------------------------------------*/
PROCESS(boostrapping_service_process, "CoAP-EAP Bootstrapping Service");
AUTOSTART_PROCESSES(&boostrapping_service_process);
/*---------------------------------------------------------------------------*/
/* Saving locally UDP messages sent or received */
uint8_t 	sent	 [400]; //TODO: Fit value
uint8_t 	received [400]; //TODO: Fit value
uint16_t 	sent_len;
uint16_t 	received_len;
char 		URI[8] = {'/','b','o','o','t', 0, 0, 0}; // CoAP

uint8_t resent = 0;
uint8_t nAuth = 0;

static struct etimer et;
uint32_t nonce_c, nonce_s; //EDU: TODO: See usage

unsigned char auth_key[16] = {0};
unsigned char sequence[26] = {0};

uint8_t authKeyAvailable;
//TODO: Define usage of var state
uint8_t state;
static uint8_t last_seq_id = 0;

char URIcheck[10] = {0}; //DAN: CoAP
uint16_t URIcheck_len; //DAN: CoAP


// CoapPDU *response, *request; //DAN: CoAP
static coap_message_t response[1], request[1]; //EDU: CoAP


static void
tcpip_handler(void)
{

	if(uip_newdata()) {
		// Check for retransmission
		if(memcmp(uip_appdata, received ,uip_datalen()) == 0)
		{
			uip_udp_packet_send(client_conn, sent, sent_len);
			return;
		}

		// Store last message received
		memcpy(received, uip_appdata, uip_datalen());
		// _CoapPDU_buf_withCPDU(request, (uint8_t*)uip_appdata,uip_datalen()); //DAN: CoAP

		/* Parse CoAP message stored in UDP payload */
		coap_parse_message(request, (uint8_t*)uip_appdata,uip_datalen()); //EDU: CoAP

		// EDU: Already done in coap_parse_message
		// if(!validate(request)) //DAN: CoAP
		// 	return;
		// int URIcheck_len_tmp = (int)URIcheck_len;
		// getURI(request, URIcheck, 10, &URIcheck_len_tmp ); //DAN: CoAP
		// if(memcmp(URIcheck, URI , URIcheck_len) != 0) //DAN: CoAP
		// 	return;

		//EDU: Dan says it is a hack
		// if(last_seq_id >= ntohs(getMessageID(request)) || getType(request) == COAP_ACKNOWLEDGEMENT ) //DAN: CoAP
		// 	return;

		unsigned char *payload, *ptr; //TODO: ptr usage?? Maybe remove it
		uint8_t mac2check[16] 	={0};
		uint8_t mac[16] 	={0};
		uint8_t response_code = CHANGED_2_04;

		// if((getCode(request) == COAP_POST)){ //DAN: CoAP
		if((request->code == COAP_POST)){ //DAN: CoAP
			if(!state) {
				//state = 1;
				nonce_s = rand();
				response_code = CREATED_2_01;

				// We create the sequence
				// memcpy(&nonce_c, getPayloadPointer(request),(size_t)getPayloadLength(request)); //DAN: CoAP
				memcpy(&nonce_c, request->payload,request->payload_len); //EDU: CoAP
				ptr = (unsigned char*)&sequence;

				unsigned char label[] = "IETF COAP AUTH";
				memcpy(ptr,label,(size_t)14);
				ptr += 14;

				memcpy(ptr, request->token,request->token_len); //DAN: CoAP
				ptr += 4;

				memcpy(ptr, &(nonce_c),sizeof(uint32_t));
				ptr += 4;

				memcpy(ptr, &(nonce_s),sizeof(uint32_t));


				// EAP Restart
				memset(&msk_key,0, MSK_LENGTH);
				eapRestart=TRUE;
				eap_peer_sm_step(NULL);

				// creating the id of the service
				URI[5] = '/';
				URI[6] = '0' + (rand() % 9);
			}

			else{
				if(eapKeyAvailable){
					do_omac(msk_key, sequence, 26, auth_key);
					authKeyAvailable = TRUE;

					// Verify the AUTH Option

					// Copy the mac
					memcpy(&mac2check,request->payload+request->payload_len-16-5,16); //DAN: CoAP
					// Zeroing the mac in meesage
					memcpy(request->payload+request->payload_len-16-5,&mac,16); //DAN: CoAP
					// Setting the MAC
					do_omac(auth_key, request->payload,request->payload_len, mac); //DAN: CoAP

					if(memcmp(&mac2check, &mac,16) != 0)
					{
						printf("error\n");
					}

					memset(mac2check,0,16);


				}

				eapReq = TRUE;
				payload = request->payload;
#if EDU_DEBUG
				printf("EDU: %s print PayLoad\n",__func__); //EDU: DEBUG
				printf("      Request Hdr: '");
				for (int i = 0; i < 2; i++)
					printf("%02x ", request->payload[i]);
				printf("'\n");
				printf("      Value: '");
				for (int i = 0; i < 5; i++)
					printf("%02x", payload[i]);
				for (int i = 5; i < request->payload_len; i++) //EDU: CoAP
					printf("%c", payload[i]);
				printf("'\n");
#endif

				eap_peer_sm_step(payload);
				if (((struct eap_msg *)payload)->code == FAILURE_CODE){
					etimer_stop(&et);
					printf("EAP-Failure received\n");
					#if EDU_DEBUG
						printf("EDU: %s Set TIMEOUT_INTERVAL after EAP-Failure\n", __func__); //EDU: DEBUG
					#endif
					// etimer_restart(&et);
					etimer_set(&et, 10 * CLOCK_SECOND);
					return;
				}
			}
		}
		else{
			// Got ACK from GET
			return;
		}

		// reset(response); //DAN: CoAP
		// setVersion(response,1); //DAN: CoAP
		// setType(response,COAP_ACKNOWLEDGEMENT); //DAN: CoAP
		// setCode(response,responsecode); //DAN: CoAP
		/*
		 FIXME: setToken -> Null Pointer in coap_pdu->_pduLength
		  Error solved with COAP_PAYLOAD_SIZE = 400
		*/
		// setToken(response,
		// 		getTokenPointer(request),
		// 		(uint8_t)getTokenLength(request)); //DAN: CoAP

		// setMessageID(response,getMessageID(request)); //DAN: CoAP

		/* reset CoAP response with new response_code and request message ID */
		coap_init_message(response, COAP_TYPE_ACK, response_code, request->mid); //EDU: CoAP
		/* Set request token and message ID */
		coap_set_token(response, request->token, request->token_len); //EDU: CoAP
		

#if EDU_DEBUG
		unsigned char *tmpPayload;
		printf("EDU: %s print PayLoad again\n",__func__); //EDU: DEBUG
		printf("      Request Hdr: '");
		for (int i = 0; i < 2; i++)
			printf("%02x ", request->buffer[i]);
		printf("'\n");
		printf("      Value: '");
		tmpPayload = request->payload; //EDU: CoAP
		for (int i = 0; i < 5; i++)
			printf("%02x", tmpPayload[i]);
		for (int i = 5; i < request->payload_len; i++) //EDU: CoAP
			printf("%c", tmpPayload[i]);
		printf("'\n");
#endif

#if EDU_DEBUG
	printf("EDU:  if getCode(request) == COAP_POST\n");
#endif
		if(request->code == COAP_POST){ //EDU: CoAP
#if EDU_DEBUG
	printf("EDU:  YES getCode(request) == COAP_POST\n");
#endif
			if(! state){
				#if EDU_DEBUG
					printf("EDU:  no state\n");
				#endif
				state++;
				// _setURI(response,&URI[0],7); //DAN: CoAP
				// setPayload(response, (uint8_t *)&nonce_s, getPayloadLength(request)); //DAN: CoAP
				coap_set_header_uri_path(response, URI); //EDU: CoAP -> _setURI()
				printf("EDU: ---------------------------\n");
				printf("EDU: SET PAYLOAD NONCE_S\n");
				printf("EDU: ---------------------------\n");
				coap_set_payload(response, (uint8_t *)&nonce_s, request->payload_len); //EDU: CoAP
			} else{
				#if EDU_DEBUG
					printf("EDU:  YES state\n");
				#endif
				if(!authKeyAvailable){
					if (eapResp){
						uint16_t len = NTOHS( ((struct eap_msg*) eapRespData)->length);
						// setPayload(response,eapRespData, len); //DAN: CoAP
						coap_set_payload(response, eapRespData, len); //EDU: CoAP
				printf("EDU: ---------------------------\n");
				printf("EDU: SET PAYLOAD EAP RESP DATA\n");
				printf("EDU: ---------------------------\n");
					}
				}else{
					/**
					 * TODO: Several issues
					 * - CoAP library (Contiki) does not support COAP_OPTION_AUTH
					 * - Check if this code snippet is needed.
					 * - Do we need mac2check in EAP-NOOB?
					 */
					// addOption(response,COAP_OPTION_AUTH, 16, (uint8_t *)&mac2check); //DAN: CoAP
					// do_omac(auth_key, getPDUPointer(response),
					// 		getPDULength(response), mac2check); //DAN: CoAP
					// memcpy(getPDUPointer(response)+getPDULength(response)-16,&mac2check,16); //DAN: CoAP
				}
			}

			static uint8_t udp_payload[300];
			size_t coap_len = coap_serialize_message(response, udp_payload); //EDU: TODO: Buffer with or without \0?
			uip_udp_packet_send(client_conn, udp_payload, coap_len);
			memcpy(sent, udp_payload, coap_len); //DAN: CoAP
			sent_len = coap_len; //DAN: CoAP
		}
	}

	if(authKeyAvailable){
		nAuth++;
		printf("tick finish\n");
		etimer_set(&et, 5 * CLOCK_SECOND);
		return;
	}
#if EDU_DEBUG
	printf("EDU: %s set TIMEOUT_INTERVAL\n", __func__); //EDU: DEBUG
#endif
	etimer_set(&et, 20 * CLOCK_SECOND);
}

/*---------------------------------------------------------------------------*/
	static void
timeout_handler(void)
{
#if EDU_DEBUG
	printf("EDU: %s init\n", __func__); //EDU: DEBUG
#endif
	etimer_stop(&et);

	last_seq_id = 0;
	etimer_restart(&et);
	state = 0;

	memset(&msk_key,0, MSK_LENGTH);
	eapRestart=TRUE;
	eap_peer_sm_step(NULL);

	memset(&auth_key,0, 16);
	memset(&sequence,0, 26);

	authKeyAvailable = 0;
	currentPort++;

	udp_bind(client_conn, UIP_HTONS( (currentPort) )  );
	printf("Send /boot to CoAP-EAP Controller to start communication.\n");
			printf("EDU: UDP-CLIENT 1\n");

	// reset(request); //DAN: CoAP
	// setVersion(request,1); //DAN: CoAP
	// setType(request,COAP_CONFIRMABLE); //DAN: CoAP
	// setCode(request,COAP_POST); //DAN: CoAP
	// int token=1; //DAN: CoAP
	// setToken(request,(uint8_t*)&token,4); //DAN: CoAP
	// setMessageID(request,htons(0x0000)); //DAN: CoAP
	// _setURI(request,"/boot",5); //DAN: CoAP // CoAP URI to start communication with CoAP-EAP Controller

	/* Initiate request: NON_CONFIRMABLE, POST, MessageID = 0 */
	coap_init_message(request, COAP_TYPE_NON, COAP_POST, 0); //EDU: CoAP
	/* Set empty payload */
	coap_set_payload(request, "", 0);
	/* Set CoAP header values: 
	version = 1 by default
	message ID starts with 0.
	token: It does not matter. Set to 1. TODO: Change tu uint_8 - size 1
	*/
			printf("EDU: UDP-CLIENT 2\n");
	uint8_t token=1;
	coap_set_token(request, &token, 1); //EDU: CoAP
	/* Set URI path */
			printf("EDU: UDP-CLIENT 3\n");
	coap_set_header_uri_path(request, "/boot"); //EDU: CoAP -> _setURI()
			printf("EDU: UDP-CLIENT 4\n");

	/* Put CoAP message (header and payload) in buffer. It returns the length */
	static uint8_t udp_payload[100];
	udp_payload[0] = 0x00;
			printf("EDU: UDP-CLIENT 5\n");
	size_t coap_len = coap_serialize_message(request, udp_payload); //EDU: TODO: Buffer with or without \0?
			printf("EDU: UDP-CLIENT 6\n");
	
	uip_udp_packet_send(client_conn, udp_payload, coap_len);
			printf("EDU: UDP-CLIENT 7\n");
	etimer_set(&et, 40 * CLOCK_SECOND);
}
/*---------------------------------------------------------------------------*/
// 	static void
// print_local_addresses(void)
// {
// 	int i;
// 	uint8_t state;

// 	printf("Client IPv6 addresses: ");
// 	for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
// 		state = uip_ds6_if.addr_list[i].state;
// 		if(uip_ds6_if.addr_list[i].isused &&
// 				(state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
// 			PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
// 			printf("\n");
// 		}
// 	}
// }
/*---------------------------------------------------------------------------*/
#if UIP_CONF_ROUTER
	static void
set_global_address(void)
{
	uip_ipaddr_t ipaddr;

	uip_ip6addr(&ipaddr, 0xfd00, 0, 0, 0, 0, 0, 0, 0);
	uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
	uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);
}
#endif /* UIP_CONF_ROUTER */
/*---------------------------------------------------------------------------*/
	static void
set_connection_address(uip_ipaddr_t *ipaddr)
{
#define _QUOTEME(x) #x
#define QUOTEME(x) _QUOTEME(x)
#ifdef UDP_CONNECTION_ADDR
	if(uiplib_ipaddrconv(QUOTEME(UDP_CONNECTION_ADDR), ipaddr) == 0) {
		printf("UDP client failed to parse address '%s'\n", QUOTEME(UDP_CONNECTION_ADDR));
	}
#elif UIP_CONF_ROUTER
	uip_ip6addr(ipaddr,0xfd00,0,0,0,0,0,0,0x1);
#else
	uip_ip6addr(ipaddr,0xfe80,0,0,0,0x6466,0x6666,0x6666,0x6666);
#endif /* UDP_CONNECTION_ADDR */
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(boostrapping_service_process, ev, data)
{
	uip_ipaddr_t ipaddr;

	PROCESS_BEGIN();
#if UIP_CONF_ROUTER
	set_global_address();
#endif
	/* Initialize UDP connection */
	// print_local_addresses();
	rand();
	set_connection_address(&ipaddr);
	currentPort = 3000;
	/* new connection with remote host */
	client_conn = udp_new(&ipaddr, UIP_HTONS(5683), NULL);
	udp_bind(client_conn, UIP_HTONS( (currentPort) )  );

	printf("Created a connection with the server ");
	// PRINT6ADDR(&client_conn->ripaddr);
	printf(" local/remote port %u/%u\n",UIP_HTONS(client_conn->lport), UIP_HTONS(client_conn->rport));

	// request = _CoapPDU(); //DAN: CoAP
	// response = _CoapPDU(); //DAN: CoAP
	// coap_init_connection(void); // TODO: Initiate CoAP message ID with rand number.
	coap_init_message(request, COAP_TYPE_NON, COAP_POST, 0); //EDU: CoAP

	//TODO: Move to EAP-Peer
	//TODO: Differentiate between EAP_NOOB and EAP_PSK
	init_eap_noob();

	etimer_set(&et, START_INTERVAL);
	PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

	// ECDH - Generate Client Public Key
	process_start(&ecdh_generate_pubkey, NULL);

	PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_CONTINUE && data != NULL && strcmp(data, "pubkey_generated") == 0);
	printf("Client Public Key Generated\n");
	// ECDH - end
	etimer_set(&et, 1*CLOCK_SECOND);

	while(1) {
#if EDU_DEBUG
		printf("EDU: while(1)\n"); //EDU: DEBUG
#endif
		PROCESS_YIELD();
#if EDU_DEBUG
		printf("EDU: while(1) 2\n"); //EDU: DEBUG
#endif
		if(NETSTACK_ROUTING.node_is_reachable()) {
			if(etimer_expired(&et) ) {
				timeout_handler();
			} else if(ev == tcpip_event) {
				tcpip_handler();
			} else if(ev == PROCESS_EVENT_CONTINUE && data != NULL && strcmp(data, "sharedkey_generated") == 0) {
				printf("Generated shared secret\n");
			} else {
				printf("Received another kind of event\n");
				// timeout_handler();
			}
		} else {
			printf("BR not reachable\n");
			etimer_set(&et, 2 * CLOCK_SECOND);
		}
	}
	PROCESS_END();
}
/*---------------------------------------------------------------------------*/
