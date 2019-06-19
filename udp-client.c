/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
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
#include "node-id.h"

#include "_cantcoap.h"
#include "uthash.h"


#include <string.h>

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"

// TICKS indicates the print of a log line to measure the time
// a given operation or group of operations take
#define TICKS 0

#define START_INTERVAL      5 * CLOCK_SECOND
#define SEND_INTERVAL	    5 * CLOCK_SECOND
#define TIMEOUT_INTERVAL    5 * CLOCK_SECOND

#include "eap-peer.h"


static struct uip_udp_conn *client_conn;
static uint8_t seq_number;
static uint32_t currentPort;

/*---------------------------------------------------------------------------*/
PROCESS(boostrapping_service_process, "CoAP-EAP Bootstrapping Service");
AUTOSTART_PROCESSES(&boostrapping_service_process);
/*---------------------------------------------------------------------------*/
uint8_t 	sent	 [170];
uint8_t 	received [170];
uint16_t 	sent_len;
uint16_t 	received_len;
char 		URI[8] = {'/','b','o','o','t', 0, 0, 0};

uint8_t resent = 0;
uint8_t nAuth = 0;

static struct etimer et;
uint32_t nonce_c, nonce_s;

unsigned char auth_key[16] = {0};
unsigned char sequence[26] = {0};

uint8_t authKeyAvailable;
uint8_t state;
static uint8_t last_seq_id = 0;

char URIcheck[10] = {0};
uint16_t URIcheck_len;


CoapPDU *response, *request;


static void
tcpip_handler(void)
{

	if(uip_newdata()) {

#if TICKS
	printf("tick %d\n",last_seq_id);
#endif

		// Check for retransmission
		if(memcmp(uip_appdata, received ,uip_datalen()) == 0)
		{
			uip_udp_packet_send(client_conn, sent, sent_len);
			return;
		}

		// Store last message received
		memcpy(received, uip_appdata, uip_datalen());
		_CoapPDU_buf_withCPDU(request, (uint8_t*)uip_appdata,uip_datalen());

		if(!validate(request))
			return;

		getURI(request, URIcheck, 10, &URIcheck_len);
		if(memcmp(URIcheck, URI , URIcheck_len) != 0)
			return;

		if(last_seq_id >= ntohs(getMessageID(request))
			|| getType(request) == COAP_ACKNOWLEDGEMENT  )
			return;

			unsigned char *payload, *ptr;
			uint8_t mac2check[16] 	={0};
			uint8_t mac[16] 	={0};
			uint8_t responsecode = COAP_CHANGED;

			if((getCode(request) == COAP_POST)){
				if(!state) {
					//state = 1;
					nonce_s = rand();
					responsecode = COAP_CREATED;

					// We create the sequence
					memcpy(&nonce_c, getPayloadPointer(request),(size_t)getPayloadLength(request));
					ptr = (unsigned char*)&sequence;

					unsigned char label[] = "IETF COAP AUTH";
					memcpy(ptr,label,(size_t)14);
					ptr += 14;

					memcpy(ptr,getTokenPointer(request),(size_t)getTokenLength(request));
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

			//else if((getCode(request) == COAP_PUT)){ // EAP EXCHANGE FINISHED
			else{
				if(eapKeyAvailable){

					do_omac(msk_key, sequence, 26, auth_key);
					authKeyAvailable = TRUE;

					// Verify the AUTH Option

					// Copy the mac
					memcpy(&mac2check,getPDUPointer(request)+getPDULength(request)-16-5,16);
					// Zeroing the mac in meesage
					memcpy(getPDUPointer(request)+getPDULength(request)-16-5,&mac,16);
					// Setting the MAC
					do_omac(auth_key, getPDUPointer(request),getPDULength(request), mac);

					if(memcmp(&mac2check, &mac,16) != 0)
					{
						printf("error");
					}

					memset(mac2check,0,16);


				}

#if TICKS
				printf("tick eap in(%d)\n",last_seq_id);
#endif
				eapReq = TRUE;
				payload = getPayloadPointer(request);
				eap_peer_sm_step(payload);
#if TICKS
				printf("tick eap out(%d)\n",last_seq_id);
#endif

				}
			}
			else{
				// Es el ACK del GET
				return;
			}

#if TICKS
	printf("tick %d\n",last_seq_id);
#endif

			reset(response);
			setVersion(response,1);
			setType(response,COAP_ACKNOWLEDGEMENT);
			setCode(response,responsecode);
			setToken(response,
					getTokenPointer(request),
					(uint8_t)getTokenLength(request));

			setMessageID(response,getMessageID(request));



			if((getCode(request) == COAP_POST)){

				if(! state){
					state++;
					_setURI(response,&URI[0],7);
					setPayload(response, (uint8_t *)&nonce_s, getPayloadLength(request));
				}
				else{
				if(!authKeyAvailable){
					if (eapResp){
						uint16_t len = ntohs( ((struct eap_msg*) eapRespData)->length);
						setPayload(response,eapRespData, len);
					}
				}else{
					addOption(response,COAP_OPTION_AUTH, 16, (uint8_t *)&mac2check);

					do_omac(auth_key, getPDUPointer(response),
							getPDULength(response), mac2check);
					memcpy(getPDUPointer(response)+getPDULength(response)-16,&mac2check,16);
				}
			}
#if TICKS
	printf("tick %d\n",last_seq_id);
#endif

			uip_udp_packet_send(client_conn, getPDUPointer(response), (size_t)getPDULength(response));
#if TICKS
	printf("tick %d\n",last_seq_id);
#endif

			memcpy(sent, getPDUPointer(response), (size_t)getPDULength(response));
			sent_len = getPDULength(response);

		}
	}

	if(authKeyAvailable){
		nAuth++;
		printf("tick finish\n");
		etimer_set(&et, TIMEOUT_INTERVAL * CLOCK_SECOND);
		return;
	}

	etimer_set(&et, TIMEOUT_INTERVAL * CLOCK_SECOND);


}


/*---------------------------------------------------------------------------*/
	static void
timeout_handler(void)
{
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


	printf("tick init\n");

	reset(request);
	setVersion(request,1);
	setType(request,COAP_CONFIRMABLE);
	setCode(request,COAP_POST);
	int token=1;
	setToken(request,(uint8_t*)&token,4);
	setMessageID(request,htons(0x0000));
	_setURI(request,"/boot",5); // CoAP URI to start communication with CoAP-EAP Controller

#if TICKS
	printf("tick init\n");
#endif
	uip_udp_packet_send(client_conn,getPDUPointer(request),(size_t)getPDULength(request));
#if TICKS
	printf("tick init\n");
#endif
	etimer_set(&et, TIMEOUT_INTERVAL * CLOCK_SECOND);


}
/*---------------------------------------------------------------------------*/
	static void
print_local_addresses(void)
{
	int i;
	uint8_t state;

	printf("Client IPv6 addresses: ");
	for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
		state = uip_ds6_if.addr_list[i].state;
		if(uip_ds6_if.addr_list[i].isused &&
				(state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
			PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
			printf("\n");
		}
	}
}
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
	//printf("UDP client process started\n");

#if UIP_CONF_ROUTER
	set_global_address();
#endif

	print_local_addresses();
	rand();
	set_connection_address(&ipaddr);

	currentPort = 3000;

	/* new connection with remote host */
	client_conn = udp_new(&ipaddr, UIP_HTONS(5683), NULL);
	udp_bind(client_conn, UIP_HTONS( (currentPort) )  );

	//printf("Created a connection with the server ");
	PRINT6ADDR(&client_conn->ripaddr);
	printf(" local/remote port %u/%u\n",UIP_HTONS(client_conn->lport), UIP_HTONS(client_conn->rport));


	etimer_set(&et, START_INTERVAL);
	PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
	etimer_set(&et, 1*CLOCK_SECOND);


	request = _CoapPDU();
	response = _CoapPDU();

	while(1) {
		PROCESS_YIELD();
		if(etimer_expired(&et) ) {
			timeout_handler();
		} else if(ev == tcpip_event) {
			tcpip_handler();
		}
	}


	PROCESS_END();
}
/*---------------------------------------------------------------------------*/
