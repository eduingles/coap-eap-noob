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

#include "_cantcoap.h"
#include "uthash.h"
#include "eax.h" //do_omac()

// ECC implementation
#include "include.h"
#include "ecc_pubkey.h"
#include "sys/process.h" // process_start()

// static const unsigned char base64_table[65] =
// 	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * base64_decode - Base64 decode
	* @src: Data to be decoded
	* @len: Length of the data to be decoded
	* @out_len: Pointer to output length variable
	* Returns: Allocated buffer of out_len bytes of decoded data,
	* or %NULL on failure
	*
	* Caller is responsible for freeing the returned buffer.
	*/

	// static void base64_decode(const unsigned char *src, size_t len, size_t *out_len, unsigned char *dst)
	// {
	// 	if (src == NULL)
	// 		printf("base64_decode: src NULL\n");
	// 	if (dst == NULL)
	// 		printf("base64_decode: dst NULL\n");
	// 	if (out_len == NULL)
	// 		printf("base64_decode: outlen NULL\n");
	// 	if (len == NULL)
	// 		printf("base64_decode: len == 0\n");


	// 	unsigned char dtable[256], *pos, block[4], tmp;
	// 	size_t i, count, olen;
	// 	int pad = 0;

	// 	memset(dtable, 0x80, 256);
	// 	for (i = 0; i < sizeof(base64_table) - 1; i++)
	// 		dtable[base64_table[i]] = (unsigned char) i;
	// 	dtable['='] = 0;

	// 	count = 0;
	// 	for (i = 0; i < len; i++) {
	// 		if (dtable[src[i]] != 0x80)
	// 			count++;
	// 	}

	// 	if (count == 0 || count % 4)
	// 		return NULL;

	// 	olen = count / 4 * 3;
	// 	unsigned char out[olen];
	// 	pos = out;
	// 	if (out == NULL)
	// 		return NULL;

	// 	count = 0;
	// 	for (i = 0; i < len; i++) {
	// 		tmp = dtable[src[i]];
	// 		if (tmp == 0x80)
	// 			continue;

	// 		if (src[i] == '=')
	// 			pad++;
	// 		block[count] = tmp;
	// 		count++;
	// 		if (count == 4) {
	// 			*pos++ = (block[0] << 2) | (block[1] >> 4);
	// 			*pos++ = (block[1] << 4) | (block[2] >> 2);
	// 			*pos++ = (block[2] << 6) | block[3];
	// 			count = 0;
	// 			if (pad) {
	// 				if (pad == 1)
	// 					pos--;
	// 				else if (pad == 2)
	// 					pos -= 2;
	// 				else {
	// 					/* Invalid padding */
	// 					return NULL;
	// 				}
	// 				break;
	// 			}
	// 		}
	// 	}

	// 	*out_len = pos - out;
	// 	memcpy(dst, out, *out_len+1);
	// 	// return out;
	// }


// /**
//  * base64_encode : Base64 encoding
	//  * @src: data to be encoded
	//  * @len: length of the data to be encoded
	//  * @out_len: pointer to output length variable, or NULL if not used
	//  */
	// static void base64_encode(const unsigned char *src, size_t len, size_t *out_len, unsigned char *dst)
	// {
	// 	unsigned char *pos;
	// 	const unsigned char *end, *in;
	// 	size_t olen;
	// 	int line_len;

	// 	olen = len * 4 / 3 + 4; // 3-byte blocks to 4-byte
	// 	olen += olen / 72;      // line feeds
	// 	olen++;                 // null termination
	// 	if (olen < len)
	//         return NULL;        // integer overflow

	//     unsigned char out[olen];
	// 	if (out == NULL)
	// 		return NULL;

	// 	end = src + len;
	// 	in = src;
	// 	pos = out;
	// 	line_len = 0;
	// 	while (end-in >= 3) {
	// 		*pos++ = base64_table[in[0] >> 2];
	// 		*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
	// 		*pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
	// 		*pos++ = base64_table[in[2] & 0x3f];
	// 		in += 3;
	// 		line_len += 4;
	// 		if (line_len >= 72)
	// 			line_len = 0;
	// 	}
	// 	if (end-in) {
	// 		*pos++ = base64_table[in[0] >> 2];
	// 		if (end-in == 1) {
	// 			*pos++ = base64_table[(in[0] & 0x03) << 4];
	// 			// *pos++ = '=';
	// 		} else {
	// 			*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
	// 			*pos++ = base64_table[(in[1] & 0x0f) << 2];
	// 		}
	// 		// *pos++ = '=';
	// 	}
	// 	*pos = '\0';
	// 	if (out_len)
	// 		*out_len = pos - out;

	//     uint16_t strlen_tmp = *out_len;
	//     memcpy(dst, out, *out_len+1);
	// }




// static void
// ecc_set_random(uint32_t *secret)
	// {
	//   int i;
	// //   printf("EDU: ecc_set_random: ");

	//   for(i = 0; i < 8; ++i) {
	//     secret[i] = (uint32_t)random_rand() | (uint32_t)random_rand() << 16;
	//     // printf("%u ", (unsigned int)secret[i]);
	//   }
	// //   printf("\n");
	// }

#include <string.h>

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"

// TICKS indicates the print of a log line to measure the time
// a given operation or group of operations take
#define TICKS 0

#define START_INTERVAL      5 * CLOCK_SECOND
#define SEND_INTERVAL	    5 * CLOCK_SECOND

#include "eap-peer.h"


static struct uip_udp_conn *client_conn;
static uint32_t currentPort;

/*---------------------------------------------------------------------------*/
PROCESS(boostrapping_service_process, "CoAP-EAP Bootstrapping Service");
AUTOSTART_PROCESSES(&boostrapping_service_process);
/*---------------------------------------------------------------------------*/
uint8_t 	sent	 [400];
uint8_t 	received [400];
uint16_t 	sent_len;
uint16_t 	received_len;
char 		URI[8] = {'/','b','o','o','t', 0, 0, 0};

uint8_t resent = 0;
uint8_t nAuth = 0;

static struct etimer et;
uint32_t nonce_c, nonce_s;

unsigned char auth_key[16] = {0};
unsigned char sequence[26] = {0};

uint8_t authKeyAvailable; 	//EDU: static
uint8_t state;				 //EDU: static
static uint8_t last_seq_id = 0;

char URIcheck[10] = {0};
uint16_t URIcheck_len;


CoapPDU *response, *request;


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
		_CoapPDU_buf_withCPDU(request, (uint8_t*)uip_appdata,uip_datalen());

		if(!validate(request))
			return;

		getURI(request, URIcheck, 10, &URIcheck_len);
		if(memcmp(URIcheck, URI , URIcheck_len) != 0)
			return;

		if(last_seq_id >= ntohs(getMessageID(request)) || getType(request) == COAP_ACKNOWLEDGEMENT )
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
						printf("error\n");
					}

					memset(mac2check,0,16);


				}

				eapReq = TRUE;
				payload = getPayloadPointer(request);
#if EDU_DEBUG
				printf("EDU: %s print PayLoad\n",__func__); //EDU: DEBUG
				printf("      Request Hdr: '");
				for (int i = 0; i < 2; i++)
					printf("%02x ", request->_pdu[i]);
				printf("'\n");
				printf("      Value: '");
				for (int i = 0; i < 5; i++)
					printf("%02x", payload[i]);
				for (int i = 5; i < getPDULength(request); i++)
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
		reset(response);
		setVersion(response,1);
		setType(response,COAP_ACKNOWLEDGEMENT);
		setCode(response,responsecode);
		setToken(response,
				getTokenPointer(request),
				(uint8_t)getTokenLength(request));

		setMessageID(response,getMessageID(request));

#if EDU_DEBUG
		unsigned char *tmpPayload;
		printf("EDU: %s print PayLoad again\n",__func__); //EDU: DEBUG
		printf("      Request Hdr: '");
		for (int i = 0; i < 2; i++)
			printf("%02x ", request->_pdu[i]);
		printf("'\n");
		printf("      Value: '");
		tmpPayload = getPayloadPointer(request);
		for (int i = 0; i < 5; i++)
			printf("%02x", tmpPayload[i]);
		for (int i = 5; i < getPDULength(request); i++)
			printf("%c", tmpPayload[i]);
		printf("'\n");
#endif

#if EDU_DEBUG
	printf("EDU:  if getCode(request) == COAP_POST\n");
#endif
		if((getCode(request) == COAP_POST)){
#if EDU_DEBUG
	printf("EDU:  YES getCode(request) == COAP_POST\n");
#endif
			if(! state){
				#if EDU_DEBUG
					printf("EDU:  no state\n");
				#endif
				state++;
				_setURI(response,&URI[0],7);
				setPayload(response, (uint8_t *)&nonce_s, getPayloadLength(request));
			}
			else{
				#if EDU_DEBUG
					printf("EDU:  YES state\n");
				#endif
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

			uip_udp_packet_send(client_conn, getPDUPointer(response), (size_t)getPDULength(response));
			memcpy(sent, getPDUPointer(response), (size_t)getPDULength(response));
			sent_len = getPDULength(response);

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

	reset(request);
	setVersion(request,1);
	setType(request,COAP_CONFIRMABLE);
	setCode(request,COAP_POST);
	int token=1;
	setToken(request,(uint8_t*)&token,4);
	setMessageID(request,htons(0x0000));
	_setURI(request,"/boot",5);// CoAP URI to start communication with CoAP-EAP Controller

	uip_udp_packet_send(client_conn,getPDUPointer(request),(size_t)getPDULength(request));
	etimer_set(&et, 40 * CLOCK_SECOND);

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

	request = _CoapPDU();
	response = _CoapPDU();
	
	//TODO: Move to EAP-Peer
	//TODO: Differentiate between EAP_NOOB and EAP_PSK
	init_eap_noob();

	etimer_set(&et, START_INTERVAL);
	PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
	etimer_set(&et, 1*CLOCK_SECOND);

	// ECDH - Generate Client Public Key
	static bool pubkey_is_generated = false;
	static char pubkey_generated[] = "pubkey_generated";
	process_start(&ecdh_generate_pubkey, NULL);
	// ECDH - end
	









	//     static unsigned char pk_str1[33];
	//     for(int i = 0 ;i < 8;i++){
		//         pk_str1[i*4+0] = client_pk.x[i] >> 24;
		//         pk_str1[i*4+1] = client_pk.x[i] >> 16;
		//         pk_str1[i*4+2] = client_pk.x[i] >> 8;
		//         pk_str1[i*4+3] = client_pk.x[i];
		//     }
		// 	pk_str1[32] = '\0';

		//     printf("A PK.X char: ");
		//     for (int i = 0; i < 32; i++)
		//         printf("%u", pk_str1[i]);
		//     printf("\n");

		//     static uint16_t len_b64_x = 0;
		//     static unsigned char pk_x_b64[45];
		//     base64_encode(pk_str1, 33, &len_b64_x, pk_x_b64);

		//     static unsigned char pk_str2[33];
		//     for(int i = 0 ;i < 8;i++){
		//         pk_str2[i*4+0] = client_pk.y[i] >> 24;
		//         pk_str2[i*4+1] = client_pk.y[i] >> 16;
		//         pk_str2[i*4+2] = client_pk.y[i] >> 8;
		//         pk_str2[i*4+3] = client_pk.y[i];
		//     }
		// 	pk_str2[33] = '\0';

		//     printf("A PK.Y char: ");
		//     for (int i = 0; i < 33; i++)
		//         printf("%u", pk_str2[i]);
		//     printf("\n");

		//     static uint16_t len_b64_y = 0;
		//     static unsigned char pk_y_b64[45];
		//     base64_encode(pk_str2, 33, &len_b64_y, pk_y_b64);

		//   	puts("    	  DECODE SIDE A");
		//     static unsigned char pk_str3[33];
		//     static unsigned char pk_str4[33];
		// 	static uint32_t pk_uint3[8];
		// 	static uint32_t pk_uint4[8];
		// 	static uint16_t len_plain = 0;
		// 	static uint16_t len_plain2 = 0;

		// 	base64_decode(pk_x_b64, len_b64_x, &len_plain, pk_str3);
		//     printf("PK.X %02u chr: ", len_plain);    
		//     for (int i = 0; i < 32; i++)
		//         printf("%u", pk_str3[i]);
		//     printf("\n");

		// 	for (int i = 0; i < 32; i += 4)
		// 		pk_uint3[i/4] = pk_str3[i+3] | (uint32_t)pk_str3[i+2] << 8 | (uint32_t)pk_str3[i+1] << 16 | (uint32_t)pk_str3[i] << 24;

		//     printf("    PK.X %02u: ", len_plain);    
		//     for(int i = 0 ;i < 8;i++)
		//         printf("%u",pk_uint3[i]);
		//     printf("\n");
			
		// 	printf("  Orig PK.X: ");
		// 	for(int i = 0; i < 8; ++i)
		// 		printf("%u", (unsigned int)client_pk.x[i]);
		// 	printf("\n");

		// 	base64_decode(pk_y_b64, len_b64_y, &len_plain2, pk_str4);
		//     printf("PK.Y %02u chr: ", len_plain2);    
		//     for (int i = 0; i < 32; i++)
		//         printf("%u", pk_str4[i]);
		//     printf("\n");
		// 	for (int i = 0; i < 32; i += 4)
		// 		pk_uint4[i/4] = pk_str4[i+3] | (uint32_t)pk_str4[i+2] << 8 | (uint32_t)pk_str4[i+1] << 16 | (uint32_t)pk_str4[i] << 24;

		//     printf("    PK.y %02u: ", len_plain2);    
		//     for(int i = 0 ;i < 8;i++)
		//         printf("%u",pk_uint4[i]);
		//     printf("\n");
			
			
		// 	printf("  Orig PK.Y: ");
		// 	for(int i = 0; i < 8; ++i) 
		// 		printf("%u", (unsigned int)client_pk.y[i]);
		// 	printf("\n");





		//   	puts("-----------------------------------------");
		//   	puts("    		  SIDE B ECC PROCESS");
		//   	puts("-----------------------------------------");

		// 	// ECC implementation SIDE B
		// 	pka_init();

		//     static ecc_compare_state_t state2 = {
		//         .process = &boostrapping_service_process,
		//         .size    = 8,
		//     };
		// 	memcpy(state2.b, nist_p_256.n, sizeof(uint32_t) * 8);
		// 	do {
		// 		ecc_set_random(private_secret2);
		// 		memcpy(state2.a, private_secret2, sizeof(uint32_t) * 8);
		// 		PT_SPAWN(&(boostrapping_service_process.pt), &(state2.pt), ecc_compare(&state2));
		// 	} while(state2.result != PKA_STATUS_A_LT_B);
		// 	static ecc_multiply_state_t ecc_client2 = {
		// 		.process    = &boostrapping_service_process,
		// 		.curve_info = &nist_p_256,
		// 	};
		// 	memcpy(ecc_client2.point_in.x, nist_p_256.x, sizeof(uint32_t) * 8);
		// 	memcpy(ecc_client2.point_in.y, nist_p_256.y, sizeof(uint32_t) * 8);
		// 	memcpy(ecc_client2.secret, private_secret2, sizeof(private_secret2));
		// 	PT_SPAWN(&(boostrapping_service_process.pt), &(ecc_client2.pt), ecc_multiply(&ecc_client2)); 
		// 	memcpy(client_pk2.x, ecc_client2.point_out.x, sizeof(uint32_t) * 8);
		// 	memcpy(client_pk2.y, ecc_client2.point_out.y, sizeof(uint32_t) * 8);
			
		// 	pka_disable();

		// 	printf("    B PK.X: ");
		// 	for(int i = 0; i < 8; ++i) {
		// 		printf("%u ", (unsigned int)client_pk2.x[i]);
		// 	}
		// 	printf("\n");
		// 	printf("    B PK.Y: ");
		// 	for(int i = 0; i < 8; ++i) {
		// 		printf("%u ", (unsigned int)client_pk2.y[i]);
		// 	}
		// 	printf("\n");
		// #if EDU_DEBUG
		//   	puts("-----------------------------------------");
		//   	puts("             KEY ECHANGE");
		//   	puts("-----------------------------------------");
		// #endif
		// 	// ECC implementation - end




		// 	pka_init();
		//   /*   * Key Exchange   */
		//   memcpy(ecc_client.point_in.x, ecc_client2.point_out.x, sizeof(uint32_t) * 8);
		//   memcpy(ecc_client.point_in.y, ecc_client2.point_out.y, sizeof(uint32_t) * 8);
		//   memcpy(ecc_client2.point_in.x, pk_uint3, sizeof(uint32_t) * 8);
		//   memcpy(ecc_client2.point_in.y, pk_uint4, sizeof(uint32_t) * 8);
		//   /*   * Round 2   */
		//   PT_SPAWN(&(boostrapping_service_process.pt), &(ecc_client.pt), ecc_multiply(&ecc_client));

		//     	// puts("-----------------------------------------1");

		//   PT_SPAWN(&(boostrapping_service_process.pt), &(ecc_client2.pt), ecc_multiply(&ecc_client2));
		//     	// puts("-----------------------------------------2");

		//   memcpy(state1.a, ecc_client.point_out.x, sizeof(uint32_t) * 8);
		//   memcpy(state1.b, ecc_client2.point_out.x, sizeof(uint32_t) * 8);

		//   PT_SPAWN(&(boostrapping_service_process.pt), &(state1.pt), ecc_compare(&state1));
		//   if(state1.result) {
		//     puts("shared secrets do not match");
		//   } else {
		//     puts("shared secrets MATCH");
		//   }

	//   puts("-----------------------------------------\n"
	//        "Disabling pka...");
	//   pka_disable();




	while(1) {
#if EDU_DEBUG
		printf("EDU: while(1)\n"); //EDU: DEBUG
#endif
		PROCESS_YIELD();
#if EDU_DEBUG
		printf("EDU: while(1) 2\n"); //EDU: DEBUG
#endif
		if(pubkey_is_generated && NETSTACK_ROUTING.node_is_reachable()) {
			if(etimer_expired(&et) ) {
				timeout_handler();
			} else if(ev == tcpip_event) {
				tcpip_handler();
			} else {
				printf("Received another kind of event\n");
				// timeout_handler();
			}
		} else if (ev == PROCESS_EVENT_CONTINUE && data != NULL && strcmp(data, pubkey_generated) == 0 ) {
			pubkey_is_generated = true;
			printf("Client Public Key Generated\n");
			etimer_set(&et, 0.5 * CLOCK_SECOND);
		} else {
			printf("BR not reachable\n");
			etimer_set(&et, 2 * CLOCK_SECOND);
		}
	}
	PROCESS_END();
}
/*---------------------------------------------------------------------------*/
