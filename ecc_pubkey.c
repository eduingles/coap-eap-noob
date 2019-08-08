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

#include "ecc_pubkey.h"

static void
ecc_set_random(uint32_t *secret)
{
    for(int i = 0; i < 8; ++i) {
        secret[i] = (uint32_t)random_rand() | (uint32_t)random_rand() << 16;
    }
}

PROCESS(ecdh_generate_pubkey, "ECDH Generate Client Public Key");
PROCESS_THREAD(ecdh_generate_pubkey, ev, data) {

	PROCESS_BEGIN();

	pka_init();
    static ecc_compare_state_t state1 = {
        .process = &ecdh_generate_pubkey,
        .size    = 8,
    };
	memcpy(state1.b, nist_p_256.n, sizeof(uint32_t) * 8);
	do {
		if (pk_state == 1){
			ecc_set_random(private_secret);
			memcpy(state1.a, private_secret, sizeof(uint32_t) * 8);
		} else {
			ecc_set_random(private_secret2);
			memcpy(state1.a, private_secret2, sizeof(uint32_t) * 8);
		}
		PT_SPAWN(&(ecdh_generate_pubkey.pt), &(state1.pt), ecc_compare(&state1));
	} while(state1.result != PKA_STATUS_A_LT_B);

	static ecc_multiply_state_t ecc_client = {
		.process    = &ecdh_generate_pubkey,
		.curve_info = &nist_p_256,
	};
	memcpy(ecc_client.point_in.x, nist_p_256.x, sizeof(uint32_t) * 8);
	memcpy(ecc_client.point_in.y, nist_p_256.y, sizeof(uint32_t) * 8);
	if (pk_state == 1){
		memcpy(ecc_client.secret, private_secret, sizeof(private_secret));
	} else {
		memcpy(ecc_client.secret, private_secret2, sizeof(private_secret2));
	}

	PT_SPAWN(&(ecdh_generate_pubkey.pt), &(ecc_client.pt), ecc_multiply(&ecc_client));
	if (pk_state == 1){
		memcpy(client_pk.x, ecc_client.point_out.x, sizeof(uint32_t) * 8);
		memcpy(client_pk.y, ecc_client.point_out.y, sizeof(uint32_t) * 8);
	} else {
		memcpy(client_pk2.x, ecc_client.point_out.x, sizeof(uint32_t) * 8);
		memcpy(client_pk2.y, ecc_client.point_out.y, sizeof(uint32_t) * 8);
	}

  	pka_disable();
   	process_post(&boostrapping_service_process,
                PROCESS_EVENT_CONTINUE, "pubkey_generated");

	ec_point_t client_pk_tmp; // Generator Point
    #if NOOB_DEBUG
	    printf("EAP-NOOB: Client PK.X: ");
    #endif
    for(int i = 7; i >= 0; i--) {
		if (pk_state == 1){
			client_pk_tmp.x[i] = NTOHL(client_pk.x[7-i]);
		} else {
			client_pk_tmp.x[i] = NTOHL(client_pk2.x[7-i]);
		}
        #if NOOB_DEBUG
            printf("%08lX ", client_pk_tmp.x[i]);
		#endif
	}
    #if NOOB_DEBUG
        printf("\n");
        printf("EAP-NOOB: Client PK.Y: ");
    #endif
    for(int i = 7; i >=0 ; i--) {
		if (pk_state == 1){
			client_pk_tmp.y[i] = NTOHL(client_pk.y[7-i]);
		} else {
			client_pk_tmp.y[i] = NTOHL(client_pk2.y[7-i]);
		}
        #if NOOB_DEBUG
            printf("%08lX ", client_pk_tmp.y[i]);
        #endif
	}
    #if NOOB_DEBUG
            printf("\n");
    #endif

    PROCESS_END();
}
/*---------------------------------------------------------------------------*/
