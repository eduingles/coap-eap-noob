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

#include "ecc_shared_secret.h"

PROCESS(ecc_derive_secret, "ECDH Shared Secret Derivation");
PROCESS_THREAD(ecc_derive_secret, ev, data) {

	PROCESS_BEGIN();

	pka_init();

	static ecc_multiply_state_t ec_server = {
		.process    = &ecc_derive_secret,
		.curve_info = &nist_p_256,
	};
	memcpy(ec_server.point_in.x, server_pk.x, sizeof(uint32_t) * 8);
	memcpy(ec_server.point_in.y, server_pk.y, sizeof(uint32_t) * 8);
	memcpy(ec_server.secret, private_secret, sizeof(private_secret));

	PT_SPAWN(&(ecc_derive_secret.pt), &(ec_server.pt), ecc_multiply(&ec_server)); 
	memcpy(shared_secret, ec_server.point_out.x, sizeof(uint32_t) * 8);

  	pka_disable();

  	puts("-----------------------------------------");
  	puts("        Derived Shared Secret");
  	puts("-----------------------------------------");
	for(int i = 7 ;i >=0;i--){ //Little endian (change order to 3,2,1,0)
		printf("%lX", shared_secret[i]);
	}
  	puts("\n-----------------------------------------\n");
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/