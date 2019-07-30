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

#include "sha256_mac.h"

#define MSK_LEN                 64
#define EMSK_LEN                64
#define AMSK_LEN                64
#define KZ_LEN                  32
#define KMS_LEN                 32
#define KMP_LEN                 32
#define MAC_LEN                 32
#define MAX_X25519_LEN          48
#define P256_LEN		        32
#define HASH_LEN                16
#define METHOD_ID_LEN		    32

#define PKP1 "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\""
#define PKP2 "\", \"y\":\""
#define PKP3 "\"}"

PROCESS(sha256_mac, "SHA256 MACs and MACp");
PROCESS_THREAD(sha256_mac, ev, data) {

	PROCESS_BEGIN();

	// Kz
    // char Kz[KZ_LEN+1];
	// memcpy(Kz, kdf_hash+288, KZ_LEN);
	// Kz[KZ_LEN] = '\0';

	/*----------------------- SHA256 MAC Generation -----------------------*/
    #define MAC_VALUES  15

    static const char *MAC_keys[] = {
       "Vers", "Verp", "PeerId", "Cryptosuites", "Dirs", "ServerInfo",
        "Cryptosuitep", "Dirp", "Realm", "PeerInfo", "PKs", "Ns", "PKp", "Np",
        "Noob"
    };

    // Temporary array for reading the database
    char tmp_val[130];

    // Re-build PKp because it doesn't fit in the database
    char pk_x_b64[45];
    char pk_y_b64[45];
	pk_x_b64[44] = '\0';
	pk_y_b64[44] = '\0';
    read_db("Xp", pk_x_b64);
    read_db("Yp", pk_y_b64);
	/*
	FIXME: (delete me after reading) You may want to change this line again. It's up to you, but remember checking the length
	*/
    // char PKp[130];
    // sprintf(PKp, "%s%s%s%s%s",
    //     "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"", pk_x_b64,
    //     "\", \"y\":\"", pk_y_b64, "\"}"
    // );

    /*----------------------- SHA256 MACs Generation -----------------------*/
	// Kms
    char Kms[KMS_LEN+1];
	read_db("Kms", Kms);
	// memcpy(Kms, kdf_hash+224, KMS_LEN);
	// Kms[KMS_LEN] = '\0';

    // Build input for MACs
    static char MACs_input[580];
	memcpy(MACs_input, "\"", 1);
	memcpy(MACs_input+1, Kms, KMS_LEN);
	memcpy(MACs_input+33, "\",\"2\"\0", 6);

    for (int i = 0; i < MAC_VALUES; i++) {
        if (!strcmp(MAC_keys[i], "PKp")) {
            sprintf(MACs_input, "%s,\"%s%s%s%s%s\"", MACs_input, PKP1,pk_x_b64,PKP2,pk_y_b64,PKP3);
        } else {
            read_db((char *)MAC_keys[i], tmp_val);
            sprintf(MACs_input, "%s,\"%s\"", MACs_input, tmp_val);
        }
    }

	/* SHA256 Variables */
	static sha256_state_t state;
	static uint8_t sha256[32]; /* SHA256: Hash result */
	size_t len;

    // Calculate MACs
   	crypto_init();
	sha256_init(&state);
	len = strlen(MACs_input);
	sha256_process(&state, MACs_input, len);
	/* SHA256: Get result in param 'sha256' */
	sha256_done(&state, sha256);
	crypto_disable();

    // Store MACs as Base64url
    char MACs[45];
    size_t len_b64_macs = 0;
    base64_encode(sha256, 32, &len_b64_macs, (unsigned char*) MACs);
    MACs[43] = '\0'; // Get rid of padding character ('=') at the end

	// write_db("MACs", MACs);

#if NOOB_DEBUG
    printf("EAP-NOOB: MACs generated: %s\n", MACs);
#endif

	/*----------------------- SHA256 MACp Generation ---------------------- */
// 	// Kmp
//     char Kmp[KMP_LEN+1];
// 	read_db("Kmp", Kmp);
// 	// memcpy(Kmp, kdf_hash+256, KMP_LEN);
// 	// Kmp[KMP_LEN] = '\0';

//     // Build input for MACp
//     char MACp_input[600];
//     sprintf(MACp_input, "%s,\"%s\"", MACp_input, Kmp);
//     sprintf(MACp_input, "%s,\"%d\"", MACp_input, 1);
//     for (int i = 0; i < MAC_VALUES; i++) {
//         if (!strcmp(MAC_keys[i], "PKp")) {
//             sprintf(MACs_input, "%s,\"%s%s%s%s%s\"", MACs_input, PKP1,pk_x_b64,PKP2,pk_y_b64,PKP3);
//             // sprintf(MACp_input, "%s,\"%s\"", MACp_input, PKp);
//         } else {
//             read_db((char *)MAC_keys[i], tmp_val);
//             sprintf(MACp_input, "%s,\"%s\"", MACp_input, tmp_val);
//         }
//     }

//     // Calculate MACp
//     crypto_init();
//     sha256_init(&state);
//     len = strlen(MACp_input);
//     sha256_process(&state, MACp_input, len);
//     /* SHA256: Get result in param 'sha256' */
//     sha256_done(&state, sha256);
//     crypto_disable();

//     // Store MACp as Base64url
//     char MACp[44];
//     size_t len_b64_macp = 0;
//     base64_encode(sha256, 32, &len_b64_macp, (unsigned char*) MACp);
//     MACp[43] = '\0'; // Get rid of padding character ('=') at the end

//     // write_db("MACp", MACp);

// #if NOOB_DEBUG
//     printf("EAP-NOOB: MACp generated: %s\n", MACp);
// #endif

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
