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
#define P256_LEN		            32
#define HASH_LEN                16
#define METHOD_ID_LEN		        32

#define PKP1 "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\""
#define PKP2 "\",\"y\":\""
#define PKP3 "\"}"

#define MAC_VALUES  15

PROCESS(sha256_mac, "SHA256 MACs and MACp");
PROCESS_THREAD(sha256_mac, ev, data)
{
    PROCESS_BEGIN();

    // Keys for MAC input
    static const char *MAC_keys[] = {
        "Vers", "Verp", "PeerId", "Cryptosuites", "Dirs", "ServerInfo",
        "Cryptosuitep", "Dirp", "Realm", "PeerInfo", "PKs", "Ns", "PKp", "Np",
        "Noob"
    };

    // Temporary array for reading the database
    char tmp_val[130];
    // MAC input
    static char MAC_input[600];

    // Re-build PKp because it doesn't fit in the database
    char pk_x_b64[45];
    char pk_y_b64[45];
    pk_x_b64[44] = '\0';
    pk_y_b64[44] = '\0';
    read_db("Xp", pk_x_b64);
    read_db("Yp", pk_y_b64);

    /*------------------------ SHA256 MACs Generation ------------------------*/
    // Kms
    read_db("Kms", tmp_val);

    size_t len_kms = 0;
    unsigned char Kms[KMS_LEN+1];
    base64_decode((unsigned char *)tmp_val, strlen(tmp_val), &len_kms, Kms);

    // Build input for MACs
    size_t counter = 0;

    memcpy(MAC_input, Kms, KMS_LEN);
    counter += KMS_LEN;

    memcpy(MAC_input+counter, ",2", 2);
    counter += 2;

    for (int i = 0; i < MAC_VALUES; i++) {
        if (!strcmp(MAC_keys[i], "PKp")) {
            memcpy(MAC_input+counter, ",", 1);
            counter += 1;
            memcpy(MAC_input+counter, PKP1, strlen(PKP1));
            counter += strlen(PKP1);
            memcpy(MAC_input+counter, pk_x_b64, strlen(pk_x_b64));
            counter += strlen(pk_x_b64);
            memcpy(MAC_input+counter, PKP2, strlen(PKP2));
            counter += strlen(PKP2);
            memcpy(MAC_input+counter, pk_y_b64, strlen(pk_y_b64));
            counter += strlen(pk_y_b64);
            memcpy(MAC_input+counter, PKP3, strlen(PKP3));
            counter += strlen(PKP3);
        } else {
            read_db((char *)MAC_keys[i], tmp_val);
            memcpy(MAC_input+strlen(MAC_input), ",", 1);
            counter += 1;
            memcpy(MAC_input+strlen(MAC_input), tmp_val, strlen(tmp_val));
            counter += strlen(tmp_val);
        }
    }

    /* SHA256 Variables */
    static sha256_state_t state;
    static uint8_t sha256[32]; /* SHA256: Hash result */
    size_t len;
    // Calculate MACs
   	crypto_init();
    sha256_init(&state);
    len = strlen(MAC_input);
    sha256_process(&state, MAC_input, len);
    /* SHA256: Get result in param 'sha256' */
    sha256_done(&state, sha256);

    // Store MACs as Base64url
    char MACs[45];
    size_t len_b64_macs = 0;
    base64_encode(sha256, 32, &len_b64_macs, (unsigned char*) MACs);
    MACs[43] = '\0'; // Get rid of padding character ('=') at the end
    write_db("MACs", MACs);

#if NOOB_DEBUG
    printf("EAP-NOOB: MACs generated: %s\n", MACs);
#endif

    // Clear input array
    memset(MAC_input,'\0',600);

    /*------------------------ SHA256 MACp Generation ------------------------*/
    // Kmp
    read_db("Kmp", tmp_val);

    size_t len_kmp = 0;
    unsigned char Kmp[KMP_LEN+1];
    base64_decode((unsigned char *)tmp_val, strlen(tmp_val), &len_kmp, Kmp);

    // Build input for MACs
    counter = 0;

    memcpy(MAC_input, Kmp, KMP_LEN);
    counter += KMP_LEN;

    memcpy(MAC_input+counter, ",2", 2);
    counter += 2;

    for (int i = 0; i < MAC_VALUES; i++) {
        if (!strcmp(MAC_keys[i], "PKp")) {
            memcpy(MAC_input+counter, ",", 1);
            counter += 1;
            memcpy(MAC_input+counter, PKP1, strlen(PKP1));
            counter += strlen(PKP1);
            memcpy(MAC_input+counter, pk_x_b64, strlen(pk_x_b64));
            counter += strlen(pk_x_b64);
            memcpy(MAC_input+counter, PKP2, strlen(PKP2));
            counter += strlen(PKP2);
            memcpy(MAC_input+counter, pk_y_b64, strlen(pk_y_b64));
            counter += strlen(pk_y_b64);
            memcpy(MAC_input+counter, PKP3, strlen(PKP3));
            counter += strlen(PKP3);
        } else {
            read_db((char *)MAC_keys[i], tmp_val);
            memcpy(MAC_input+strlen(MAC_input), ",", 1);
            counter += 1;
            memcpy(MAC_input+strlen(MAC_input), tmp_val, strlen(tmp_val));
            counter += strlen(tmp_val);
        }
    }

    // Calculate MACp
    sha256_init(&state);
    len = strlen(MAC_input);
    sha256_process(&state, MAC_input, len);
    /* SHA256: Get result in param 'sha256' */
    sha256_done(&state, sha256);
    crypto_disable();

    // Store MACp as Base64url
    char MACp[45];
    size_t len_b64_macp = 0;
    base64_encode(sha256, 32, &len_b64_macp, (unsigned char*) MACp);
    MACp[43] = '\0'; // Get rid of padding character ('=') at the end
    write_db("MACp", MACp);

#if NOOB_DEBUG
    printf("EAP-NOOB: MACp generated: %s\n", MACp);
#endif
    /*------------------------------------------------------------------------*/

    PROCESS_END();
}
