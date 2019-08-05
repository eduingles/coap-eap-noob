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
#if EDU_DEBUG
    // #include "sys/stack-check.h"
#endif

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

    // MAC input
    static char MAC_input[610];

    /*------------------------ SHA256 MACs Generation ------------------------*/
    // Temporary array for reading the database
    char tmp_val[127];
    read_db(KEY_DB, "Kms", tmp_val);
    // read_db_name("kmsdb.txt", "Kms", tmp_val);
    tmp_val[43] = '\0';
    size_t len_kms = 0;
    memset(MAC_input, 0x00, 64);
    sprintf(tmp_val,"%s""=", tmp_val);
    base64_decode((unsigned char *)tmp_val, 44, &len_kms, (unsigned char *)MAC_input);
    MAC_input[32] = 0x00;
#if EDU_DEBUG
    printf("EDU: sha256_mac: KMS (hex) ");
    for(uint8_t i = 0; i < 32 ; i++) printf("%02x", MAC_input[i]);
    printf("\n");
#endif
    /* ipad */
    for (uint8_t i=0; i < 64; ++i) MAC_input[i] ^= 0x36;

    // Build input for MACs
    size_t counter = 64;
    memcpy(MAC_input+counter, "[2", 2);
    counter += 2;

    for (uint8_t i = 0; i < MAC_VALUES; i++) {
        if (!strcmp(MAC_keys[i], "PKp")) {
            memcpy(MAC_input+counter, ",", 1);
            counter += 1;
            memcpy(MAC_input+counter, PKP1, strlen(PKP1));
            counter += strlen(PKP1);
            // Re-build PKp because it doesn't fit in the database
            char pk_b64[45];
            read_db(PEER_DB, "Xp", pk_b64);
            pk_b64[43] = '\0';
            memcpy(MAC_input+counter, pk_b64, strlen(pk_b64));
            counter += strlen(pk_b64);
            memcpy(MAC_input+counter, PKP2, strlen(PKP2));
            counter += strlen(PKP2);
            read_db(PEER_DB, "Yp", pk_b64);
            pk_b64[43] = '\0';
            memcpy(MAC_input+counter, pk_b64, strlen(pk_b64));
            counter += strlen(pk_b64);
            memcpy(MAC_input+counter, PKP3, strlen(PKP3));
            counter += strlen(PKP3);
        } else if (!strcmp(MAC_keys[i], "PeerId") ||
            !strcmp(MAC_keys[i], "Realm") ||
            !strcmp(MAC_keys[i], "Ns") ||
            !strcmp(MAC_keys[i], "Np") ||
            !strcmp(MAC_keys[i], "Noob") ){

            read_db(PEER_DB, (char *)MAC_keys[i], tmp_val);
            memcpy(MAC_input+counter, ",\"", 2);
            counter += 2;
            memcpy(MAC_input+counter, tmp_val, strlen(tmp_val));
            counter += strlen(tmp_val);
            memcpy(MAC_input+counter, "\"", 1);
            counter += 1;
        } else {
            read_db(PEER_DB, (char *)MAC_keys[i], tmp_val);
            memcpy(MAC_input+counter, ",", 1);
            counter += 1;
            memcpy(MAC_input+counter, tmp_val, strlen(tmp_val));
            counter += strlen(tmp_val);
        }
    }
    memcpy(MAC_input+counter, "]\0", 1);
    counter += 1;
#if EDU_DEBUG
    printf("EDU: sha256_mac: MAC_input ---- (%d) %s\n", counter, MAC_input+64);
#endif
    /* SHA256 Variables */
    static sha256_state_t state;
    static uint8_t sha256[32]; /* SHA256: Hash result */
    // Calculate MACs
   	crypto_init();
    sha256_init(&state);
    sha256_process(&state, MAC_input, counter);
    sha256_done(&state, sha256);

    read_db(KEY_DB, "Kms", tmp_val);
    // read_db_name("kmsdb.txt", "Kms", tmp_val);
    memset(MAC_input, 0x00, 64);
    sprintf(tmp_val,"%s""=", tmp_val);
    base64_decode((unsigned char *)tmp_val, 44, &len_kms, (unsigned char *)MAC_input);
    MAC_input[32] = 0x00;
    for (uint8_t i=0; i < 64; ++i) MAC_input[i] ^= 0x5c;
    memcpy(MAC_input+64, sha256, 32);

    sha256_init(&state);
    sha256_process(&state, MAC_input, 96);
    sha256_done(&state, sha256);

#if EDU_DEBUG
    printf("EDU: sha256_mac: sha256 MACs ");
#endif
    for(uint8_t i = 0; i < 32 ; i++)
        printf("%02x", sha256[i]);
    printf("\n");

    base64_encode(sha256, 32, &len_kms, (unsigned char *)MAC_input);
    MAC_input[43] = '\0'; // Get rid of padding character ('=') at the end
    write_db(MAC_DB, "MACs", strlen(MAC_input), MAC_input);

#if NOOB_DEBUG
    printf("EAP-NOOB: MACs generated b64: %s\n", MAC_input);
#endif

    // Clear input array
    // memset(MAC_input,'\0',576);

    /*------------------------ SHA256 MACp Generation ------------------------*/
    /*------------------------------------------------------------------------*/

    crypto_disable();
    PROCESS_END();
}
