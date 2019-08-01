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

#include "sha256_calc.h"
#include "eap-noob-conf.h"

#define ALGORITHM_ID            "EAP-NOOB"
#define ALGORITHM_ID_LEN        8
#define KDF_LEN                 320
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

PROCESS(sha256_calc, "SHA256 CALCULATIONS");
PROCESS_THREAD(sha256_calc, ev, data) {

	PROCESS_BEGIN();

	// PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_CONTINUE && data != NULL && strcmp(data, "sharedkey_generated") == 0);

	/*------------------- SHA256 HOOB Generation ------------------ */

	/* SHA256: Array of key names to extract values from DB

	TODO: Update client and server with the values detailed in EAP-NOOB draft.
		  Hoob calculation mistmach between code in NodeJS Server and test-vectors (example_messages.py).
	*/
	static const char *keys_db[] = {
		"Vers",
		"Verp",
		"PeerId",
		"Cryptosuites",
		"Dirs",
		"ServerInfo",
		"Cryptosuitep",
		"Dirp",
		"Realm",
		"PeerInfo",
		// "PKs",
		"Xs",
		"Ys",
		"Ns",
		// "PKp",
		"Xp",
		"Yp",
		"Np",
		"Noob"
	};

	/* SHA256 Variables */
	static sha256_state_t state;
	static uint8_t sha256[32]; /* SHA256: Hash result */

	size_t len;
	char hash_str[600] = "[1"; // TODO: get actual Dir from Peer
	char tmp[65]; /* Fixme: ATTENTION!! Value based on 'ServerInfo' length (63).
                     It should be larger for PKp or PKs. */

	/* SHA256: Get values to hash from DB and set format */
	for (int i = 0; i < sizeof(keys_db)/sizeof(keys_db[0]); i++) {
		read_db((char *)keys_db[i], tmp);
		if (!strcmp(keys_db[i], "PeerId") ||
            !strcmp(keys_db[i], "Realm")  ||
            !strcmp(keys_db[i], "Ns")     ||
            !strcmp(keys_db[i], "Np")     ||
            !strcmp(keys_db[i], "Noob")   ||
            !strcmp(keys_db[i], "Xs")     ||
            !strcmp(keys_db[i], "Ys")     ||
            !strcmp(keys_db[i], "Xp")     ||
            !strcmp(keys_db[i], "Yp")
        )
            sprintf(hash_str, "%s,\"%s\"", hash_str,tmp);
        else
            sprintf(hash_str, "%s,%s", hash_str,tmp);

        if (!strcmp(keys_db[i], "PeerInfo")) // Add Keying mode (0)
			sprintf(hash_str, "%s,0", hash_str);
	}
	sprintf(hash_str, "%s]",hash_str);

#if EDU_DEBUG
	printf("EDU: hash_str: %s\n", hash_str);
#endif

	crypto_init();

	sha256_init(&state);
	len = strlen(hash_str);
	sha256_process(&state, hash_str, len);

	/* SHA256: Get result in param 'sha256' */
	sha256_done(&state, sha256);

#if EDU_DEBUG
	printf("Hoob calculation process.\n");
	printf("Hash value (hex): ");
	for (int i = 0;i <32;i++)
		printf("%02x", sha256[i]);
	printf("\n");
#endif

    size_t len_b64_hoob = 0;
	unsigned char hoob[23];
    base64_encode(sha256, 16, &len_b64_hoob, hoob);
	hoob[22] = '\0'; // Remove '=' padding

	crypto_disable();

	/* SHA256: Show URL */
	char peer_id[23];
	char noob[23];
	read_db("PeerId", peer_id);
	read_db("Noob", noob);

	/* TODO: Get url from 'ServerInfo' */
	printf("EAP-NOOB: OOB:\n https://193.234.219.186:8080/sendOOB?P=%s&N=%s&H=%s\n",
        peer_id, noob, hoob
    );

	printf("EAP-NOOB: OOB:\n\n https://localhost:8080/sendOOB?P=%s&N=%s&H=%s\n\n",
        peer_id, noob, hoob
    );

	/*--------------------- SHA256 NoobId Generation -------------------- */

	char noobid_str[29]; // "NoobId" + noob + '\0' = 6 + 22 + 1
	sprintf(noobid_str, "NoobId%s",noob);

    /* Generate NoobId */
   	crypto_init();
	sha256_init(&state);
	len = strlen(noobid_str);
	sha256_process(&state, noobid_str, len);
	/* SHA256: Get result in param 'sha256' */
	sha256_done(&state, sha256);
	crypto_disable();
	unsigned char NoobId[23];
    len_b64_hoob = 0;
    base64_encode(sha256, 16, &len_b64_hoob, NoobId);
	NoobId[22] = '\0'; // Remove '=' padding
	write_db("NoobId", (char *)NoobId);

#if NOOB_DEBUG
	printf("EAP-NOOB: NoobId generated: %s\n", NoobId);
#endif

	/*----------------------- SHA256 KDF Generation ---------------------- */
	/* KDF Generation: Values used in EAP-NOOB Server (https://github.com/tuomaura/eap-noob)
		Function: eap_noob_ECDH_KDF_X9_63
		Values: EAP-NOOB Server		Contiki Client
				________________	________________
				Z					shared_secret
				algorithm_id		"EAP-NOOB"
				partyUinfo (Np)		Generate (np_nonce)
				partyVinfo (Ns)		Got from msg Type 2 (DB)
				suppPrivinfo		Noob (DB)
	*/

    /* Generate KDF */
    unsigned char ctr[4] = {0};
    static uint8_t kdf_hash[321]; /* ctr + Z + Np + Ns + Noob + '\0'
                           = 4 + 32 + 8 + 32 + 32 + 16 + 1
                           = 125 */

    /* Decode nonces */
	size_t len_tmp = 0;

   	crypto_init();
	static size_t outlen = KDF_LEN;
    size_t mdlen = 32; // Message Digest size
	static size_t kdf_hash_len = 0;
	for (int i=1;;i++) {
		sha256_init(&state);
        ctr[3] = i & 255;
        ctr[2] = (i >> 8) & 255;
        ctr[1] = (i >> 16) & 255;
        ctr[0] = (i >> 24) & 255;
		char z[32];
		for(int j = 0; j < 8; j++) {
			z[j*4+0] = shared_secret[7-j] >> 24;
			z[j*4+1] = shared_secret[7-j] >> 16;
			z[j*4+2] = shared_secret[7-j] >> 8;
			z[j*4+3] = shared_secret[7-j];
		}
		char nonce[45]; // 45 to include '=' padding
		unsigned char np_decoded[33];
		unsigned char ns_decoded[33];
		unsigned char noob2[17];
		// Decode Np
		read_db("Np", nonce);
		sprintf(nonce, "%s""=", nonce); // Recover '=' to decode
		base64_decode((unsigned char *)nonce, strlen(nonce), &len_tmp, np_decoded);
		// Decode Ns
		read_db("Ns", nonce);
		sprintf(nonce, "%s""=", nonce); // Recover '=' to decode
		base64_decode((unsigned char *)nonce, strlen(nonce), &len_tmp, ns_decoded);
		// Decode Noob
		read_db("Noob", nonce);
		sprintf(nonce, "%s""==", nonce); // Recover '=' to decode
		base64_decode((unsigned char *)nonce, 24, &len_tmp, noob2);

		// printf("EDU: sha256_calc: ctr (%x) ", i);
        // for(int i = 0; i < 4; i++)
        //     printf("%02x", ctr[i]);
		// printf("\n");
		// // sha256_process(&state, ctr, sizeof(ctr));		
		// printf("EDU: sha256_calc: Shared secret ");
        // for(int i = 0; i < 32 ; i++)
        //     printf("%02x", z[i]);
		// printf("\n");
		// // sha256_process(&state, z, 32); // Z: ECDHE shared secret
		// printf("EDU: sha256_calc: ALGORITHM_ID ");
        // for(int i = 0; i < strlen(ALGORITHM_ID) ; i++)
        //     printf("%02x", ALGORITHM_ID[i]);
		// printf("\n");
		// // sha256_process(&state, ALGORITHM_ID, ALGORITHM_ID_LEN); // AlgorithmId: "EAP-NOOB"
		// printf("EDU: sha256_calc: np_decoded ");
        // for(int i = 0; i < 32 ; i++)
        //     printf("%02x", np_decoded[i]);
		// printf("\n");
		// // sha256_process(&state, np_decoded, sizeof(np_decoded)); // PartyUInfo: Np
		// printf("EDU: sha256_calc: ns_decoded ");
        // for(int i = 0; i < 32 ; i++)
        //     printf("%02x", ns_decoded[i]);
		// printf("\n");
		// // sha256_process(&state, ns_decoded, sizeof(ns_decoded)); // PartyVInfo: Ns
		// printf("EDU: sha256_calc: noob2 ");
        // for(int i = 0; i < 16 ; i++)
        //     printf("%02x", noob2[i]);
		// printf("\n");
		// sha256_process(&state, noob2, 16); // SuppPrivInfo: Noob

		static uint8_t kdf_hash_tmp[125];
		memcpy(kdf_hash_tmp, ctr, 4);
		memcpy(kdf_hash_tmp+4, z, 32); // Z: ECDHE shared secret
		memcpy(kdf_hash_tmp+36, ALGORITHM_ID, ALGORITHM_ID_LEN); // AlgorithmId: "EAP-NOOB"
		memcpy(kdf_hash_tmp+44, np_decoded, 32); // PartyUInfo: Np
		memcpy(kdf_hash_tmp+76, ns_decoded, 32); // PartyVInfo: Ns
		memcpy(kdf_hash_tmp+108, noob2, 16); // SuppPrivInfo: Noob
		kdf_hash_tmp[124] = '\0';
		
		sha256_process(&state, kdf_hash_tmp, 124);


        if (outlen >= mdlen) {
			/* SHA256: Get result in param 'sha256' */
			sha256_done(&state, sha256);
			// printf("EDU: sha256_calc: kdf_hash_len %d\n", kdf_hash_len);
			// printf("EDU: sha256_calc: sha256 tmp ");
			// for(int i = 0; i < 32 ; i++)
			// 	printf("%02x", sha256[i]);
			// printf("\n");
			memcpy(kdf_hash+kdf_hash_len, sha256, sizeof(sha256));
            outlen -= mdlen;
            if (outlen == 0)
                break;
            kdf_hash_len += mdlen;
        } else {
			/* SHA256: Get result in param 'sha256' */
			sha256_done(&state, sha256);
			memcpy(kdf_hash+kdf_hash_len, sha256, outlen);
            break;
        }

    }

	crypto_disable();

	kdf_hash[320] = '\0'; // End string properly
	write_db_kdf(kdf_hash);

#if EDU_DEBUG
	printf("EDU: SHA256: KDF Hash (hex): ");
	for (int i = 0;i <320;i++){
		printf("%02x", kdf_hash[i]);
		if ((i%32) == 31){
				printf("\n");
		}
	}
	printf("\n");
#endif

#if NOOB_DEBUG
	   printf("EAP-NOOB: KDF generated\n");
#endif
	/* SHA256: Send notification to main thread. Hoob, NoobId and KDF are completed */
   	process_post(&boostrapping_service_process,
                PROCESS_EVENT_CONTINUE, "hoob_noobid_kdf_generated");

    /* Extract values */
    size_t counter = 0;
    size_t len_tmp_b64 = 0;
    unsigned char tmp_res[65];
    unsigned char tmp_res_b64[90]; // 64 Bytes in b64 = 88 Bytes

    memcpy(tmp_res, kdf_hash, MSK_LEN);
    tmp_res[MSK_LEN] = '\0';
    memset(tmp_res_b64, '\0', 90);
    base64_encode(tmp_res, MSK_LEN, &len_tmp_b64, tmp_res_b64);
    write_db("Msk", (char *)tmp_res_b64);
    counter += MSK_LEN;

    memcpy(tmp_res, kdf_hash+counter, EMSK_LEN);
    tmp_res[EMSK_LEN] = '\0';
    memset(tmp_res_b64, '\0', 90);
    base64_encode(tmp_res, EMSK_LEN, &len_tmp_b64, tmp_res_b64);
    write_db("Emsk", (char *)tmp_res_b64);
    counter += EMSK_LEN;

    memcpy(tmp_res, kdf_hash+counter, AMSK_LEN);
    tmp_res[AMSK_LEN] = '\0';
    memset(tmp_res_b64, '\0', 90);
    base64_encode(tmp_res, AMSK_LEN, &len_tmp_b64, tmp_res_b64);
    write_db("Amsk", (char *)tmp_res_b64);
    counter += AMSK_LEN;

    memcpy(tmp_res, kdf_hash+counter, METHOD_ID_LEN);
    tmp_res[METHOD_ID_LEN] = '\0';
    memset(tmp_res_b64, '\0', 90);
    base64_encode(tmp_res, METHOD_ID_LEN, &len_tmp_b64, tmp_res_b64);
    write_db("MethodId", (char *)tmp_res_b64);
    counter += METHOD_ID_LEN;

    memcpy(tmp_res, kdf_hash+counter, KMS_LEN);
    tmp_res[KMS_LEN] = '\0';
    memset(tmp_res_b64, '\0', 90);
    base64_encode(tmp_res, KMS_LEN, &len_tmp_b64, tmp_res_b64);
    write_db("Kms", (char *)tmp_res_b64);
    counter += KMS_LEN;

    memcpy(tmp_res, kdf_hash+counter, KMP_LEN);
    tmp_res[KMP_LEN] = '\0';
    memset(tmp_res_b64, '\0', 90);
    base64_encode(tmp_res, KMP_LEN, &len_tmp_b64, tmp_res_b64);
    write_db("Kmp", (char *)tmp_res_b64);
    counter += KMP_LEN;

    memcpy(tmp_res, kdf_hash+counter, KZ_LEN);
    tmp_res[KZ_LEN] = '\0';
    memset(tmp_res_b64, '\0', 90);
    base64_encode(tmp_res, KZ_LEN, &len_tmp_b64, tmp_res_b64);
    write_db("Kz", (char *)tmp_res_b64);
    counter += KZ_LEN;

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
