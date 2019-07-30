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
#define P256_LEN		        32
#define HASH_LEN                16
#define METHOD_ID_LEN		    32

PROCESS(sha256_calc, "SHA256 CALCULATIONS");
PROCESS_THREAD(sha256_calc, ev, data) {

	PROCESS_BEGIN();

	// PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_CONTINUE && data != NULL && strcmp(data, "sharedkey_generated") == 0);

	/*------------------- SHA256 HOOB Generation ------------------ */
	/* SHA256: states */
	static const char *const str_res[] = {
	    "success",
	    "invalid param",
	    "NULL error",
	    "resource in use",
	    "DMA bus error"
	};

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
	static uint8_t ret; // Integer code representing operation state (match with str_res)
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
	ret = sha256_process(&state, hash_str, len);

	/* SHA256: Get result in param 'sha256' */
	ret = sha256_done(&state, sha256);

#if EDU_DEBUG
	printf("Hoob calculation process: %s\n", str_res[ret]);

	printf("Hash value (hex): ");
	for (int i = 0;i <32;i++)
		printf("%02x", sha256[i]);
	printf("\n");
#else
    (void) ret;
    (void) str_res;
#endif

    size_t len_b64_hoob = 0;
	unsigned char hoob[23];
    base64_encode(sha256, 16, &len_b64_hoob, hoob);
	hoob[22] = '\0'; // Remove '=' padding

	crypto_disable();

	/* SHA256: Show URL */
	char peer_id[23];
	static char noob[23];
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
	ret = sha256_process(&state, noobid_str, len);
	/* SHA256: Get result in param 'sha256' */
	ret = sha256_done(&state, sha256);
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
    static unsigned char ctr[4] = {0};
    static uint8_t kdf_hash[321]; /* ctr + Z + Np + Ns + Noob + '\0'
                           = 4 + 32 + 8 + 32 + 32 + 16 + 1
                           = 125 */
						   
    /* Decode nonces */
	char nonce[45]; // 45 to include '=' padding
	size_t len_tmp = 0;

	static unsigned char np_decoded[33];
	static unsigned char ns_decoded[33];
    // Decode Np
	read_db("Np", nonce);
	sprintf(nonce, "%s""=", nonce); // Recover '=' to decode
	base64_decode((unsigned char *)nonce, strlen(nonce), &len_tmp, np_decoded);
    // Decode Ns
	read_db("Ns", nonce);
	sprintf(nonce, "%s""=", nonce); // Recover '=' to decode
	base64_decode((unsigned char *)nonce, strlen(nonce), &len_tmp, ns_decoded);

   	crypto_init();
	static size_t outlen = KDF_LEN;
    size_t mdlen = 32; // Message Digest size
	static size_t kdf_hash_len = 0;
    for (int i = 1;; i++) {
        // EVP_DigestInit_ex(mctx, md, NULL);
		sha256_init(&state);
        ctr[3] = i & 0xFF;
        ctr[2] = (i >> 8) & 0xFF;
        ctr[1] = (i >> 16) & 0xFF;
        ctr[0] = (i >> 24) & 0xFF;
		sha256_process(&state, ctr, sizeof(ctr));
		sha256_process(&state, shared_secret, sizeof(shared_secret)); // Z: ECDHE shared secret
		sha256_process(&state, ALGORITHM_ID, ALGORITHM_ID_LEN); // AlgorithmId: "EAP-NOOB"
		sha256_process(&state, np_decoded, sizeof(np_decoded)); // PartyUInfo: Np
		sha256_process(&state, ns_decoded, sizeof(ns_decoded)); // PartyVInfo: Ns
		sha256_process(&state, noob, sizeof(noob)); // SuppPrivInfo: Noob

        if (outlen >= mdlen) {
			/* SHA256: Get result in param 'sha256' */
			ret = sha256_done(&state, sha256);
			memcpy(kdf_hash+kdf_hash_len, sha256, sizeof(sha256));
            outlen -= mdlen;
            if (outlen == 0)
                break;
            kdf_hash_len += mdlen;
        } else {
			/* SHA256: Get result in param 'sha256' */
			ret = sha256_done(&state, sha256);
			memcpy(kdf_hash+kdf_hash_len, sha256, outlen);
            break;
        }

    }

	crypto_disable();

	kdf_hash[320] = '\0'; // End string properly
	write_db_kdf(kdf_hash);

#if EDU_DEBUG
	printf("EDU: SHA256: KDF Hash (hex): ");
	for (int i = 0;i <320;i++)
		printf("%02x", kdf_hash[i]);
	printf("\n");
#endif

#if NOOB_DEBUG
	   printf("EAP-NOOB: KDF generated\n");
#endif
	/* SHA256: Send notification to main thread. Hoob, NoobId and KDF are completed */
   	process_post(&boostrapping_service_process,
                PROCESS_EVENT_CONTINUE, "hoob_noobid_kdf_generated");

    /* Extract values */
//   printf("EDU: 1 stack usage: %u permitted: %u\n", stack_check_get_usage(), stack_check_get_reserved_size());

	size_t counter = 0;
	size_t len_tmp_b64 = 0;
	unsigned char tmp_res[65];
	unsigned char tmp_res_b64[90]; // 64 Bytes in b64 = 88 Bytes
	memcpy(tmp_res, kdf_hash, MSK_LEN);
	tmp_res[MSK_LEN] = '\0';
    base64_encode(tmp_res, 16, &len_tmp_b64, tmp_res_b64);
	write_db("Msk", (char *)tmp_res_b64);
	counter += MSK_LEN;
	memcpy(tmp_res, kdf_hash+counter, EMSK_LEN);
//   printf("EDU: 4 stack usage: %u permitted: %u\n", stack_check_get_usage(), stack_check_get_reserved_size());
	tmp_res[EMSK_LEN] = '\0';
    base64_encode(tmp_res, 16, &len_tmp_b64, tmp_res_b64);
	write_db("Emsk", (char *)tmp_res_b64);
	counter += EMSK_LEN;
//   printf("EDU: 5 stack usage: %u permitted: %u\n", stack_check_get_usage(), stack_check_get_reserved_size());
	memcpy(tmp_res, kdf_hash+counter, AMSK_LEN);
//   printf("EDU: 6 stack usage: %u permitted: %u\n", stack_check_get_usage(), stack_check_get_reserved_size());
	tmp_res[AMSK_LEN] = '\0';
    base64_encode(tmp_res, 16, &len_tmp_b64, tmp_res_b64);
	write_db("Amsk", (char *)tmp_res_b64);
	counter += AMSK_LEN;
//   printf("EDU: 7 stack usage: %u permitted: %u\n", stack_check_get_usage(), stack_check_get_reserved_size());
	memcpy(tmp_res, kdf_hash+counter, METHOD_ID_LEN);
//   printf("EDU: 8 stack usage: %u permitted: %u\n", stack_check_get_usage(), stack_check_get_reserved_size());
	tmp_res[METHOD_ID_LEN] = '\0';
    base64_encode(tmp_res, 16, &len_tmp_b64, tmp_res_b64);
	write_db("MethodId", (char *)tmp_res_b64);
	counter += METHOD_ID_LEN;
//   printf("EDU: 9 stack usage: %u permitted: %u\n", stack_check_get_usage(), stack_check_get_reserved_size());
	memcpy(tmp_res, kdf_hash+counter, KMS_LEN);
//   printf("EDU: 10 stack usage: %u permitted: %u\n", stack_check_get_usage(), stack_check_get_reserved_size());
	tmp_res[KMS_LEN] = '\0';
    base64_encode(tmp_res, 16, &len_tmp_b64, tmp_res_b64);
	write_db("Kms", (char *)tmp_res_b64);
	counter += KMS_LEN;
//   printf("EDU: 1 stack usage: %u permitted: %u\n", stack_check_get_usage(), stack_check_get_reserved_size());
	memcpy(tmp_res, kdf_hash+counter, KMP_LEN);
//   printf("EDU: 1 stack usage: %u permitted: %u\n", stack_check_get_usage(), stack_check_get_reserved_size());
	tmp_res[KMP_LEN] = '\0';
    base64_encode(tmp_res, 16, &len_tmp_b64, tmp_res_b64);
	write_db("Kmp", (char *)tmp_res_b64);
	counter += KMP_LEN;
	memcpy(tmp_res, kdf_hash+counter, KZ_LEN);
	tmp_res[KZ_LEN] = '\0';
    base64_encode(tmp_res, 16, &len_tmp_b64, tmp_res_b64);
	write_db("Kz", (char *)tmp_res_b64);
	counter += KZ_LEN;

	// print_db();


	// Kms
    // static char Kms[KMS_LEN+1];
	// memcpy(Kms, kdf_hash+224, KMS_LEN);
	// Kms[KMS_LEN] = '\0';

	// Kmp
    // char Kmp[KMP_LEN+1];
	// memcpy(Kmp, kdf_hash+256, KMP_LEN);
	// Kmp[KMP_LEN] = '\0';

	// // Kz
    // char Kz[KZ_LEN+1];
	// memcpy(Kz, kdf_hash+288, KZ_LEN);
	// Kz[KZ_LEN] = '\0';

	/*----------------------- SHA256 MAC Generation -----------------------*/
//     #define MAC_VALUES  15

//     static const char *MAC_keys[] = {
//         "Vers", "Verp", "PeerId", "Cryptosuites", "Dirs", "ServerInfo",
//         "Cryptosuitep", "Dirp", "Realm", "PeerInfo", "PKs", "Ns", "PKp", "Np",
//         "Noob"
//     };

//     // Temporary array for reading the database
//     char tmp_val[64];

//     // Re-build PKp because it doesn't fit in the database
//     char pk_x_b64[44];
//     char pk_y_b64[44];
//     read_db("Xp", pk_x_b64);
//     read_db("Yp", pk_y_b64);
//     char PKp[86];
//     sprintf(PKp, "%s%s%s%s%s",
//         "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"", pk_x_b64,
//         "\", \"y\":\"", pk_y_b64, "\"}"
//     );

//     /*----------------------- SHA256 MACs Generation -----------------------*/
//     // Build input for MACs
//     char MACs_input[500];
//     sprintf(MACs_input, "%s,\"%s\"", MACs_input, Kms);
//     sprintf(MACs_input, "%s,\"%d\"", MACs_input, 2);
//     for (int i = 0; i < MAC_VALUES; i++) {
//         if (!strcmp(MAC_keys[i], "PKp")) {
//             sprintf(MACs_input, "%s,\"%s\"", MACs_input, PKp);
//         } else {
//             read_db((char *)MAC_keys[i], tmp_val);
//             sprintf(MACs_input, "%s,\"%s\"", MACs_input, tmp_val);
//         }
//     }

//     // Calculate MACs
//    	crypto_init();
// 	sha256_init(&state);
// 	len = strlen(MACs_input);
// 	ret = sha256_process(&state, MACs_input, len);
// 	/* SHA256: Get result in param 'sha256' */
// 	ret = sha256_done(&state, sha256);
// 	crypto_disable();

//     // Store MACs as Base64url
//     char MACs[44];
//     size_t len_b64_macs = 0;
//     base64_encode(sha256, 32, &len_b64_macs, (unsigned char*) MACs);
//     MACs[43] = '\0'; // Get rid of padding character ('=') at the end

// 	// write_db("MACs", MACs);

// #if NOOB_DEBUG
//     printf("EAP-NOOB: MACs generated: %s\n", MACs);
// #endif

// 	/*----------------------- SHA256 MACp Generation ---------------------- */
//     // Build input for MACp
//     char MACp_input[500];
//     sprintf(MACp_input, "%s,\"%s\"", MACp_input, Kmp);
//     sprintf(MACp_input, "%s,\"%d\"", MACp_input, 1);
//     for (int i = 0; i < MAC_VALUES; i++) {
//         if (!strcmp(MAC_keys[i], "PKp")) {
//             sprintf(MACp_input, "%s,\"%s\"", MACp_input, PKp);
//         } else {
//             read_db((char *)MAC_keys[i], tmp_val);
//             sprintf(MACp_input, "%s,\"%s\"", MACp_input, tmp_val);
//         }
//     }

//     // Calculate MACp
//     crypto_init();
//     sha256_init(&state);
//     len = strlen(MACp_input);
//     ret = sha256_process(&state, MACp_input, len);
//     /* SHA256: Get result in param 'sha256' */
//     ret = sha256_done(&state, sha256);
//     crypto_disable();

//     // Store MACp as Base64url
//     char MACp[44];
//     size_t len_b64_macp = 0;
//     base64_encode(sha256, 32, &len_b64_macp, (unsigned char*) MACp);
//     MACp[43] = '\0'; // Get rid of padding character ('=') at the end

    // write_db("MACp", MACp);

// #if NOOB_DEBUG
//     printf("EAP-NOOB: MACp generated: %s\n", MACp);
// #endif

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
