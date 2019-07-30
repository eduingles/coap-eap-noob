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

	// printf("EAP-NOOB: OOB:\n https://localhost:8080/sendOOB?P=%s&N=%s&H=%s\n",
    //     peer_id, noob, hoob
    // );

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
	unsigned char noobid[23];
    len_b64_hoob = 0;
    base64_encode(sha256, 16, &len_b64_hoob, noobid);
	noobid[22] = '\0'; // Remove '=' padding
	write_db("NoobId", (char *)noobid);

#if NOOB_DEBUG
	printf("NoobId generated\n");
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

    /* Decode nonces */
	char nonce[45]; // 45 to include '=' padding
	size_t len_tmp = 0;

    // Decode Np
    static unsigned char np_decoded[33];
	read_db("Np", nonce);
	sprintf(nonce, "%s""=", nonce); // Recover '=' to decode
	base64_decode((unsigned char *)nonce, strlen(nonce), &len_tmp, np_decoded);

    // Decode Ns
    static unsigned char ns_decoded[33];
	read_db("Ns", nonce);
	sprintf(nonce, "%s""=", nonce); // Recover '=' to decode
	base64_decode((unsigned char *)nonce, strlen(nonce), &len_tmp, ns_decoded);

    /* Generate KDF */
    static unsigned char ctr[4] = {0};
    char kdf_hash[321]; /* ctr + Z + Np + Ns + Noob + '\0'
                           = 4 + 32 + 8 + 32 + 32 + 16 + 1
                           = 125 */
	static size_t outlen = KDF_LEN;
    size_t mdlen = 32; // Message Digest size
	static size_t kdf_hash_len = 0;

    crypto_init();
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
	// write_db("Kdf", kdf_hash);

#if NOOB_DEBUG
	   printf("EAP-NOOB: KDF generated\n");
#endif

    /* Extract values */
    // TODO: add MSK, EMSK, AMSK, MethodId

	// Kms
    char Kms[KMS_LEN+1];
	memcpy(Kms, kdf_hash+224, KMS_LEN);
	Kms[KMS_LEN] = '\0';
	write_db("Kms", Kms);
	// Kmp
    char Kmp[KMP_LEN+1];
	memcpy(Kmp, kdf_hash+256, KMP_LEN);
	Kmp[KMP_LEN] = '\0';
	write_db("Kmp", Kmp);
	// Kz
    char Kz[KZ_LEN+1];
	memcpy(Kz, kdf_hash+288, KZ_LEN);
	Kz[KZ_LEN] = '\0';
	write_db("Kz", Kz);

	/*----------------------- SHA256 MACs Generation ---------------------- */
	// char macs[600];
	/*
		TODO: Creating MACs
		- Recreate JSON
		- Compact JSON
		- Check HMAC OpenSSL process
		- Emulate process
	 */
   	// crypto_init();
	// sha256_init(&state);
	// len = strlen(macs);
	// ret = sha256_process(&state, macs, len);
	// /* SHA256: Get result in param 'sha256' */
	// ret = sha256_done(&state, sha256);
	// crypto_disable();

	// write_db("MACs", macs);


	/*----------------------- SHA256 MACp Generation ---------------------- */

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/