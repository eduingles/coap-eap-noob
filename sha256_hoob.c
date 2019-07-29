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

#include "sha256_hoob.h"

static const unsigned char base64_table[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";


/**
 * base64_encode : Base64 encoding
 * @src : data to be encoded
 * @len : length of the data to be encoded
 * @out_len : pointer to output length variable, or NULL if not used
 * Returns :
 */
static uint8_t base64_encode(const unsigned char *src, size_t len, size_t *out_len, unsigned char *dst)
{
    unsigned char *pos;
    const unsigned char *end, *in;
    size_t olen;

    olen = len * 4 / 3 + 4; // 3-byte blocks to 4-byte
    olen += olen / 72;      // line feeds
    olen++;                 // null termination
    if (olen < len)
        return 0;           // integer overflow

    unsigned char out[olen];
    if (out == NULL)
        return 0;

    end = src + len;
    in = src;
    pos = out;

    while (end - in >= 3) {
        *pos++ = base64_table[in[0] >> 2];
        *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
        *pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
        *pos++ = base64_table[in[2] & 0x3f];
        in += 3;
    }
    if (end - in) {
        *pos++ = base64_table[in[0] >> 2];
        if (end-in == 1) {
            *pos++ = base64_table[(in[0] & 0x03) << 4];
            *pos++ = '=';
        } else {
            *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
            *pos++ = base64_table[(in[1] & 0x0f) << 2];
        }
    }
    *pos = '\0';
    if (out_len)
        *out_len = pos - out;

    memcpy(dst, out, *out_len+1);
    return 1;
}

PROCESS(sha256_hoob, "SHA256 HOOB Generation");
PROCESS_THREAD(sha256_hoob, ev, data) {
	
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
	
	print_db();

	/* SHA256: Array of key names to extract values from DB

	TODO: Update client and server with the values detailed in EAP-NOOB draft.
		  Hoob calculation mistmach between code in NodeJS Server and test-vectors (example_messages.py).
	*/
	static const char * keys_db[] = {
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

	/* KDF(?): Values used in EAP-NOOB Server (https://github.com/tuomaura/eap-noob)
		Function: eap_noob_ECDH_KDF_X9_63
		Values: EAP-NOOB Server		Contiki Client
				________________	________________
				Z					shared_secret
				algorithm_id		"EAP-NOOB"
				partyUinfo (Np)		Generate (np_nonce)
				partyVinfo (Ns)		Got from msg Type 2 (DB)
				suppPrivinfo		Noob (DB)
	*/

	/* SHA256 Variables */
	static sha256_state_t state;
	static uint8_t sha256[32]; /* SHA256: Hash result */
	static uint8_t ret; // Integer code representing operation state (match with str_res)
	size_t len;
	char hash_str[600] = "[1"; // First value 'Dir'.
	char tmp[65]; // Fixme: ATTENTION!! Value based on 'ServerInfo' length (63). It should be larger for PKp or PKs.

	/* SHA256: Get values to hash from DB and set format */
	for (int i = 0; i < sizeof(keys_db) / sizeof(keys_db[0]); i++){
		read_db((char *)keys_db[i], tmp);
		printf("EDUARDO: %s\n", tmp);
		if (!strcmp(keys_db[i], "PeerId") || !strcmp(keys_db[i], "Realm") || !strcmp(keys_db[i], "Ns") || !strcmp(keys_db[i], "Np") || !strcmp(keys_db[i], "Noob") || !strcmp(keys_db[i], "Xs") || !strcmp(keys_db[i], "Ys") || !strcmp(keys_db[i], "Xp") || !strcmp(keys_db[i], "Yp") ) {
			sprintf(hash_str, "%s,\"%s\"",hash_str,tmp);
		} else {
			sprintf(hash_str, "%s,%s",hash_str,tmp);
		}
		if (!strcmp(keys_db[i], "PeerInfo") ){ // Add Keying mode (0)
			sprintf(hash_str, "%s,0",hash_str);
		}		
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
	printf("URL OOB Process:\n\n\thttps://193.234.219.186:8080/sendOOB?P=%s&N=%s&H=%s\n\n\n", peer_id, noob, hoob);

	printf("URL OOB Process:\n\n\thttps://localhost:8080/sendOOB?P=%s&N=%s&H=%s\n\n\n", peer_id, noob, hoob);

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
