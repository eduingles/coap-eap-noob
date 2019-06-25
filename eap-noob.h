/*
 * EAP peer method: EAP-NOOB
 *  Copyright (c) 2019, Aalto University
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *  * Neither the name of the Aalto University nor the
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL AALTO UNIVERSITY BE LIABLE FOR ANY
 *  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  See CONTRIBUTORS for more information.
 */

#ifndef EAPNOOB_H
#define EAPNOOB_H

#include "eap-peer.h"

/* Configuration file */
#define CONF_FILE               "eapnoob.conf"

/* Print debug information */
#define DEBUG_NOOB(X) printf("EAP-NOOB: %s\n", X)

/* Get EAP message values */
#define reqId ((struct eap_msg *)eapReqData)->id
#define reqMethod ((struct eap_msg *)eapReqData)->method
#define reqCode ((struct eap_msg *)eapReqData)->code
#define reqLength ((struct eap_msg *)eapReqData)->length

/* All the pre-processors of EAP-NOOB */

#define DB_NAME                 "peer_db.txt"

#define SUCCESS_NOOB                 1
#define FAILURE_NOOB                 -1
#define EMPTY_NOOB                   0

/* Keywords for json encoding and decoding */

enum {
    EAP_NOOB_NONE,
    EAP_NOOB_TYPE_1,
    EAP_NOOB_TYPE_2,
    EAP_NOOB_TYPE_3,
    EAP_NOOB_TYPE_4,
    EAP_NOOB_TYPE_5,
    EAP_NOOB_TYPE_6,
    EAP_NOOB_TYPE_7,
    EAP_NOOB_ERROR
};

struct eap_noob_server_data {
};

struct eap_noob_peer_config_params {
    char * Peer_name;
    char * Peer_ID_Num;
};

struct eap_noob_peer_data {
    uint32_t version;
    uint32_t state;
    uint32_t cryptosuite;
    uint32_t dir;
    uint32_t minsleep;
    uint32_t config_params;

    char * PeerId;
    char * PeerInfo;
    char * MAC;
    char * Realm;

    uint8_t * Kz;

    struct eap_noob_peer_config_params * peer_config_params;
};

#endif
