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

#ifndef EAPNOOB_H
#define EAPNOOB_H

#include "eap-peer.h"

/* Configuration file */
#include "eap-noob-conf.h"

/* Print debug information */
#define DEBUG_NOOB(X) printf("EAP-NOOB: %s\n", X)
#define ERROR_NOOB(X,Y) printf("EAP-NOOB: %s %d\n", X, Y)

/* Get EAP message values */
#define reqId ((struct eap_msg *)eapReqData)->id
#define reqMethod ((struct eap_msg *)eapReqData)->method
#define reqCode ((struct eap_msg *)eapReqData)->code
#define reqLength ((struct eap_msg *)eapReqData)->length

/* All the pre-processors of EAP-NOOB */

#define DB_NAME             "peer_db.txt"
#define DEFAULT_REALM       "eap-noob.net"
#define SUCCESS_NOOB        1
#define FAILURE_NOOB        -1
#define EMPTY_NOOB          0

/* MAX values for the fields */

#define MAX_PEER_ID_LEN     22

/* Keywords for json encoding and decoding */

enum {
    EAP_NOOB_TYPE_0,
    EAP_NOOB_TYPE_1,
    EAP_NOOB_TYPE_2,
    EAP_NOOB_TYPE_3,
    EAP_NOOB_TYPE_4,
    EAP_NOOB_TYPE_5,
    EAP_NOOB_TYPE_6,
    EAP_NOOB_TYPE_7,
    EAP_NOOB_ERROR
};

uint8_t PeerId [MAX_PEER_ID_LEN];

#endif
