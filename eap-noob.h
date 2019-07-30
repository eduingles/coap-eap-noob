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

#ifndef EAPNOOB_H
#define EAPNOOB_H

#include "database.h"
#include "include.h"
#include "jsonparse.h"
#include "base64.h"

/* ECDH implementation */
#include "ecc_shared_secret.h"

/* Configuration file */
#include "eap-noob-conf.h"

/* Print debug information */
#define DEBUG_MSG_NOOB(X)   printf("EAP-NOOB: %s\n", X)
#define ERROR_MSG_NOOB(X,Y) printf("EAP-NOOB: %s %d\n", X, Y)

/* All the pre-processors of EAP-NOOB */
#define DEFAULT_REALM       "eap-noob.net"
#define SUCCESS_NOOB        1
#define FAILURE_NOOB        -1
#define EMPTY_NOOB          0

/* MAX values for the fields */
#define MAX_NAI_LEN         44
#define MAX_PEERID_LEN      23

uint8_t eapKeyAvailable;

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
    EAP_NOOB_TYPE_8,
    EAP_NOOB_ERROR
};

enum {
    E1001, E1002, E1003, E1004, E1007,
    E2001, E2002, E2003, E2004,
    E3001, E3002, E3003,
    E4001,
    E5001, E5002, E5003, E5004
};

/* Public functions */
void init_eap_noob(void);
void eap_noob_process(const uint8_t*,size_t,uint8_t*,uint8_t*,uint8_t*,size_t*);
void eap_noob_build_identity(char*);

#endif
