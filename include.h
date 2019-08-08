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

#ifndef INCLUDE_H
#define INCLUDE_H

#include "lib/random.h"
#include <stdint.h> //uint32_t

#if EDU_DEBUG
    //Stack guard
    // #include "sys/stack-check.h"
#endif

/**
 * General buffer to store persistent data
 * Please. Por favor. Olkaa hyvä.
 * FIXME: Fix it.
 */
// uint8_t stored_data[610];

// ECDH implementation
#include "dev/ecc-driver.h" // ec_point_t for Client/Server Public Key

#define MAX_PAYLOAD_LEN 512 //TODO: Migrate MACROS to their corresponding headers

//Data types
#define TRUE 1
#define FALSE 0
#define UNSET 0
#define SET 1
#define ERROR 253

//States defined in eap peer sm (rfc 4137)
#define IDLE 0
#define RECEIVED 1
#define SUCCESS 2
#define FAILURE 3
#define NONE 4

//Auxilar defines
#define FAIL 0
#define RxREQ 1
#define RxSUCCESS 2
#define RxFAILURE 3

#define REQUEST_CODE 1
#define RESPONSE_CODE 2
#define SUCCESS_CODE 3
#define FAILURE_CODE 4
#define IDENTITY 1
#define DUMMY 6
#define EAP_PSK 47
#define EAP_NOOB 90
#define INIT 7
#define DONE 8
#define CONT 9
#define MAY_CONT 10
#define COND_SUCC 12
#define UNCOND_SUCC 13


#define MSK_LENGTH  16 // 16 uint8_ts due to AES key length

// Network to/from Host uint8_t order functions
#define HTONS(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))
#define NTOHS(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))

#define HTONL(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
                  ((((unsigned long)(n) & 0xFF00)) << 8) | \
                  ((((unsigned long)(n) & 0xFF0000)) >> 8) | \
                  ((((unsigned long)(n) & 0xFF000000)) >> 24))

#define NTOHL(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
                  ((((unsigned long)(n) & 0xFF00)) << 8) | \
                  ((((unsigned long)(n) & 0xFF0000)) >> 8) | \
                  ((((unsigned long)(n) & 0xFF000000)) >> 24))

//Global variables
// uint8_t msk_key [MSK_LENGTH];

//ECDH Implementation
PROCESS_NAME(boostrapping_service_process);
uint32_t private_secret[8];
uint32_t shared_secret[8]; // Shared Secret derived during ECDH

//SHA256 Implementation
uint8_t is_mac2_in_progress;

typedef struct {
  uint32_t       x[12];     /**< Pointer to value of the x co-ordinate. */
  uint32_t       y[12];     /**< Pointer to value of the y co-ordinate. */
} public_key;
public_key client_pk;  // Client Public Key (Local) - Generator Point
public_key server_pk;  // Server Public Key (HostAPD) - Generator Point
public_key client_pk2; // Client Public Key (Local) - Generator Point
public_key server_pk2; // Server Public Key (HostAPD) - Generator Point


#endif
