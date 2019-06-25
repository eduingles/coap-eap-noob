/*
 * Copyright (c) 2013, Institute for Pervasive Computing, ETH Zurich
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 */

/**
 * \file
 *      Erbium (Er) CoAP client example.
 * \author
 *      Matthias Kovatsch <kovatsch@inf.ethz.ch>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"
#include "contiki-net.h"
#include "coap-engine.h"
#include "coap-blocking-api.h"
#if PLATFORM_SUPPORTS_BUTTON_HAL
#include "dev/button-hal.h"
#else
#include "dev/button-sensor.h"
#endif


// EDU Filesystem example
    // #include "cfs/cfs.h"
    // #include "dev/leds.h"
// EDU Filesystem example - End

// ECC implementation
#include "dev/ecc-algorithm.h"
#include "dev/ecc-curve.h"
#include "lib/random.h"
#include "sys/rtimer.h"
#include "sys/pt.h"

static void
ecc_set_random(uint32_t *secret)
{
  int i;
  printf("EDU: ecc_set_random: ");

  for(i = 0; i < 8; ++i) {
    secret[i] = (uint32_t)random_rand() | (uint32_t)random_rand() << 16;
    printf("%u ", (unsigned int)secret[i]);
  }
}
// ECC implementation - end


/* Log configuration */
#include "coap-log.h"
#define LOG_MODULE "App"
#define LOG_LEVEL  LOG_LEVEL_APP

/* FIXME: This server address is hard-coded for Cooja and link-local for unconnected border router. */
#define SERVER_EP "coap://[fe80::212:4b00:11f4:8138]"

#define TOGGLE_INTERVAL 10

PROCESS(coap_eap_client, "Erbium Example Client");
AUTOSTART_PROCESSES(&coap_eap_client);

static struct etimer et;

/* Example URIs that can be queried. */
#define NUMBER_OF_URLS 4
/* leading and ending slashes only for demo purposes, get cropped automatically when setting the Uri-Path */
char *service_urls[NUMBER_OF_URLS] =
{ ".well-known/core", "/actuators/toggle", "battery/", "error/in//path" };
#if PLATFORM_HAS_BUTTON
static int uri_switch = 0;
#endif

/* This function is will be passed to COAP_BLOCKING_REQUEST() to handle responses. */
void
client_chunk_handler(coap_message_t *response)
{
  const uint8_t *chunk;

  int len = coap_get_payload(response, &chunk);

  printf("|%.*s", len, (char *)chunk);
}
PROCESS_THREAD(coap_eap_client, ev, data)
{
  static coap_endpoint_t server_ep;
  PROCESS_BEGIN();

  static coap_message_t request[1];      /* This way the packet can be treated as pointer as usual. */

  coap_endpoint_parse(SERVER_EP, strlen(SERVER_EP), &server_ep);

  etimer_set(&et, TOGGLE_INTERVAL * CLOCK_SECOND);

#if PLATFORM_HAS_BUTTON
#if !PLATFORM_SUPPORTS_BUTTON_HAL
  SENSORS_ACTIVATE(button_sensor);
#endif
  printf("Press a button to request %s\n", service_urls[uri_switch]);
#endif /* PLATFORM_HAS_BUTTON */

// EDU Filesystem example
    // int fd;
    // char buf[] = "Hello, World!";
    // char buf2[] = "Aaaaaa Aaaaa!";

    // struct cfs_dir dir;
    // struct cfs_dirent dirent;

    // if(cfs_opendir(&dir, "/") == 0) {
    //   while(cfs_readdir(&dir, &dirent) != -1) {
    //     printf("File1: %s (%ld bytes)\n",
    //           dirent.name, (long)dirent.size);
    //     fd = cfs_open(dirent.name, CFS_READ | CFS_WRITE);
    //     if(fd >= 0) {
    //       // cfs_seek(fd, 0, CFS_SEEK_SET);
    //       cfs_read(fd, buf2, sizeof(buf2));
    //       printf("Read message: %s\n", buf2);
    //       cfs_close(fd);
    //     }

    //     leds_on(LEDS_GREEN);
    //   }
    //   cfs_closedir(&dir);
    // }

    // fd = cfs_open("test", CFS_READ | CFS_WRITE);
    // if(fd >= 0) {
    //   cfs_write(fd, buf, sizeof(buf));
    //   cfs_close(fd);
    // }
    // fd = cfs_open("test", CFS_READ | CFS_WRITE);
    // if(fd >= 0) {
    //   // cfs_seek(fd, 0, CFS_SEEK_SET);
    //   cfs_read(fd, buf2, sizeof(buf2));
    //   printf("Read message: %s\n", buf2);
    //   cfs_close(fd);
    // }

    // if(cfs_opendir(&dir, "/") == 0) {
    //   while(cfs_readdir(&dir, &dirent) != -1) {
    //     printf("File2: %s (%ld bytes)\n",
    //           dirent.name, (long)dirent.size);
    //   }
    //   cfs_closedir(&dir);
    // }
// EDU Filesystem example - End


// ECC implementation

  /*
   * Variable for Time Measurement
   */
  static rtimer_clock_t time;

  /*
   * Activate Engine
   */
  puts("-----------------------------------------\n"
       "Initializing pka...");
  pka_init();

  /*
   * Generate secrets make sure they are valid (smaller as order)
   */
  static ecc_compare_state_t state = {
    .process = &coap_eap_client,
    .size    = 8,
  };

  //EDU: state.b = nist_p_256.n while n is prime order of G
  memcpy(state.b, nist_p_256.n, sizeof(uint32_t) * 8);
  //EDU: state.a = secret_a = d (random private key)
  static uint32_t secret_a[8];
  do {
    printf("A\n");
    ecc_set_random(secret_a);
    memcpy(state.a, secret_a, sizeof(uint32_t) * 8);
    //EDU: Compares state->a (d) and state->b (n)
    //EDU: 1 <= d <= n-1
    PT_SPAWN(&(coap_eap_client.pt), &(state.pt), ecc_compare(&state)); //EDU: Spawn a child protothread
    //ecc_compare stores the solution in state->result.
  } while(state.result != PKA_STATUS_A_LT_B);/**< Big number compare return status if
                                              the first big num is less than the
                                              second. */
    // In while state.a should be less than state.b.

  //EDU: state.a = secret_b = e (random private key)
  static uint32_t secret_b[8];
  do {
    printf("B\n");
    ecc_set_random(secret_b);
    memcpy(state.a, secret_b, sizeof(uint32_t) * 8);
    //EDU: Compares state->a (e) and state->b (n)
    //EDU: 1 <= e <= n-1
    PT_SPAWN(&(coap_eap_client.pt), &(state.pt), ecc_compare(&state));
  } while(state.result != PKA_STATUS_A_LT_B);/**< Big number compare return status if
                                              the first big num is less than the
                                              second. */

  //EDU: ------ Code so far, for client and server ------

  /*
   * Prepare Points
   */
  //EDU: CoAP-EAP Client
  static ecc_multiply_state_t side_a = {
    .process    = &coap_eap_client,
    .curve_info = &nist_p_256,
  };
  //EDU: Generates Ga = (Xa, Ya)
  //EDU: side_a.point_in = Ga
  memcpy(side_a.point_in.x, nist_p_256.x, sizeof(uint32_t) * 8);
  memcpy(side_a.point_in.y, nist_p_256.y, sizeof(uint32_t) * 8);
  //EDU: side_a.secret = secret_a
  memcpy(side_a.secret, secret_a, sizeof(secret_a));

  //EDU: Radius Server
  static ecc_multiply_state_t side_b = {
    .process    = &coap_eap_client,
    .curve_info = &nist_p_256,
  };
  //EDU: Generates Gb = (Xb, Yb)
  //EDU: side_b.point_in = Gb
  memcpy(side_b.point_in.x, nist_p_256.x, sizeof(uint32_t) * 8);
  memcpy(side_b.point_in.y, nist_p_256.y, sizeof(uint32_t) * 8);
  //EDU: side_b.secret = secret_b
  memcpy(side_b.secret, secret_b, sizeof(secret_b));

  /*
   * Round 1
   */
  //EDU: CoAP-EAP Client
  time = RTIMER_NOW(); //Return current time
  //EDU: Generates d x G = (Xa, Ya) = Pa
  PT_SPAWN(&(coap_eap_client.pt), &(side_a.pt), ecc_multiply(&side_a)); // Do a Multiplication on a EC
  // The result of ecc_multiply is saved in side_a->rv.
  time = RTIMER_NOW() - time; //difference of time
  printf("Round 1, Side a: %i, %lu ms\n", (unsigned)side_a.result,
         (uint32_t)((uint64_t)time * 1000 / RTIMER_SECOND));

  //EDU: Radius Server
  time = RTIMER_NOW();
  //EDU: Generates e x G = (Xb, Yb) = Qb
  PT_SPAWN(&(coap_eap_client.pt), &(side_b.pt), ecc_multiply(&side_b)); // Do a Multiplication on a EC
  time = RTIMER_NOW() - time;
  printf("Round 1, Side b: %i, %lu ms\n", (unsigned)side_b.result,
         (uint32_t)((uint64_t)time * 1000 / RTIMER_SECOND));

  printf("Qb.X: ");
  for(int i = 0; i < 8; ++i) {
    printf("%u ", (unsigned int)side_a.point_out.x);
  }
  printf("\n");
  printf("Qb.Y: ");
  for(int i = 0; i < 8; ++i) {
    printf("%u ", (unsigned int)side_a.point_out.y);
  }
  printf("\n");

  // side_a.point_out.y, sizeof(uint32_t) * 8);


  /*
   * Key Exchange
   */
  /************** EDU: Share Pa and Qb (and curve info) ***************/
  // Point generators exchange
  memcpy(side_a.point_in.x, side_b.point_out.x, sizeof(uint32_t) * 8);
  memcpy(side_a.point_in.y, side_b.point_out.y, sizeof(uint32_t) * 8);
  memcpy(side_b.point_in.x, side_a.point_out.x, sizeof(uint32_t) * 8);
  memcpy(side_b.point_in.y, side_a.point_out.y, sizeof(uint32_t) * 8);

  /*
   * Round 2
   */
  time = RTIMER_NOW();
  //EDU: Generates R = d x Qb
  PT_SPAWN(&(coap_eap_client.pt), &(side_a.pt), ecc_multiply(&side_a));
  time = RTIMER_NOW() - time;
  printf("Round 2, Side a: %i, %lu ms\n", (unsigned)side_a.result,
         (uint32_t)((uint64_t)time * 1000 / RTIMER_SECOND));

  time = RTIMER_NOW();
  //EDU: Generates R = e x Pa
  PT_SPAWN(&(coap_eap_client.pt), &(side_b.pt), ecc_multiply(&side_b));
  time = RTIMER_NOW() - time;
  printf("Round 2, Side b: %i, %lu ms\n", (unsigned)side_b.result,
         (uint32_t)((uint64_t)time * 1000 / RTIMER_SECOND));

  /*
   * Check Result
   */
  memcpy(state.a, side_a.point_out.x, sizeof(uint32_t) * 8);
  memcpy(state.b, side_b.point_out.x, sizeof(uint32_t) * 8);

  PT_SPAWN(&(coap_eap_client.pt), &(state.pt), ecc_compare(&state));
  if(state.result) {
    puts("shared secrets do not match");
  } else {
    puts("shared secrets MATCH");
  }

  puts("-----------------------------------------\n"
       "Disabling pka...");
  pka_disable();

  puts("Done!");
// ECC implementation - end

  while(1) {
    PROCESS_YIELD();

    if(etimer_expired(&et)) {
      printf("--Toggle timer--\n");

      /* prepare request, TID is set by COAP_BLOCKING_REQUEST() */
      coap_init_message(request, COAP_TYPE_CON, COAP_POST, 0);
      coap_set_header_uri_path(request, service_urls[1]);

      const char msg[] = "Toggle!";

      coap_set_payload(request, (uint8_t *)msg, sizeof(msg) - 1);

      LOG_INFO_COAP_EP(&server_ep);
      LOG_INFO_("\n");

      COAP_BLOCKING_REQUEST(&server_ep, request, client_chunk_handler);

      printf("\n--Done--\n");

      etimer_reset(&et);

#if PLATFORM_HAS_BUTTON
#if PLATFORM_SUPPORTS_BUTTON_HAL
    } else if(ev == button_hal_release_event) {
#else
    } else if(ev == sensors_event && data == &button_sensor) {
#endif

      /* send a request to notify the end of the process */

      coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
      coap_set_header_uri_path(request, service_urls[uri_switch]);

      printf("--Requesting %s--\n", service_urls[uri_switch]);

      LOG_INFO_COAP_EP(&server_ep);
      LOG_INFO_("\n");

      COAP_BLOCKING_REQUEST(&server_ep, request,
                            client_chunk_handler);

      printf("\n--Done--\n");

      uri_switch = (uri_switch + 1) % NUMBER_OF_URLS;
#endif /* PLATFORM_HAS_BUTTON */
    }
  }

  PROCESS_END();
}
