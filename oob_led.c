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

 #include "oob_led.h"

/**
 * string_to_binary : Convert String to binary
 * @str : String to be converted
 * Returns : The input String as binary
**/
static char *string_to_binary(char *str)
{
    if (str == NULL)
        return 0;
    size_t len = strlen(str);
    char *binary = malloc(len*8 + 1); // The use of malloc is not recommended
    binary[0] = '\0';
    size_t i = 0;

    for (i = 0; i < len; i++) {
        char ch = str[i];
        int j = 7;
        while (j >= 0) {
            if (ch & (1 << j))
                strcat(binary, "1");
            else
                strcat(binary, "0");
            j--;
        }
    }
    return binary;
}

static struct etimer et_oob;

PROCESS(led_oob_process, "OOB ENCODING");
PROCESS_THREAD(led_oob_process, ev, data) {

    PROCESS_BEGIN();
    /* String prefix of characters, e.g. +26 or +9 to indicate string
     * length of 3 character sets. (+26 equals 26*3 character string length
     * without prefix)
     */
    while(1) {
        /* Generating URL */
        // char peer_id[23];
        // char hoob[23];
        // char noob[23];
        // read_db(PEER_DB, "PeerId", peer_id);
        // read_db(PEER_DB, "Noob", noob);
        // read_db(PEER_DB, "Hoob", hoob);
        // char url_params[75]; //22+22+22+9
        // sprintf(url_params, "P=%s&N=%s&H=%s", peer_id, noob, hoob);
        // char msg [130];
        // #if EDU_DEBUG
        //     sprintf(msg, "+35https://localhost:8080/sendOOB?%s", url_params);
        //     printf("OOB URL: %s\n",msg);
        // #else
        //     sprintf(msg, "+37https://193.234.219.186:8080/sendOOB?%s", url_params);
        //     printf("OOB URL: %s\n",msg);
        // #endif

        char *msg = "+33https://example.com/123456789/123456789/123456789/123456789/123456789/123456789/123456789/123456789";
        char *msg_bin = string_to_binary(msg);

        static char str[960]; // currently for (120 * 8) or OOB message * 8
        memcpy(str, msg_bin, 960); 
        if (strlen(msg) % 3 != 0) {
            printf("EAP-NOOB: OOB string is of incorrect size\n");
        }

        static int i = 0;
        static int j = 0;
        static int l = 0;
        static int loop = 0;
        static int payload_len = 24;  // 3 * 8
        static int repeat = 14;

        etimer_set(&et_oob, (1 / CLOCK_SECOND));
        while(1) {
            /* Any printf or other similar tasks during blinking process may disrupt
            * blinking resulting in some frames not being sent properly.
            */
            if (str[i] == '\0') {
                printf("String index: %d\n", i);
                i = 0; l = 0; j = 0;
                break;
            }
        /*---------- frame delimiter / start of frame sequence ----------*/
            if (j == 0) {
                j++;
                leds_off(LEDS_GREEN);
                while (loop < 2) {
                    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et_oob));
                    etimer_reset(&et_oob);
                    loop++;
                }
                loop = 0;
                leds_on(LEDS_GREEN);
                while (loop < 5) {
                    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et_oob));
                    etimer_reset(&et_oob);
                    loop++;
                }
                loop = 0;
                leds_off(LEDS_GREEN);
                while (loop < 2) {
                    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et_oob));
                    etimer_reset(&et_oob);
                    loop++;
                }
                loop = 0;
            }
            /*---------------------------------------------------------------*/
            if (str[i] == '1') {
                leds_on(LEDS_GREEN);
                PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et_oob));
                etimer_reset(&et_oob);
                loop = 0;
                leds_off(LEDS_GREEN);
                while (loop < 2){
                    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et_oob));
                    etimer_reset(&et_oob);
                    loop++;
                }
                loop = 0;
            } else {
                leds_off(LEDS_GREEN);
                while (loop < 2) {
                    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et_oob));
                    etimer_reset(&et_oob);
                    loop++;
                }
                loop = 0;
                leds_on(LEDS_GREEN);
                PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et_oob));
                etimer_reset(&et_oob);
            }
            i++;

            if (i % (payload_len) == 0) {
                /* Repeats each three character sets / 24 bits for 'repeat'
                * times. Needed for reading the messages in the correct order.
                * Increase the repeat value if messages are not read in order.
                */
                j = 0; // sets frame delimiter
                int m_len = 34; // OOB message length including prefix
                if (l > repeat * m_len)
                    l = -1;
                if (l < repeat) {
                    i = 0;
                } else {
                    for (int c = 2; c <= m_len; c++) { // c < 34 fails on longer OOB messages, ideally same as msg prefix + 1
                        if (l <= repeat*c) {
                            i = payload_len * (c-1);
                            break;
                        }
                    }
                }
                l++;
            }
        }
    }
    etimer_stop(&et_oob);
    PROCESS_END();
}
/*----------------------------------------------------------------------*/
