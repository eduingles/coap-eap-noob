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
 * decimalToBinary : Convert decimal to 7-bit binary
 * @str : String to be converted
 * Returns : The input String as binary
**/
char *decimalToBinary(int n)
{  
	int c = 6;
	int d = 0;
	int count = 0;
	char *ptr;
  count = 0;
  ptr = (char*)malloc(6+1);
  for (c = 6 ; c >= 0 ; c--)
  {
     d = n >> c;
     if (d & 1)
        *(ptr+count) = 1 + '0';
     else
        *(ptr+count) = 0 + '0';
     count++;
  }
  *(ptr+count) = '\0';
  return  ptr;
}

/*----------------------------------------------------------------------*/

/**
 * stringToBinary : Convert String to 7-bit binary
 * @str : String to be converted
 * Returns : The input String as binary
**/

char* stringToBinary(char* str){
	if (str == NULL) {
		return 0;	
	}
	size_t len = strlen(str);
	char *binary = malloc(len+1);
	binary[0] = '\0';
	size_t i = 0;
	for (i = 0; i < len; i++){	
		char ch = str[i];
		int j = 6; // 7 bit ASCII
		char* decimal = decimalToBinary(i);
		strcat(binary, decimal);
		while (j >= 0){
			if (ch & (1 << j)){
				strcat(binary, "1");
			}
			else
			{
				strcat(binary, "0");			
			}
			j--;
		}
	}
	return binary;
}

/*----------------------------------------------------------------------*/

static struct etimer et;

PROCESS(led_oob_process, "OOB ENCODING");
PROCESS_THREAD(led_oob_process, ev, data) {

    PROCESS_BEGIN();
    while(1) {
        /* Generating URL */
        char peer_id[23];
        char hoob[23];
        char noob[23];
        read_db(PEER_DB, "PeerId", peer_id);
        read_db(PEER_DB, "Noob", noob);
        read_db(PEER_DB, "Hoob", hoob);
        char url_params[75]; //22+22+22+9
        sprintf(url_params, "P=%s&N=%s&H=%s", peer_id, noob, hoob);
        char msg [120];
        #if EDU_DEBUG
             sprintf(msg, "localhost:8080/sendOOB?%s", url_params);
             printf("OOB URL: %s\n",msg);
        #else
        	sprintf(msg, "193.234.219.186:8080/sendOOB?%s", url_params);
        	printf("OOB URL: %s\n",msg);
         #endif

        char *msg_bin = stringToBinary(msg);

        static char str[1512]; 
        memcpy(str, msg_bin, 1512); 

        static int i = 0;
        static int j = 0;
        static int loop = 0;
				static int rando = 0;

        etimer_set(&et, (1 / CLOCK_SECOND));

			while (1) {
			if (str[i] == '\0') {
				//printf("string index: %d preamble \n", i);
				i = 0;
				//l = 0;
				j = 0;
				//break;
			}
			if (i % 14 == 0){ j = 0;}
			/*------------ frame delimiter / start of frame sequence ------------*/
			if (j == 0){
				j++;
				leds_off(LEDS_GREEN);
				while (loop < 2) {
					PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et)); etimer_reset(&et);
					loop++;
				}
				loop = 0;
				leds_on(LEDS_GREEN); 
				while (loop <= 4) {
					PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et)); etimer_reset(&et);
					loop++;
				}
				loop = 0;
				leds_off(LEDS_GREEN);
				while (loop < 2) {
					PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et)); etimer_reset(&et);
					loop++;
				}
				loop = 0;
			}		
			/*--------------------------------------------------------------------*/
			if (str[i] == '1') {
				leds_on(LEDS_GREEN);
				PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et)); etimer_reset(&et);
				loop = 0;
				leds_off(LEDS_GREEN);
				while (loop < 2){
					PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et)); etimer_reset(&et);
					loop++;
				}
				loop = 0;
			}
			//if (str[i]== '0') {
			else {
				leds_off(LEDS_GREEN);
				while (loop < 2){
					PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et)); etimer_reset(&et);
					loop++;
				}
				loop = 0;
				leds_on(LEDS_GREEN);
				PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et)); etimer_reset(&et); 
			}
			i++;
			rando++;
		if (rando > i) {
			i = 0;
			rando = 0;
		}
		}
	}
	etimer_stop(&et);
	PROCESS_END();	
}
/*----------------------------------------------------------------------*/
