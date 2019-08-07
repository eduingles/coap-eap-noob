
#include "contiki.h"
#include "sys/etimer.h"
#include "dev/leds.h"

#include <stdio.h>
#include <stdlib.h>

/*----------------------------------------------------------------------*/
// help function to get string in binary form
char* stringToBinary(char* str){
	if (str == NULL) {
		return 0;	
	}
	size_t len = strlen(str);
	char *binary = malloc(len*8 + 1);
	binary[0] = '\0';
	size_t i = 0;
	for (i = 0; i < len; i++){	
		char ch = str[i];
		int j = 7;
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

PROCESS(led_oob_process, "led process");
AUTOSTART_PROCESSES(&led_oob_process);

/*----------------------------------------------------------------------*/
static struct etimer et;
PROCESS_THREAD(led_oob_process, ev, data)
{
	PROCESS_BEGIN();
	// string prefix of characters, e.g., +26 or ++9 to indicate string
	// length of 3 character sets. (+26 equals 26*3 character string length 
	// without prefix)
	char* msg = "+33https://example.com/123456789/123456789/123456789/123456789/123456789/123456789/123456789/123456789";
	//printf("Message payload len: %d", strlen(msg)/3-1);*/
	char *msg_bin = stringToBinary(msg);
	static char str[960]; // (120 * 8) or OOB message * 8 
	memcpy(str, msg_bin, 960);
	if (strlen(msg) % 3 != 0){
		printf("String is not correct length.\n");
		memcpy(str, " ");
	}
	static int i = 0;
	static int j = 0;
	static int l = 0;
	static int loop = 0;
	static int payload_len = 24;  // 3 * 8
	static int repeat = 14;
	etimer_set(&et, (1 / CLOCK_SECOND));
	while(1) {
		// Any printf or other similar tasks during blinking process may disrupt blinking
		// resulting in some frames not being sent properly.
		while (1) {
			//printf("value of i: %d\n", i);
			/*if (str[i] == '\0') {
				printf("string index: %d\n", i);
				i = 0;
				l = 0;
				j = 0;
				break;
			}*/
			/*------------ frame delimiter / start of frame sequence ------------*/
			if (j == 0){
				j++;
				leds_off(LEDS_GREEN);
				while (loop < 4) {
					PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et)); etimer_reset(&et);
					loop++;
				}
				loop = 0;
				leds_on(LEDS_GREEN); 
				while (loop < 10) {
					PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et)); etimer_reset(&et);
					loop++;
				}
				loop = 0;
				leds_off(LEDS_GREEN);
				while (loop < 4) {
					PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et)); etimer_reset(&et);
					loop++;
				}
				loop = 0;
			}			
			/*--------------------------------------------------------------------*/
			if (str[i] == '1') {
				leds_on(LEDS_GREEN);
				while (loop < 2){
					PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et)); etimer_reset(&et);
					loop++;
				}
				loop = 0;
				leds_off(LEDS_GREEN);
				while (loop < 4){
					PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et)); etimer_reset(&et);
					loop++;
				}
				loop = 0;
			}
			//if (str[i]== '0') {
			else {
				leds_off(LEDS_GREEN);
				while (loop < 4){
					PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et)); etimer_reset(&et);
					loop++;
				}
				loop = 0;
				leds_on(LEDS_GREEN);	
				while (loop < 2){
					PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et)); etimer_reset(&et);
					loop++;
				}
				loop = 0;  
			}
			i++;

			if ( i % (payload_len) == 0) {
			// Repeats each three character sets / 24 bits for 'repeat' times. 
			// Needed for reading the messages in correct order
			// Increase the repeat value if messages are not read in order.
				j = 0; // sets frame delimiter
				//printf("value of l: %d ", l);
				if (l > repeat*34) l = -1;
				if (l <= repeat*34) i = payload_len*33;
				if (l <= repeat*33) i = payload_len*32;
				if (l <= repeat*32) i = payload_len*31;
				if (l <= repeat*31) i = payload_len*30;
				if (l <= repeat*30) i = payload_len*29;
				if (l <= repeat*29) i = payload_len*28;
				if (l <= repeat*28) i = payload_len*27;
				if (l <= repeat*27) i = payload_len*26;
				if (l <= repeat*26) i = payload_len*25;
				if (l <= repeat*25) i = payload_len*24;
				if (l <= repeat*24) i = payload_len*23;
				if (l <= repeat*23) i = payload_len*22;
				if (l <= repeat*22) i = payload_len*21;
				if (l <= repeat*21) i = payload_len*20;
				if (l <= repeat*20) i = payload_len*19;
				if (l <= repeat*19) i = payload_len*18;
				if (l <= repeat*18) i = payload_len*17;
				if (l <= repeat*17) i = payload_len*16;
				if (l <= repeat*16) i = payload_len*15;
				if (l <= repeat*15) i = payload_len*14;
				if (l <= repeat*14) i = payload_len*13;
				if (l <= repeat*13) i = payload_len*12;
				if (l <= repeat*12) i = payload_len*11;
				if (l <= repeat*11) i = payload_len*10;
				if (l <= repeat*10) i = payload_len*9;
				if (l <= repeat*9)  i = payload_len*8;
				if (l <= repeat*8)  i = payload_len*7;
				if (l <= repeat*7)  i = payload_len*6;
				if (l <= repeat*6)  i = payload_len*5;
				if (l <= repeat*5)  i = payload_len*4;
				if (l <= repeat*4)  i = payload_len*3;
				if (l <= repeat*3)  i = payload_len*2;
				if (l <= repeat*2)  i = payload_len;
				if (l < repeat)   i = 0;
				l++;
			}
		}
	}
	etimer_stop(&et);
	PROCESS_END();	
}
/*----------------------------------------------------------------------*/

