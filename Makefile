all: udp-client

UIP_CONF_IPV6=1
MODULES+=os/services/shell
#APPS = cantcoap eap-sm powertrace

PROJECT_SOURCEFILES= eap-peer.c eap-psk.c eax.c aes.c  _cantcoap.c 

#CFLAGS += -ffunction-sections -Os
#LDFLAGS += -Wl,--gc-sections,--undefined=_reset_vector__,--undefined=InterruptVectors,--undefined=_copy_data_init__,--undefined=_clear_bss_init__,--undefined=_end_of_init__

CONTIKI = ../..
include $(CONTIKI)/Makefile.include


