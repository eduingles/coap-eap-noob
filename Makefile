all: udp-client

UIP_CONF_IPV6=1
MODULES += os/services/shell

PROJECT_SOURCEFILES = eap-peer.c eap-noob.c eax.c aes.c _cantcoap.c
# eap-psk.c
CFLAGS += -w

CONTIKI = ../..
include $(CONTIKI)/Makefile.include
