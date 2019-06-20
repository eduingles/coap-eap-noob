all: udp-client

UIP_CONF_IPV6=1
#MODULES += os/services/shell # Enable only in case you need to use the shell
MODULES += os/lib/json # For Contiki-NG to include JSON library

PROJECT_SOURCEFILES = eap-peer.c eap-noob.c eax.c aes.c _cantcoap.c
# eap-psk.c
CFLAGS += -w

# Configure PANID based on user: 1 Eduardo
ifdef MAKE_ALTERNATIVE_PANID
CFLAGS += -DALTERNATIVE_PANID=$(MAKE_ALTERNATIVE_PANID)
endif

CONTIKI = ../..
include $(CONTIKI)/Makefile.include
