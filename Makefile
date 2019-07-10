all: udp-client

UIP_CONF_IPV6=1
#MODULES += os/services/shell # Enable only in case you need to use the shell
MODULES += os/lib/json # For Contiki-NG to include JSON library

PROJECT_SOURCEFILES = eap-noob.c eap-peer.c ecc_pubkey.c ecc_shared_secret.c eax.c aes.c _cantcoap.c
# eap-psk.c

# Configure PANID based on user: 1 Eduardo
ifdef MAKE_ALTERNATIVE_PANID
CFLAGS += -DALTERNATIVE_PANID=$(MAKE_ALTERNATIVE_PANID)
endif

# Eduardo: Custom Configuration
ifeq ($(MAKE_CONF_EDU),1)
CFLAGS += -DCONF_EDU=1
else  # Aleksi
CFLAGS += -w
endif


CONTIKI = ../..
include $(CONTIKI)/Makefile.include
