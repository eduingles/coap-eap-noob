all: udp-client

UIP_CONF_IPV6=1
MODULES += os/lib/json # For Contiki-NG to include JSON library

PROJECT_SOURCEFILES += eap-noob.c eap-peer.c
PROJECT_SOURCEFILES += ecc_pubkey.c ecc_shared_secret.c sha256_calc.c sha256_mac.c
PROJECT_SOURCEFILES += aes.c database.c base64.c oob_led.c # eax.c

# Configure PANID based on user: 1 Eduardo
ifdef MAKE_ALTERNATIVE_PANID
	CFLAGS += -DALTERNATIVE_PANID=$(MAKE_ALTERNATIVE_PANID)
endif

# Eduardo: Custom Configuration
ifeq ($(MAKE_CONF_EDU),1)
	CFLAGS += -DCONF_EDU=1
endif

ifeq ($(DEBUG_NOOB),1)
	CFLAGS += -DDEBUG_NOOB=1
endif


CONTIKI = ../..
include $(CONTIKI)/Makefile.include
