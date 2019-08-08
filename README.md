# Lo-CoAP-EAP with EAP-NOOB in Contiki
=====================================================

About
--------

This repository is an implementation of Lo-CoAP-EAP and EAP-NOOB in Contiki. It is an EAP method for secure bootstrapping of IoT appliances. The specification for EAP-NOOB can be found at: https://datatracker.ietf.org/doc/draft-aura-eap-noob/?include_text=1.

This implementation consists of three separate applications:

1. Contiki Client : Contains EAP-NOOB peer implementation.

2. CoAP-EAP Controller :  Contains CoAP-EAP proxy implementation.

3. EAP-NOOB Server (hostapd) : Contains EAP-NOOB server side implementation (AAA server).

4. NodeJS webserver:  Maintains users accounts and provides a front end for the database tracking the IoT appliances being bootstrapped. Out-of-band (OOB) messages encoded as URLs are sent to, or received from this web server. This server is vital for associating the appliance being bootstrapped with a registered user account.

Licensing
------------       
Copyright (c) 2019, University of Murcia
Copyright (c) 2019, Aalto University
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

Neither the name of the Aalto University nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL AALTO UNIVERSITY BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

See CONTRIBUTORS for more information.

## Clone Contiki-NG

```bash
$ git clone git@github.com:contiki-ng/contiki-ng.git
$ cd contiki-ng
$ git submodule update --init --recursive
```

## Clone CoAP-EAP Client as submodule

```bash
$ git submodule add https://github.com/eduingles/coap-eap-basic.git coap-eap-basic
```

Now you should be able to use normal git actions like push, pull, commit, etc.

## Increase RAM Memory in Zolertia Firefly
Path: [contiki-ng folder]/arch/cpu/cc2538/startup-gcc.c

Change 
```cpp
static uint64_t stack[256] __attribute__ ((section(".stack")));
```
For 
```cpp
static uint64_t stack[512] __attribute__ ((section(".stack")));
```

## Debug flags
- EAP-NOOB: DEBUG_NOOB
- EDU: MAKE_CONF_EDU

## Executing the motes
 - Aleksi:  PANID: 0xABCD (default)
    - Client mote:
        ```bash
        make udp-client.upload TARGET=zoul BOARD=firefly MOTES=/dev/ttyUSB1 login
        ```

    - Bridge mote:

        ```bash
        make border-router.upload TARGET=zoul BOARD=firefly MOTES=/dev/ttyUSB0
        ```

        ```bash
        make TARGET=zoul BOARD=firefly connect-router
        ```

 - Eduardo: PANID: 0xDCBA
    - Client mote:
        ```bash
        make udp-client.upload TARGET=zoul BOARD=firefly MOTES=/dev/ttyUSB1 MAKE_ALTERNATIVE_PANID=1 MAKE_CONF_EDU=1 WERROR=0 login
        ```
        NOTE: Remember to set the same PANID in examples/rpl-border-router

    - Bridge mote:

        ```bash
        make border-router.upload TARGET=zoul BOARD=firefly MOTES=/dev/ttyUSB0
        ```

        ```bash
        make TARGET=zoul BOARD=firefly connect-router
        ```

## Executing the controller
    https://github.com/eduingles/coap-eap-controller

## Reconnect Exchange 
There are two ways of starting the Reconnect Exhange:

    - Wait until timeout expires
    - Press right button in Client mote

