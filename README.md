

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
