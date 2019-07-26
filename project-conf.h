#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

#define COAP_MAX_CHUNK_SIZE 512 // Check macro in coap.h before changing value 
/** 
 * Must be bigger than COAP_MAX_CHUNK_SIZE:
 *      COAP_MAX_PACKET_SIZE > (UIP_BUFSIZE - UIP_IPH_LEN - UIP_UDPH_LEN)
 */
#define UIP_CONF_BUFFER_SIZE 600

// Set an alternative PANID other than 0xABCD
#ifdef ALTERNATIVE_PANID
    #if ALTERNATIVE_PANID == 1    //Eduardo
    #define IEEE802154_CONF_PANID            0xDCBA
    #elif ALTERNATIVE_PANID == 0         //Other
    #define IEEE802154_CONF_PANID            0xBBBB
    #endif //else: Default PANID: 0xABCD
#endif

#ifdef CONF_EDU
    // Custom configuration
    #define EDU_DEBUG 1
    //Stack Guard (Atiselsts)
    // #define STACK_CHECK_CONF_ENABLED 1
#else
    #define EDU_DEBUG 0
#endif

#ifdef DEBUG_NOOB
    #define NOOB_DEBUG 1
#else
    #define NOOB_DEBUG 0
#endif

// #define LOG_CONF_LEVEL_IPV6                        LOG_LEVEL_DBG
// #define LOG_CONF_LEVEL_RPL                         LOG_LEVEL_DBG
// #define LOG_CONF_LEVEL_6LOWPAN                     LOG_LEVEL_DBG
// #define LOG_CONF_LEVEL_TCPIP                       LOG_LEVEL_DBG
// #define LOG_CONF_LEVEL_MAC                         LOG_LEVEL_DBG
// #define LOG_CONF_LEVEL_FRAMER                      LOG_LEVEL_DBG

#endif /* PROJECT_CONF_H_ */
