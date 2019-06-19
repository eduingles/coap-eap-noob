#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

//EDU: Change UIP buffer size
//#define UIP_CONF_BUFFER_SIZE 180


// Set an alternative PANID other than 0xABCD
#ifdef ALTERNATIVE_PANID
    #if ALTERNATIVE_PANID == 1    //Eduardo
    #define IEEE802154_CONF_PANID            0xDCBA
    #elif ALTERNATIVE_PANID == 0         //Other
    #define IEEE802154_CONF_PANID            0xBBBB
    #endif //else: Default PANID: 0xABCD
#endif

#endif /* PROJECT_CONF_H_ */
