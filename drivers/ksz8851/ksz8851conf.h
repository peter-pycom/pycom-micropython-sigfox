#ifndef KSZ8851CONF_H
#define KSZ8851CONF_H

#define KSZ8851_SPI_NUM                                          (SpiNum_SPI3)

#ifdef PYGATE_ENABLED
// Pygate
#define KSZ8851_SCLK_PIN                                         (&PIN_MODULE_P21)
#define KSZ8851_MOSI_PIN                                         (&PIN_MODULE_P23)
#define KSZ8851_MISO_PIN                                         (&PIN_MODULE_P17)
#define KSZ8851_NSS_PIN                                          (&PIN_MODULE_P22)
#define KSZ8851_RST_PIN                                          (&PIN_MODULE_P19)
#define KSZ8851_INT_PIN                                          (&PIN_MODULE_P18)
#else
// Expansion board 4.0
#define KSZ8851_SCLK_PIN                                         (&PIN_MODULE_P22) 
// 10)
// P22 = GPIO 9
#define KSZ8851_MOSI_PIN                                         (&PIN_MODULE_P11)
// P11 = GPIO 22
#define KSZ8851_MISO_PIN                                         (&PIN_MODULE_P14)
// 16
// P14 = GPIO 4
#define KSZ8851_NSS_PIN                                          (&PIN_MODULE_P3)
// P3 = GPIO 24
#define KSZ8851_RST_PIN                                          (&PIN_MODULE_P8)
// 9)
// P8 = GPIO 15
#define KSZ8851_INT_PIN                                          (&PIN_MODULE_P13)
// P13 = GPIO 5
#endif


#define KSZ8851_MAC0    '0'
#define KSZ8851_MAC1    'F'
#define KSZ8851_MAC2    'F'
#define KSZ8851_MAC3    'I'
#define KSZ8851_MAC4    'C'
#define KSZ8851_MAC5    'E'

#endif
