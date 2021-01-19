/*
 * Copyright (c) 2019, Pycom Limited.
 *
 * This software is licensed under the GNU GPL version 3 or any
 * later version, with permitted additional terms. For more information
 * see the Pycom Licence v1.0 document supplied with this file, or
 * available at https://www.pycom.io/opensource/licensing
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "py/mpstate.h"
#include "py/obj.h"
#include "py/objstr.h"
#include "py/nlr.h"
#include "py/runtime.h"
#include "py/mphal.h"
#include "py/stream.h"

#include "netutils.h"

#include "esp_system.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_eth.h"

#include "gpio.h"
#include "machpin.h"
#include "pins.h"
#include "ksz8851conf.h"
#include "ksz8851.h"

#include "modeth.h"
#include "mpexception.h"
#include "lwipsocket.h"
//#include "modmachine.h"
//#include "mperror.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/event_groups.h"
#include "freertos/timers.h"

#include "esp32chipinfo.h"
#include "str_utils.h"

// #include "lwip/esp_netif_lwip_internal.h"

/*****************************************************************************
* DEFINE CONSTANTS
*****************************************************************************/
#define ETHERNET_TASK_STACK_SIZE        3072
#define ETHERNET_TASK_PRIORITY          24 // 12
#define ETHERNET_CHECK_LINK_PERIOD_MS   2000
#define ETHERNET_CMD_QUEUE_SIZE         100

//EVENT bits
#define ETHERNET_EVT_CONNECTED        0x0001
#define ETHERNET_EVT_STARTED          0x0002

//#define DEBUG_MODETH
#define MSG(fmt, ...) printf("[%u] modeth %s: " fmt, mp_hal_ticks_ms(), __func__, ##__VA_ARGS__)
// #define MSG(fmt, ...) (void)0

/*****************************************************************************
* DECLARE PRIVATE FUNCTIONS
*****************************************************************************/
static void TASK_ETHERNET (void *pvParameters);
static mp_obj_t eth_init_helper(eth_obj_t *self, const mp_arg_val_t *args);
static IRAM_ATTR void ksz8851_evt_callback(uint32_t ksz8851_evt);
static void process_tx(uint8_t* buff, uint16_t len);
static uint32_t process_rx(void);
// static void eth_validate_hostname (const char *hostname);
STATIC void modeth_event_handler(void* event_handler_arg, esp_event_base_t event_base, int32_t event_id, void* event_data);


/*****************************************************************************
* DECLARE PRIVATE DATA
*****************************************************************************/
eth_obj_t DRAM_ATTR eth_obj = {
        .mac = {0},
        .hostname = {0},
        .link_status = false,
        .sem = NULL,
        .trigger = 0,
        .events = 0,
        .handler = NULL,
        .handler_arg = NULL,
        .esp_netif = NULL,
};

static uint8_t* modeth_rxBuff = NULL;
// #if defined(FIPY) || defined(GPY)
// // Variable saving DNS info
// // static esp_netif_dns_info_t eth_inf_dns_info;
// #endif
uint8_t ethernet_mac[ETH_MAC_SIZE] = {0};
xQueueHandle DRAM_ATTR eth_cmdQueue = NULL;
static DRAM_ATTR EventGroupHandle_t eth_event_group;

/*****************************************************************************
* DEFINE PUBLIC FUNCTIONS
*****************************************************************************/

// struct esp_netif_netstack_lwip_vanilla_config {
//     err_t (*init_fn)(struct netif*);
//     void (*input_fn)(void *netif, void *buffer, size_t len, void *eb);
// };


void eth_pre_init (void) {
    MSG("\n");
    esp_netif_config_t cfg = ESP_NETIF_DEFAULT_ETH();
    const esp_netif_netstack_config_t* s = cfg.stack;
    //struct esp_netif_netstack_lwip_vanilla_config* l = &(cfg.stack->lwip);
    printf("%p\n", cfg.stack); // ->init_fn );
    // printf("%p\n", cfg.stack->lwip );
    //printf("%p\n", cfg.stack->lwip.input_fn );


    eth_obj.esp_netif = esp_netif_new(&cfg);

    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, &modeth_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &modeth_event_handler, NULL));

    //Create cmd Queue
    eth_cmdQueue = xQueueCreate(ETHERNET_CMD_QUEUE_SIZE, sizeof(modeth_cmd_ctx_t));
    //Create event group
    eth_event_group = xEventGroupCreate();

    // create eth Task
    xTaskCreatePinnedToCore(TASK_ETHERNET, "ethernet_task", ETHERNET_TASK_STACK_SIZE / sizeof(StackType_t), NULL, ETHERNET_TASK_PRIORITY, &ethernetTaskHandle, 1);
}

void modeth_get_mac(uint8_t *mac)
{
    memcpy(mac, ethernet_mac, ETH_MAC_SIZE);
}

eth_speed_t get_eth_link_speed(void)
{
    portDISABLE_INTERRUPTS();
    uint16_t speed = ksz8851_regrd(REG_PORT_STATUS);
    portENABLE_INTERRUPTS();
    if((speed & (PORT_STAT_SPEED_100MBIT)))
    {
        return ETH_SPEED_100M;
    }
    else
    {
        return ETH_SPEED_10M;
    }
}

bool is_eth_link_up(void)
{
    return eth_obj.link_status;
}

/*****************************************************************************
* DEFINE PRIVATE FUNCTIONS
*****************************************************************************/


STATIC void modeth_event_handler(void* event_handler_arg, esp_event_base_t event_base, int32_t event_id, void* event_data) 
{
    tcpip_adapter_ip_info_t ip;
    if(event_base == ETH_EVENT) {
        MSG("%s %d\n", event_base, event_id);
        switch(event_id) {
            case ETHERNET_EVENT_CONNECTED:
                MSG("ETHERNET_EVENT_CONNECTED\n");
                break;
            case ETHERNET_EVENT_DISCONNECTED:
                MSG("ETHERNET_EVENT_DISCONNECTED\n");
                // TODO: does this work?
                mod_network_deregister_nic(&eth_obj);
                xEventGroupClearBits(eth_event_group, ETHERNET_EVT_CONNECTED);
                break;
            case ETHERNET_EVENT_START: {
                MSG("ETHERNET_EVENT_START\n");
    tcpip_adapter_ip_info_t eth_ip;
    uint8_t eth_mac[6];

    modeth_get_mac(eth_mac);
    hexdump(eth_mac, 6);

    tcpip_adapter_get_ip_info(TCPIP_ADAPTER_IF_ETH, &eth_ip);

    MSG("ip: " IPSTR " " IPSTR " " IPSTR "\n", IP2STR(&eth_ip.ip), IP2STR(&eth_ip.netmask), IP2STR(&eth_ip.gw));
    // printf("ip: " IPSTR "\n", IP2STR(&eth_ip.ip));

printf("esp_obj.esp_netfi:%p\n", eth_obj.esp_netif);

    tcpip_adapter_eth_start(eth_mac, &eth_ip, NULL);
    //tcpip_adapter_compat_start_netif(eth_obj.esp_netif, eth_mac, eth_ip);


                }
                break;
            case ETHERNET_EVENT_STOP:
                MSG("ETHERNET_EVENT_STOP\n");
                xEventGroupClearBits(eth_event_group, ETHERNET_EVT_STARTED);
                break;
            default:
                MSG("unkown ETH_EVENT: %d\n", event_id);
                break;
        }
    } else if(event_base == IP_EVENT) {
        MSG("%s %d\n", event_base, event_id);
        switch(event_id) {
            case IP_EVENT_ETH_GOT_IP:
                memset(&ip, 0, sizeof(tcpip_adapter_ip_info_t));
                ESP_ERROR_CHECK(tcpip_adapter_get_ip_info(ESP_IF_ETH, &ip));
                MSG("IP_EVENT_ETH_GOT_IP: " IPSTR " " IPSTR " " IPSTR "\n", IP2STR(&ip.ip), IP2STR(&ip.netmask), IP2STR(&ip.gw));
// #if defined(FIPY) || defined(GPY)
//                 MSG("EH save DNS\n");
//                 // Save DNS info for restoring if wifi inf is usable again after LTE disconnect
//                 tcpip_adapter_get_dns_info(TCPIP_ADAPTER_IF_ETH, ESP_NETIF_DNS_MAIN, &eth_inf_dns_info);
// #endif
                mod_network_register_nic(&eth_obj);
                xEventGroupSetBits(eth_event_group, ETHERNET_EVT_CONNECTED);
                break;
            default:
                MSG("unhandled IP_EVENT: %d\n", event_id);
               break;
        }
    } else {
        MSG("unknown event_base %p (%p,%p)\n", event_base, IP_EVENT, ETH_EVENT);
    }
}

static void eth_set_default_inf(void)
{
    MSG("");
// #if defined(FIPY) || defined(GPY)
//     esp_netif_set_dns_info(TCPIP_ADAPTER_IF_ETH, ESP_NETIF_DNS_MAIN, &eth_inf_dns_info);
//     esp_netif_up(TCPIP_ADAPTER_IF_ETH);
// #endif
}

/* print an ethernet frame in a similar style as wireshark */
void print_frame(unsigned char* buf, size_t len){
    for ( uint16_t i = 0; i < len; ++i)
    {
        printf("%02x ", buf[i]);
        if (i%8 == 7)
            printf("  ");
        if (i%16==15)
            printf("\n");
    }
    printf("\n");
}

static void process_tx(uint8_t* buff, uint16_t len)
{
    MSG("process_tx(%u)\n", len);
#ifdef DEBUG_MODETH
    print_frame(buff, len);
#endif
    // disable int before reading buffer
    portDISABLE_INTERRUPTS();
    //ksz8851_regwr(REG_INT_MASK, 0);

    if (eth_obj.link_status) {
        ksz8851BeginPacketSend(len);
        ksz8851SendPacketData(buff, len);
        ksz8851EndPacketSend();
    }

    // re-enable int
    //ksz8851_regwr(REG_INT_MASK, INT_MASK);
    portENABLE_INTERRUPTS();

}

static uint32_t process_rx(void)
{
    // MSG("process_rx\n");

    uint32_t len, frameCnt;
    uint32_t totalLen = 0;

    // disable int before reading buffer
    portDISABLE_INTERRUPTS();
    //ksz8851_regwr(REG_INT_MASK, 0);
    frameCnt = (ksz8851_regrd(REG_RX_FRAME_CNT_THRES) & RX_FRAME_CNT_MASK) >> 8;
    portENABLE_INTERRUPTS();
    MSG("frameCnt %u\n", frameCnt);

    uint32_t frameCntTotal = frameCnt;
    uint32_t frameCntZeroLen = 0;
    while (frameCnt > 0)
    {
        // printf("x %p\n", modeth_rxBuff);
        portDISABLE_INTERRUPTS();
        ksz8851RetrievePacketData(modeth_rxBuff, &len, frameCnt, frameCntTotal);
        portENABLE_INTERRUPTS();
        // printf("y %p %u\n", modeth_rxBuff, len);
        if(len)
        {
            totalLen += len;

            // printf("a %p\n", modeth_rxBuff);
            tcpip_adapter_eth_input(modeth_rxBuff, len, NULL);

            // printf("aa %p\n", modeth_rxBuff);
            // esp_netif_receive(eth_obj.esp_netif, modeth_rxBuff, len, NULL);

            // printf("b\n");
        } else {
            frameCntZeroLen++;
        }
        frameCnt--;
    }

    // re-enable int
    //ksz8851_regwr(REG_INT_MASK, INT_MASK);
    // portENABLE_INTERRUPTS();

    // MSG("process_rx frames=%u (zero=%u) totalLen=%u last: len=%u \n", frameCntTotal, frameCntZeroLen, totalLen, len);
#ifdef DEBUG_MODETH
    if (frameCntTotal){
        // print last frame
        print_frame(modeth_rxBuff, len);
    }
#endif

    return totalLen;
}

static void processInterrupt(void) {
    modeth_cmd_ctx_t ctx;
    ctx.buf = NULL;
    ctx.isr = 0;
    uint16_t processed = 0;

    portDISABLE_INTERRUPTS();

#ifdef DEBUG_MODETH
    uint32_t int_pin_before = pin_get_value(KSZ8851_INT_PIN);
#endif

    // read interrupt status
    ctx.isr = ksz8851_regrd(REG_INT_STATUS);

    // clear interrupt status
    ksz8851_regwr(REG_INT_STATUS, 0xFFFF);

#ifdef DEBUG_MODETH
    uint32_t int_pin_after = pin_get_value(KSZ8851_INT_PIN);

    // read rx reason
    uint16_t rxqcr = ksz8851_regrd(REG_RXQ_CMD);
#endif


    // FIXME: capture errQUEUE_FULL


    if (ctx.isr & INT_RX) {
        ctx.cmd = ETH_CMD_RX;
        xQueueSendToFront(eth_cmdQueue, &ctx, portMAX_DELAY);
        processed++;
    }

    if (ctx.isr & INT_RX_OVERRUN) {
        ctx.cmd = ETH_CMD_OVERRUN;
        xQueueSendToFront(eth_cmdQueue, &ctx, portMAX_DELAY);
        processed++;
    }

    if (ctx.isr & INT_PHY) {
        ctx.cmd = ETH_CMD_CHK_LINK;
        xQueueSendToFront(eth_cmdQueue, &ctx, portMAX_DELAY);
        processed++;
    }

    if ( ! processed ) {
        // This shouldn't happen regularly.
        // It migth be possible to happen in this case:
        // - interupt fires
        // - cmd is put is received via the queue
        // - another interupt fires and puts a new cmd into the queue
        // - processInterrupt for the first one is exectued, but handles both (all) events
        // - later the second cmd is handled but processInterrupt doesn't find anything to do
        // - this case shouldn't be a real problem though
        ctx.cmd = ETH_CMD_OTHER;
        xQueueSend(eth_cmdQueue, &ctx, portMAX_DELAY);
        processed++;
    }

    portENABLE_INTERRUPTS();

#ifdef DEBUG_MODETH
    if ( ctx.isr != 0x2008 || rxqcr != 0x630 )
        MSG("processInterrupt isr=0x%04x rxqcr=0x%04x %s%s%s pin:%u/%u\n", ctx.isr, rxqcr,
            (rxqcr & RXQ_STAT_TIME_INT) ? "t": "",
            (rxqcr & RXQ_STAT_BYTE_CNT_INT) ? "b": "",
            (rxqcr & RXQ_STAT_FRAME_CNT_INT) ? "f": "",
            int_pin_before,
            int_pin_after
        );
#endif
}


/* callback runs from interrupt context */
static IRAM_ATTR void ksz8851_evt_callback(uint32_t ksz8851_evt)
{
    modeth_cmd_ctx_t ctx;
    ctx.cmd = ETH_CMD_HW_INT;
    ctx.buf = NULL;
    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    xQueueSendToFrontFromISR(eth_cmdQueue, &ctx, &xHigherPriorityTaskWoken);
    // seems is needed for link up at the start ... TODO is it actually the best solution to ulTaskNotifyTake() from Task_ETHERNET to wait for link up?
    // xTaskNotifyFromISR(ethernetTaskHandle, 0, eIncrement, NULL);
}

static void TASK_ETHERNET (void *pvParameters) {
    MSG("TE\n");

    static uint32_t thread_notification;
    system_event_t evt;
    modeth_cmd_ctx_t queue_entry;
    uint16_t timeout = 0;
    uint16_t max_timeout = 50u; // 5
    bool link_status = false;

    // Block task till notification is recieved
    thread_notification = ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
    MSG("tn=%u\n", thread_notification);

    if (thread_notification)
    {
        if(ESP_OK != esp_read_mac(ethernet_mac, ESP_MAC_ETH))
        {
            // Set mac to default
            MSG("default mac\n");
            ethernet_mac[0] = KSZ8851_MAC0;
            ethernet_mac[1] = KSZ8851_MAC1;
            ethernet_mac[2] = KSZ8851_MAC2;
            ethernet_mac[3] = KSZ8851_MAC3;
            ethernet_mac[4] = KSZ8851_MAC4;
            ethernet_mac[5] = KSZ8851_MAC5;
        }
        else
        {
            MSG("real mac\n");
            // check for MAC address limitation of KSZ8851 (5th Byte should not be 0x06)
            if(ethernet_mac[4] == 0x06)
            {
                MSG("fix mac\n");
                // OR this byte with last byte
                ethernet_mac[4] |= (ethernet_mac[5] | 0x01 /*Just in case if last byte = 0*/ );
            }
        }
        //save mac
        memcpy(eth_obj.mac, ethernet_mac, ETH_MAC_SIZE);

        //Init spi
        ksz8851SpiInit();
        /* link status  */
        ksz8851RegisterEvtCb(ksz8851_evt_callback);
eth_start:
        MSG("eth_start\n");
        xQueueReset(eth_cmdQueue);
        xEventGroupWaitBits(eth_event_group, ETHERNET_EVT_STARTED, false, true, portMAX_DELAY);
        MSG("init driver\n");
        // Init Driver
        ksz8851Init();

        evt.event_id = SYSTEM_EVENT_ETH_START;
        esp_event_send(&evt);

        MSG("ls=%u 10M=%u 100M=%u\n", get_eth_link_speed(), ETH_SPEED_10M, ETH_SPEED_100M);
        for(;;)
        {
            // if(!eth_obj.link_status && (xEventGroupGetBits(eth_event_group) & ETHERNET_EVT_STARTED))
            // {
            //     // block till link is up again
            //     MSG("link not up\n");
            //     ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
            // }

            if(!(xEventGroupGetBits(eth_event_group) & ETHERNET_EVT_STARTED))
            {
                MSG("not evt_started\n");
                // deinit called, free memory and block till re-init
                xQueueReset(eth_cmdQueue);
                heap_caps_free(modeth_rxBuff);
                eth_obj.link_status = false;
                evt.event_id = SYSTEM_EVENT_ETH_DISCONNECTED;
                esp_event_send(&evt);
                //Disable  interrupts
                portDISABLE_INTERRUPTS();
                ksz8851_regwr(REG_INT_MASK, 0x0000);
                portENABLE_INTERRUPTS();
                MSG("goto eth_start\n");
                goto eth_start;
            }

            // if ( ( uxQueueMessagesWaiting(eth_cmdQueue) == 0 ) && ( interrupt_pin_value == 0 || interrupt_stati != INT_RX_WOL_LINKUP ) ) {
            //     // there is no command,
            //     // however either the interrupt line is low, or there is an atypical status
            //     printStat = true;
            // }
            // if (ct % 100 == 0){
            //     printStat = true;
            // }
            // if (printStat){
            //     printf("TE ct=%u stack:%u queue:%u tx:%u/%u rx:%u/%u:%f link:%u:%u int:0x%x isr:0x%x (%u/%u) rstovf=%u rstint=%u\n",
            //     // port:0x%x speed:%u\n",
            //         ct, stack_high, uxQueueMessagesWaiting( eth_cmdQueue ),
            //         ctTX, totalTX, ctRX, totalRX, ((double)totalRX/ctRX),
            //         ksz8851GetLinkStatus(), get_eth_link_speed(), interrupt_pin_value, interrupt_stati, num_strange_isr, num_strange_isr_zero,
            //         num_resets_overflow, num_resets_int_pin);
            //         // ksz8851_regrd(REG_PORT_STATUS));
            //     printStat = false;
            // }

            if (xQueueReceive(eth_cmdQueue, &queue_entry, 200 / portTICK_PERIOD_MS) == pdTRUE)
            {
                UBaseType_t qw = uxQueueMessagesWaiting(eth_cmdQueue);
                if (qw)
                    printf("queue wait:%u\n", qw);


                switch(queue_entry.cmd)
                {
                    case ETH_CMD_TX:
                        MSG("TX %u\n", queue_entry.len);
                        process_tx(queue_entry.buf, queue_entry.len);
                        break;
                    case ETH_CMD_HW_INT:
                        MSG("INT\n");
                        processInterrupt();
                        break;
                    case ETH_CMD_RX:
                        MSG("RX {0x%x}\n", queue_entry.isr);
                        process_rx();
                        break;
                    case ETH_CMD_CHK_LINK:
                        link_status = ksz8851GetLinkStatus();
                        MSG("CHK_LINK {0x%x} %u\n", queue_entry.isr, link_status);
                        if(link_status)
                        {
                            eth_obj.link_status = true;
                            evt.event_id = SYSTEM_EVENT_ETH_CONNECTED;
                            esp_event_send(&evt);
                        }
                        else
                        {
                            eth_obj.link_status = false;
                            evt.event_id = SYSTEM_EVENT_ETH_DISCONNECTED;
                            esp_event_send(&evt);
                        }
                        break;
                    case ETH_CMD_OVERRUN:
                        MSG("OVERRUN {0x%x} ========================================\n", queue_entry.isr);
                        xQueueReset(eth_cmdQueue);
                        eth_obj.link_status = false;
                        ksz8851PowerDownMode();
                        evt.event_id = SYSTEM_EVENT_ETH_DISCONNECTED;
                        esp_event_send(&evt);
                        vTaskDelay(100 / portTICK_PERIOD_MS);
                        ksz8851Init();
                        break;
                    default:
                        MSG("def cmd:0x%x isr:0x%04x\n", queue_entry.cmd, queue_entry.isr);
                        break;
                }
            }
            else
            {
                timeout = 0;
                // Checking if interrupt line is locked up in Low state
                //TODO: This workaround should be removed once the lockup is resolved
                while((!pin_get_value(KSZ8851_INT_PIN)) && timeout < max_timeout)
                {
                    MSG("TO %u\n", timeout);
                    processInterrupt();
                    vTaskDelay(10 / portTICK_PERIOD_MS);
                    timeout++;
                }
                if(timeout >= max_timeout)
                {
                    printf("ETH interrupt pin stuck\n");
                    xQueueReset(eth_cmdQueue);
                    eth_obj.link_status = false;
                    ksz8851PowerDownMode();
                    evt.event_id = SYSTEM_EVENT_ETH_DISCONNECTED;
                    esp_event_send(&evt);
                    vTaskDelay(100 / portTICK_PERIOD_MS);
                    // TODO: should we ksz8851SpiInit() here?
                    ksz8851Init();

                    // // workaround for the workaround. Even the ksz8851 chip reset above is not enough to reliable restablish eth communication, let's reset the whole chip
                    // printf("ksz8851 lockup detected ... resetting device\n");
                    // vTaskDelay(100 / portTICK_PERIOD_MS);
                    // machine_reset();
                }
            }
        }
    }
}
/*
STATIC void eth_validate_hostname (const char *hostname) {
    //dont set hostname it if is null, so its a valid hostname
    if (hostname == NULL) {
        nlr_raise(mp_obj_new_exception_msg(&mp_type_ValueError, mpexception_value_invalid_arguments));
    }

    uint8_t len = strlen(hostname);
    if(len == 0 || len > TCPIP_HOSTNAME_MAX_SIZE){
        nlr_raise(mp_obj_new_exception_msg(&mp_type_ValueError, mpexception_value_invalid_arguments));
    }
}
*/
/*****************************************************************************
* MICROPYTHON FUNCTIONS
*****************************************************************************/

STATIC const mp_arg_t eth_init_args[] = {
    { MP_QSTR_id,                             MP_ARG_INT,  {.u_int = 0} },
    // { MP_QSTR_hostname,         MP_ARG_KW_ONLY  | MP_ARG_OBJ,  {.u_obj = mp_const_none} },
};
STATIC mp_obj_t eth_make_new(const mp_obj_type_t *type, mp_uint_t n_args, mp_uint_t n_kw, const mp_obj_t *all_args) {
    // parse args
    mp_map_t kw_args;
    mp_map_init_fixed_table(&kw_args, n_kw, all_args + n_args);
    // parse args
    mp_arg_val_t args[MP_ARRAY_SIZE(eth_init_args)];
    mp_arg_parse_all(n_args, all_args, &kw_args, MP_ARRAY_SIZE(args), eth_init_args, args);

    // setup the object
    eth_obj_t *self = &eth_obj;
    self->base.type = (mp_obj_t)&mod_network_nic_type_eth;

    // check the peripheral id
    if (args[0].u_int != 0) {
        nlr_raise(mp_obj_new_exception_msg(&mp_type_OSError, mpexception_os_resource_not_avaliable));
    }
    // start the peripheral
    //eth_init_helper(self, &args[1]);
    eth_init_helper(self, NULL);
    return (mp_obj_t)self;
}

STATIC mp_obj_t modeth_init(mp_uint_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    // parse args
    mp_arg_val_t args[MP_ARRAY_SIZE(eth_init_args) - 1];
    mp_arg_parse_all(n_args - 1, pos_args + 1, kw_args, MP_ARRAY_SIZE(args), &eth_init_args[1], args);
    return eth_init_helper(pos_args[0], args);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_KW(modeth_init_obj, 1, modeth_init);

STATIC mp_obj_t eth_init_helper(eth_obj_t *self, const mp_arg_val_t *args) {
    MSG("init_helper\n");
    // const char *hostname;

    if (!ethernetTaskHandle){
        eth_pre_init();
    }

    // if (args[0].u_obj != mp_const_none) {
    //     MSG("0\n");
    //     hostname = mp_obj_str_get_str(args[0].u_obj);
    //     eth_validate_hostname(hostname);
    //     esp_netif_set_hostname(TCPIP_ADAPTER_IF_ETH, hostname);
    // }

    MSG("get evt_started\n");
    if (!(xEventGroupGetBits(eth_event_group) & ETHERNET_EVT_STARTED)) {
        MSG("not evt_started (%u)\n", esp32_get_chip_rev());
        //alloc memory for rx buff
        // TOOD: could it be that SPIRAM causes the slow eth corruption?
        if (esp32_get_chip_rev() > 0) {
            modeth_rxBuff = heap_caps_malloc(ETHERNET_RX_PACKET_BUFF_SIZE, MALLOC_CAP_SPIRAM);
        }
        else
        {
            modeth_rxBuff = heap_caps_malloc(ETHERNET_RX_PACKET_BUFF_SIZE, MALLOC_CAP_INTERNAL);
        }

        if(modeth_rxBuff == NULL)
        {
            nlr_raise(mp_obj_new_exception_msg(&mp_type_OSError, "Cant allocate memory for eth rx Buffer!"));
        }

        MSG("set evt_started\n");
        xEventGroupSetBits(eth_event_group, ETHERNET_EVT_STARTED);

        //Notify task to start right away
        MSG("tnGive\n");
        xTaskNotifyGive(ethernetTaskHandle);
    }

    MSG("done\n");
    return mp_const_none;
}

STATIC mp_obj_t eth_ifconfig (mp_uint_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    STATIC const mp_arg_t wlan_ifconfig_args[] = {
        { MP_QSTR_config,           MP_ARG_OBJ,     {.u_obj = MP_OBJ_NULL} },
    };

    // parse args
    mp_arg_val_t args[MP_ARRAY_SIZE(wlan_ifconfig_args)];
    mp_arg_parse_all(n_args - 1, pos_args + 1, kw_args, MP_ARRAY_SIZE(args), wlan_ifconfig_args, args);

    esp_netif_dns_info_t dns_info;
    // get the configuration
    if (args[0].u_obj == MP_OBJ_NULL) {
        // get
        esp_netif_ip_info_t ip_info;
        esp_netif_get_dns_info(eth_obj.esp_netif, ESP_NETIF_DNS_MAIN, &dns_info);
        if (ESP_OK == esp_netif_get_ip_info(eth_obj.esp_netif, &ip_info)) {
            mp_obj_t ifconfig[4] = {
                netutils_format_ipv4_addr((uint8_t *)&ip_info.ip.addr, NETUTILS_BIG),
                netutils_format_ipv4_addr((uint8_t *)&ip_info.netmask.addr, NETUTILS_BIG),
                netutils_format_ipv4_addr((uint8_t *)&ip_info.gw.addr, NETUTILS_BIG),
                netutils_format_ipv4_addr((uint8_t *)&dns_info.ip, NETUTILS_BIG)
            };
            return mp_obj_new_tuple(4, ifconfig);
        } else {
            nlr_raise(mp_obj_new_exception_msg(&mp_type_OSError, mpexception_os_operation_failed));
        }
    } else { // set the configuration
        if (MP_OBJ_IS_TYPE(args[0].u_obj, &mp_type_tuple)) {
            // set a static ip
            mp_obj_t *items;
            mp_obj_get_array_fixed_n(args[0].u_obj, 4, &items);

            esp_netif_ip_info_t ip_info;
            netutils_parse_ipv4_addr(items[0], (uint8_t *)&ip_info.ip.addr, NETUTILS_BIG);
            netutils_parse_ipv4_addr(items[1], (uint8_t *)&ip_info.netmask.addr, NETUTILS_BIG);
            netutils_parse_ipv4_addr(items[2], (uint8_t *)&ip_info.gw.addr, NETUTILS_BIG);
            netutils_parse_ipv4_addr(items[3], (uint8_t *)&dns_info.ip, NETUTILS_BIG);

            esp_netif_dhcpc_stop(eth_obj.esp_netif);
            esp_netif_set_ip_info(eth_obj.esp_netif, &ip_info);
            esp_netif_set_dns_info(eth_obj.esp_netif, ESP_NETIF_DNS_MAIN, &dns_info);

        } else {
            // check for the correct string
            const char *mode = mp_obj_str_get_str(args[0].u_obj);
            if (strcmp("dhcp", mode) && strcmp("auto", mode)) {
                nlr_raise(mp_obj_new_exception_msg(&mp_type_ValueError, mpexception_value_invalid_arguments));
            }

            if (ESP_OK != esp_netif_dhcpc_start(eth_obj.esp_netif)) {
                nlr_raise(mp_obj_new_exception_msg(&mp_type_OSError, mpexception_os_operation_failed));
            }
        }
    }

    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_KW(eth_ifconfig_obj, 1, eth_ifconfig);

/*
STATIC mp_obj_t eth_hostname (mp_uint_t n_args, const mp_obj_t *args) {
    eth_obj_t *self = args[0];
    if (n_args == 1) {
        return mp_obj_new_str((const char *)self->hostname, strlen((const char *)self->hostname));
    }
    else
    {
        const char *hostname = mp_obj_str_get_str(args[1]);
        if(hostname == NULL)
        {
            return mp_obj_new_bool(false);
        }
        eth_validate_hostname(hostname);
        esp_netif_set_hostname(TCPIP_ADAPTER_IF_ETH, hostname);
        return mp_const_none;
    }
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(eth_hostname_obj, 1, 2, eth_hostname);
*/

STATIC mp_obj_t modeth_mac (mp_obj_t self_in) {
    eth_obj_t *self = self_in;

    return mp_obj_new_bytes((const byte *)self->mac, sizeof(self->mac));
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(modeth_mac_obj, modeth_mac);

// STATIC mp_obj_t modeth_ksz8851_reg_wr (mp_uint_t n_args, const mp_obj_t *args) {

//     if ((xEventGroupGetBits(eth_event_group) & ETHERNET_EVT_STARTED)) {
//         if(mp_obj_get_int(args[2]) == 0)
//         {
//             //modeth_sem_lock();
//             return mp_obj_new_int(ksz8851_regrd(mp_obj_get_int(args[1])));
//             //modeth_sem_unlock();
//         }
//         else
//         {
//             if (n_args > 3) {
//                 //modeth_sem_lock();
//                 ksz8851_regwr(mp_obj_get_int(args[1]), mp_obj_get_int(args[3]));
//                 //modeth_sem_unlock();
//             }
//             return mp_const_none;
//         }
//     }

//     nlr_raise(mp_obj_new_exception_msg(&mp_type_OSError, "Ethernet module not initialized!"));
//     return mp_const_none;
// }
// STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(modeth_ksz8851_reg_wr_obj, 3, 4, modeth_ksz8851_reg_wr);

STATIC mp_obj_t modeth_deinit (mp_obj_t self_in) {

    system_event_t evt;

    if ((xEventGroupGetBits(eth_event_group) & ETHERNET_EVT_STARTED)) {
        mod_network_deregister_nic(&eth_obj);
        evt.event_id = SYSTEM_EVENT_ETH_STOP;
        esp_event_send(&evt);

        ksz8851PowerDownMode();
    }

    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(modeth_deinit_obj, modeth_deinit);

STATIC mp_obj_t modeth_isconnected(mp_obj_t self_in) {
    if (xEventGroupGetBits(eth_event_group) & ETHERNET_EVT_CONNECTED) {
        return mp_const_true;
    }
    return mp_const_false;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(modeth_isconnected_obj, modeth_isconnected);

STATIC const mp_map_elem_t eth_locals_dict_table[] = {
    { MP_OBJ_NEW_QSTR(MP_QSTR_init),                (mp_obj_t)&modeth_init_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_ifconfig),            (mp_obj_t)&eth_ifconfig_obj },
    // { MP_OBJ_NEW_QSTR(MP_QSTR_hostname),            (mp_obj_t)&eth_hostname_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_mac),                 (mp_obj_t)&modeth_mac_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_deinit),              (mp_obj_t)&modeth_deinit_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_isconnected),         (mp_obj_t)&modeth_isconnected_obj },
#ifdef DEBUG_MODETH
    { MP_OBJ_NEW_QSTR(MP_QSTR_register),            (mp_obj_t)&modeth_ksz8851_reg_wr_obj },
#endif
};
STATIC MP_DEFINE_CONST_DICT(eth_locals_dict, eth_locals_dict_table);

const mod_network_nic_type_t mod_network_nic_type_eth = {
    .base = {
        { &mp_type_type },
        .name = MP_QSTR_ETH,
        .make_new = eth_make_new,
        .locals_dict = (mp_obj_t)&eth_locals_dict,
    },

    .n_gethostbyname = lwipsocket_gethostbyname,
    .n_socket = lwipsocket_socket_socket,
    .n_close = lwipsocket_socket_close,
    .n_bind = lwipsocket_socket_bind,
    .n_listen = lwipsocket_socket_listen,
    .n_accept = lwipsocket_socket_accept,
    .n_connect = lwipsocket_socket_connect,
    .n_send = lwipsocket_socket_send,
    .n_recv = lwipsocket_socket_recv,
    .n_sendto = lwipsocket_socket_sendto,
    .n_recvfrom = lwipsocket_socket_recvfrom,
    .n_setsockopt = lwipsocket_socket_setsockopt,
    .n_settimeout = lwipsocket_socket_settimeout,
    .n_ioctl = lwipsocket_socket_ioctl,
    .n_setupssl = lwipsocket_socket_setup_ssl,
    .inf_up = is_eth_link_up,
    .set_default_inf = eth_set_default_inf
};
