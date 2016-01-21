/*---------------------------------------------------------------------------
 * Copyright (c) 2014 connectBlue AB, Sweden.
 * Any reproduction without written permission is prohibited by law.
 *
 * Component: SPA application
 * File     : cb_lwip.c
 *
 * Description: Drives the TCP/IP stack.
 *-------------------------------------------------------------------------*/
#define __CB_FILE__ "cbIP_ETH_IF"

#include "cb_ip.h"
#include "cb_log.h"

#include "lwip/netif.h"

#include "netif/etharp.h"
#include "lwip/dhcp.h"

#include "cb_ethernet.h"
#include <string.h>

/*===========================================================================
 * DEFINES
 *=========================================================================*/

#ifndef NDEBUG
#define LWIP_PRINT(...)                cbLOG_PRINT(__VA_ARGS__)
#else
#define LWIP_PRINT(...)
#endif

#define IFNAME0 'e'
#define IFNAME1 '0'


/*===========================================================================
 * TYPES
 *=========================================================================*/

typedef struct {
    struct netif hInterface;
    cbIP_interfaceSettings ifConfig;
    cbIP_statusIndication statusCallback;
    void* callbackArg;
} cbIP_ethIf;

typedef enum {
    cbIP_ETH_LINKUP,
    cbIP_ETH_LINKDOWN,
} cbIP_ETH_LinkState;


/*===========================================================================
 * DECLARATIONS
 *=========================================================================*/
static err_t cb_netif_init(struct netif* netif);
static err_t ethif_output(struct netif* netif, struct pbuf* p, struct ip_addr* ipaddr);
static err_t low_level_output(struct netif* netif, struct pbuf* p);
static void netif_status_callback(struct netif *netif);

/*===========================================================================
 * DEFINITIONS
 *=========================================================================*/

cbIP_ethIf ethIf;
/*===========================================================================
 * FUNCTIONS
 *=========================================================================*/
static void packetIndication(cb_uint8* pBuf, cb_uint32 len)
{
    static cb_boolean firstTime = TRUE;
    if (firstTime)
    {
        netif_set_link_up(&ethIf.hInterface);
        firstTime = FALSE;
    }
    //copy data
    //netif->input();
    struct pbuf* pbuf = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
    if (pbuf != NULL)
    {
        cb_uint32 bufferIndex = 0;
        struct pbuf* pCurBuf = pbuf;
        cb_ASSERT(ethIf.hInterface.input != NULL);
        cb_ASSERT(len == pbuf->tot_len);

        while (bufferIndex < len && pCurBuf != NULL)
        {
            cb_ASSERT(pCurBuf->payload != NULL);
            cb_ASSERT(pCurBuf->len <= (len - bufferIndex));
            memcpy(pCurBuf->payload, pBuf + bufferIndex, pCurBuf->len);
            bufferIndex += pCurBuf->len;
            pCurBuf = pCurBuf->next;
        }
        cb_ASSERT(pCurBuf == NULL);
        cb_ASSERT(bufferIndex == len);

        if (ethIf.hInterface.input(pbuf, &ethIf.hInterface) != ERR_OK)
        {
            pbuf_free(pbuf);
        }
    }

}

void cbIP_initEthInterfaceStatic(char* hostname, const cbIP_IPv4Settings * const IPv4Settings, cbIP_interfaceSettings const * const ifConfig, cbIP_statusIndication callback)
{
    struct ip_addr ipaddr;
    struct ip_addr netmask;
    struct ip_addr gw;

    cb_ASSERT(callback != NULL && hostname != NULL && ifConfig != NULL);

    if (IPv4Settings == NULL)
    {
        gw.addr = 0;
        ipaddr.addr = 0;
        netmask.addr = 0;
    }
    else
    {
        gw.addr = IPv4Settings->gateway.value;
        ipaddr.addr = IPv4Settings->address.value;
        netmask.addr = IPv4Settings->netmask.value;
    }

    memcpy(&ethIf.ifConfig, ifConfig, sizeof(ethIf.ifConfig));
    ethIf.statusCallback = callback;

   netif_add(&ethIf.hInterface, &ipaddr, &netmask, &gw, &ethIf, cb_netif_init, ethernet_input);
    ethIf.hInterface.hostname = hostname;

    LWIP_PRINT("Using static ip addresses\n");
    LWIP_PRINT("IP address: %d.%d.%d.%d\n",
               ip4_addr1(&ipaddr), ip4_addr2(&ipaddr),
               ip4_addr3(&ipaddr), ip4_addr4(&ipaddr));
    LWIP_PRINT("Netmask:    %d.%d.%d.%d\n",
               ip4_addr1(&netmask), ip4_addr2(&netmask),
               ip4_addr3(&netmask), ip4_addr4(&netmask));
    LWIP_PRINT("Gateway:    %d.%d.%d.%d\n",
               ip4_addr1(&gw), ip4_addr2(&gw),
               ip4_addr3(&gw), ip4_addr4(&gw));

    ethIf.statusCallback = callback;
    netif_set_status_callback(&ethIf.hInterface, netif_status_callback);
    netif_set_up(&ethIf.hInterface);
}

void cbIP_initEthInterfaceDHCP(char* hostname, cbIP_interfaceSettings const * const ifConfig, cbIP_statusIndication callback)
{
    struct ip_addr ipaddr;
    struct ip_addr netmask;
    struct ip_addr gw;

    cb_ASSERT(callback != NULL && hostname != NULL && ifConfig != NULL);

    IP4_ADDR(&gw, 0, 0, 0, 0);
    IP4_ADDR(&ipaddr, 0, 0, 0, 0);
    IP4_ADDR(&netmask, 0, 0, 0, 0);

    ethIf.ifConfig = *ifConfig;

    netif_add(&ethIf.hInterface, &ipaddr, &netmask, &gw, &ethIf, cb_netif_init, ethernet_input);
    ethIf.hInterface.hostname = hostname;

    ethIf.statusCallback = callback;
    netif_set_status_callback(&ethIf.hInterface, netif_status_callback);

    LWIP_PRINT("Using DHCP\n");
    dhcp_start(&ethIf.hInterface);
}

/*===========================================================================
 * INTERNAL FUNCTIONS
 *=========================================================================*/
static err_t cb_netif_init(struct netif* netif)
{
    cbIP_ethIf* hIf;

    netif->name[0] = IFNAME0;
    netif->name[1] = IFNAME1;
    netif->output = ethif_output;
    netif->linkoutput = low_level_output;
    hIf = (cbIP_ethIf*)netif->state;

    netif->hwaddr_len = 6;

    netif->hwaddr[0] = hIf->ifConfig.macAddress[0];
    netif->hwaddr[1] = hIf->ifConfig.macAddress[1];
    netif->hwaddr[2] = hIf->ifConfig.macAddress[2];
    netif->hwaddr[3] = hIf->ifConfig.macAddress[3];
    netif->hwaddr[4] = hIf->ifConfig.macAddress[4];
    netif->hwaddr[5] = hIf->ifConfig.macAddress[5];

    netif->mtu = hIf->ifConfig.MTU;

    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_IGMP;

//     cbWLAN_registerStatusCallback(statusIndication, &hIf->hInterface);
//     cbWLAN_registerPacketIndicationCallback(packetIndication, &hIf->hInterface);
    cbETH_init(netif->hwaddr, packetIndication);

    return ERR_OK;
}

/*--------------------------------------------------------------------------
 * lwIP interface functions
 *-------------------------------------------------------------------------*/

static err_t ethif_output(struct netif* netif, struct pbuf* p, struct ip_addr* ipaddr)
{
    /* resolve hardware address, then send (or queue) packet */
    return etharp_output(netif, p, ipaddr);
}

static err_t low_level_output(struct netif* cb_UNUSED(netif), struct pbuf* p)
{
    err_t res = ERR_USE;
    cb_uint8* pBuf = cbETH_getTransmitBuffer();
    if (pBuf != NULL)
    {
        cb_uint32 bufferIndex = 0;
        struct pbuf* pCurBuf = p;
        cb_boolean ethRes;
        while (pCurBuf != NULL)
        {
            memcpy(pBuf + bufferIndex, pCurBuf->payload, pCurBuf->len);
            bufferIndex += pCurBuf->len;
            pCurBuf = pCurBuf->next;
        }
        cb_ASSERT(pCurBuf == NULL);
        cb_ASSERT(bufferIndex == p->tot_len);
        ethRes = cbETH_transmit(bufferIndex);
        if (ethRes)
        {
            res = ERR_OK;
        }
    }
    return res;
}

static void netif_status_callback(struct netif *netif)
{
    cbIP_IPv4Settings ipV4Settings;
    cbIP_IPv6Settings ipV6Settings;

    ipV4Settings.address.value = netif->ip_addr.addr; // Todo change value to addr?? in cbIP address type
    ipV4Settings.netmask.value = netif->netmask.addr;
    ipV4Settings.gateway.value = netif->gw.addr;

    memcpy(&ipV6Settings.linklocal.value, netif->ip6_addr[0].addr, sizeof (cbIP_IPv6Address));

    if (netif->flags & NETIF_FLAG_UP){
        ethIf.statusCallback(cbIP_NETWORK_UP, ethIf.callbackArg, &ipV4Settings, &ipV6Settings);
    }
    else{
        ethIf.statusCallback(cbIP_NETWORK_DOWN,ethIf.callbackArg, &ipV4Settings, &ipV6Settings);
    }
}