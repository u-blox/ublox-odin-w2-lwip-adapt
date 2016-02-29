/*
* PackageLicenseDeclared: Apache-2.0
* Copyright (c) 2016 u-blox AB, Sweden.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#define __CB_FILE__ "cbIP_PAN_IF"

#include <string.h>
#include <stdio.h>

#include "cb_ip.h"
#include "cb_ip_buf.h"
#include "cb_bt_pan.h"
#include "cb_bt_conn_man.h"
#include "cb_log.h"

#include "lwip/netif.h"

#include "netif/etharp.h"
#include "lwip/ethip6.h"
#include "lwip/dhcp.h"
#include "lwip/stats.h"
#include "lwip/dns.h"

#include "ualloc/ualloc.h"
#include "mbed-drivers/mbed_assert.h"


/*===========================================================================
 * DEFINES
 *=========================================================================*/

#ifndef NDEBUG
#define LWIP_PRINT(...)                cbLOG_PRINT(__VA_ARGS__)
#else
#define LWIP_PRINT(...)
#endif

#define IFNAME0 'b'
#define IFNAME1 'p'

/*===========================================================================
 * TYPES
 *=========================================================================*/

typedef struct {
    struct netif hInterface;
    cbIP_interfaceSettings ifConfig;
    cbIP_statusIndication statusCallback;
    void* callbackArg;
    cbBCM_Handle connHandle;
} cbIP_panIf;

/*===========================================================================
 * DECLARATIONS
 *=========================================================================*/
static err_t cb_netif_init(struct netif* netif);
static err_t panif_output_ipv4(struct netif* netif, struct pbuf* p, struct ip_addr* ipaddr);
static err_t panif_output_ipv6(struct netif *netif, struct pbuf *p, ip6_addr_t *ipaddr);

static err_t low_level_output(struct netif* netif, struct pbuf* p);
static void netif_status_callback(struct netif *netif);

static void handleConnectEvt(cbBCM_Handle connHandle, cbBCM_ConnectionInfo info);
static void handleDisconnectEvt(cbBCM_Handle connHandle);
static void handleDataEvt(cbBCM_Handle connHandle, cb_uint8* pData, cb_uint16 length);
static void handleDataCnf(cbBCM_Handle connHandle, cb_int32 result);

/*===========================================================================
 * DEFINITIONS
 *=========================================================================*/

cbIP_panIf panIf;

static cbBTPAN_Callback _panCallBack =
{
    handleConnectEvt,
    handleDisconnectEvt,
    handleDataEvt,
    handleDataCnf,
};

/*===========================================================================
 * FUNCTIONS
 *=========================================================================*/

void cbIP_initPanInterfaceStatic(
	
    char* hostname, 
    const cbIP_IPv4Settings * const IPv4Settings, 
    const cbIP_IPv6Settings * const IPv6Settings, 
    cbIP_interfaceSettings const * const ifConfig, 
    cbIP_statusIndication callback, 
    void* callbackArg)
{
    struct ip_addr ipaddr;
    struct ip_addr netmask;
    struct ip_addr gw;
    struct ip_addr dns0;
    struct ip_addr dns1;
    struct ip6_addr ip6addr;

	MBED_ASSERT(callback != NULL && hostname != NULL && IPv4Settings != NULL && ifConfig != NULL);

    gw.addr = IPv4Settings->gateway.value;
    ipaddr.addr = IPv4Settings->address.value;
    netmask.addr = IPv4Settings->netmask.value;
    dns0.addr = IPv4Settings->dns0.value;
    dns1.addr = IPv4Settings->dns1.value;

    memcpy(&ip6addr, &IPv6Settings->linklocal.value, sizeof(ip6addr));

    memcpy(&panIf.ifConfig, ifConfig, sizeof(panIf.ifConfig));
    panIf.statusCallback = callback;
    panIf.callbackArg = callbackArg;
    netif_add(&panIf.hInterface, &ipaddr, &netmask, &gw, &panIf, cb_netif_init, ethernet_input);
    panIf.hInterface.hostname = hostname;

    panIf.hInterface.ip6_autoconfig_enabled = 0;
    if ((ip6addr.addr[0] == 0) && (ip6addr.addr[1] == 0) &&
        (ip6addr.addr[2] == 0) && (ip6addr.addr[3] == 0)) {
        netif_create_ip6_linklocal_address(&panIf.hInterface, 1);
    } else {
        memcpy(&panIf.hInterface.ip6_addr[0], &ip6addr, sizeof(ip6addr));
    }
    netif_ip6_addr_set_state((&panIf.hInterface), 0, IP6_ADDR_TENTATIVE);

    dns_setserver(0, &dns0);
    dns_setserver(1, &dns1);

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
    LWIP_PRINT("Primary dns:    %d.%d.%d.%d\n",
               ip4_addr1(&dns0), ip4_addr2(&dns0),
               ip4_addr3(&dns0), ip4_addr4(&dns0));
    LWIP_PRINT("Secondary dns:    %d.%d.%d.%d\n",
               ip4_addr1(&dns1), ip4_addr2(&dns1),
               ip4_addr3(&dns1), ip4_addr4(&dns1));

    panIf.statusCallback = callback;
    panIf.hInterface.state = &panIf;
    netif_set_status_callback(&panIf.hInterface, netif_status_callback);
    netif_set_up(&panIf.hInterface);

    cb_uint32 result;
    result = cbBTPAN_registerDataCallback(&_panCallBack);
    MBED_ASSERT(result == cbBTPAN_RESULT_OK);
}

void cbIP_initPanInterfaceDHCP(
    char* hostname, 
    const cbIP_IPv6Settings * const IPv6Settings, 
    cbIP_interfaceSettings const * const ifConfig, 
    cbIP_statusIndication callback, 
    void* callbackArg)
{
    struct ip_addr ipaddr;
    struct ip_addr netmask;
    struct ip_addr gw;
    struct ip6_addr ip6addr;

    MBED_ASSERT(callback != NULL && hostname != NULL && ifConfig != NULL);

    IP4_ADDR(&gw, 0, 0, 0, 0);
    IP4_ADDR(&ipaddr, 0, 0, 0, 0);
    IP4_ADDR(&netmask, 0, 0, 0, 0);

    memcpy(&ip6addr, &IPv6Settings->linklocal.value, sizeof(ip6addr));

    memcpy(&panIf.ifConfig, ifConfig, sizeof(panIf.ifConfig));

    netif_add(&panIf.hInterface, &ipaddr, &netmask, &gw, &panIf, cb_netif_init, ethernet_input);
    panIf.hInterface.hostname = hostname;
    panIf.callbackArg = callbackArg;
    panIf.hInterface.ip6_autoconfig_enabled = 0;
    if ((ip6addr.addr[0] == 0) && (ip6addr.addr[1] == 0) &&
        (ip6addr.addr[2] == 0) && (ip6addr.addr[3] == 0)) {
        netif_create_ip6_linklocal_address(&panIf.hInterface, 1);
    } else {
        panIf.hInterface.ip6_addr[0] = ip6addr;
    }
    netif_ip6_addr_set_state((&panIf.hInterface), 0, IP6_ADDR_TENTATIVE);

    panIf.statusCallback = callback;
    netif_set_status_callback(&panIf.hInterface, netif_status_callback);

    LWIP_PRINT("Using DHCP\n");
    dhcp_start(&panIf.hInterface);

    cb_uint32 result;
    result = cbBTPAN_registerDataCallback(&_panCallBack);
    MBED_ASSERT(result == cbBTPAN_RESULT_OK);
}

void cbIP_removePanInterface(void)
{
    LWIP_PRINT("Interface down\n");

    dhcp_stop(&panIf.hInterface);
    netif_remove(&panIf.hInterface);
    dhcp_cleanup(&panIf.hInterface);
}

/*===========================================================================
 * INTERNAL FUNCTIONS
 *=========================================================================*/

static void handleConnectEvt(cbBCM_Handle connHandle, cbBCM_ConnectionInfo info)
{
    (void)info;

    printf("%s\n",__FUNCTION__);

    struct netif* netif = &panIf.hInterface;
    netif_set_link_up(netif);
    panIf.connHandle = connHandle;
}

static void handleDisconnectEvt(cbBCM_Handle connHandle)
{
    printf("%s\n",__FUNCTION__);
    
    MBED_ASSERT(panIf.connHandle == connHandle);

    struct netif* netif = &panIf.hInterface;
    netif_set_link_down(netif);
    panIf.connHandle = cbBCM_INVALID_CONNECTION;
}

static void handleDataEvt(cbBCM_Handle connHandle, cb_uint8* pData, cb_uint16 length)
{
    (void)connHandle;
    struct pbuf* pbuf;
    struct netif* netif = &panIf.hInterface;

    pbuf = (struct pbuf*)cbIP_allocDataFrame(length);
    MBED_ASSERT(pbuf != NULL);
    cb_boolean status = cbIP_copyToDataFrame((cbIP_frame*)pbuf,pData,length,0);
    MBED_ASSERT(status);

    panIf.statusCallback(cbIP_NETWORK_ACTIVITY, NULL, NULL, panIf.callbackArg);
    netif->input(pbuf, netif);

    LINK_STATS_INC(link.recv);
}

static void handleDataCnf(cbBCM_Handle connHandle, cb_int32 result)
{
    (void)connHandle;
    (void)result;

    /* Do nothing */
}

static err_t cb_netif_init(struct netif* netif)
{
    cbIP_panIf* hIf;

    netif->name[0] = IFNAME0;
    netif->name[1] = IFNAME1;
    netif->num = 0;
    netif->output = panif_output_ipv4;
    netif->output_ip6 = panif_output_ipv6;
    netif->linkoutput = low_level_output;
    hIf = (cbIP_panIf*)netif->state;

    netif->hwaddr_len = 6;

    netif->hwaddr[0] = hIf->ifConfig.macAddress[0];
    netif->hwaddr[1] = hIf->ifConfig.macAddress[1];
    netif->hwaddr[2] = hIf->ifConfig.macAddress[2];
    netif->hwaddr[3] = hIf->ifConfig.macAddress[3];
    netif->hwaddr[4] = hIf->ifConfig.macAddress[4];
    netif->hwaddr[5] = hIf->ifConfig.macAddress[5];

    netif->mtu = hIf->ifConfig.MTU;

    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_IGMP;

    return ERR_OK;
}

/*--------------------------------------------------------------------------
 * lwIP interface functions
 *-------------------------------------------------------------------------*/

static err_t panif_output_ipv4(struct netif* netif, struct pbuf* p, struct ip_addr* ipaddr)
{
    /* resolve hardware address, then send (or queue) packet */
    return etharp_output(netif, p, ipaddr);
}

static err_t panif_output_ipv6(struct netif *netif, struct pbuf *p, ip6_addr_t *ipaddr)
{
    return ethip6_output(netif, p, ipaddr);
}

static err_t low_level_output(struct netif* netif, struct pbuf* p)
{
    err_t retVal = ERR_CONN;

    if (netif_is_link_up(netif)) {
        pbuf_ref(p);
        panIf.statusCallback(cbIP_NETWORK_ACTIVITY, NULL, NULL, panIf.callbackArg);

        cb_uint32 totSize = cbIP_getDataFrameSize((cbIP_frame*)p);
        UAllocTraits_t t;
        t.flags = 0;
        t.extended = 0;
        cb_uint8* buf = mbed_ualloc(totSize,t);
        MBED_ASSERT(buf != NULL); // Throw away packets if we can not allocate?
        cb_boolean status = cbIP_copyFromDataFrame(buf, (cbIP_frame*)p, totSize, 0);
        MBED_ASSERT(status);
        cb_int32 result = cbBTPAN_reqData(panIf.connHandle,buf,totSize);
        if(result == cbBTPAN_RESULT_OK) {
            retVal = ERR_OK;
            LINK_STATS_INC(link.xmit);
        } else {
            printf("low_level_output - packet dropped\n");
        }
        mbed_ufree(buf);

        return retVal;
    }

    LINK_STATS_INC(link.drop);

    return retVal;
}

static void netif_status_callback(struct netif *netif)
{
    cbIP_IPv4Settings ipV4Settings;
    cbIP_IPv6Settings ipV6Settings;

    ipV4Settings.address.value = netif->ip_addr.addr;
    ipV4Settings.netmask.value = netif->netmask.addr;
    ipV4Settings.gateway.value = netif->gw.addr;
    ipV4Settings.dns0.value = dns_getserver(0).addr;
    ipV4Settings.dns1.value = dns_getserver(1).addr;

    memcpy(&ipV6Settings.linklocal.value, netif->ip6_addr[0].addr, sizeof (cbIP_IPv6Address));

    if (netif->flags & NETIF_FLAG_UP) {
        panIf.statusCallback(cbIP_NETWORK_UP, panIf.callbackArg, &ipV4Settings, &ipV6Settings);
    } else {
        panIf.statusCallback(cbIP_NETWORK_DOWN, panIf.callbackArg, &ipV4Settings, &ipV6Settings);
    }
}
