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

#define __CB_FILE__ "cbIP_WLAN_IF"

#include "cb_ip.h"
#include "cb_wlan.h"

#include "cb_dhcps.h"

#include "lwip/netif.h"

#include "netif/etharp.h"
#include "lwip/ethip6.h"
#include "lwip/dhcp.h"
#include "lwip/stats.h"
#include "lwip/dns.h"

#include <string.h>

#include "mbed-drivers/mbed_assert.h"

/*===========================================================================
 * DEFINES
 *=========================================================================*/

#ifndef NDEBUG
#define LWIP_PRINT(...)                printf(__VA_ARGS__)
#else
#define LWIP_PRINT(...)
#endif

#define IFNAME0 'w'
#define IFNAME1 'l'

#define IFNAME "wl0"

/*===========================================================================
 * TYPES
 *=========================================================================*/

typedef struct {
    struct netif hInterface;
    cbIP_interfaceSettings ifConfig;
    cbIP_statusIndication statusCallback;
    void* callbackArg;
} cbIP_wlanIf;

/*===========================================================================
 * DECLARATIONS
 *=========================================================================*/
static err_t cb_netif_init(struct netif* netif);
static err_t wlanif_output_ipv4(struct netif* netif, struct pbuf* p, struct ip_addr* ipaddr);
static err_t wlanif_output_ipv6(struct netif *netif, struct pbuf *p, ip6_addr_t *ipaddr);

static err_t low_level_output(struct netif* netif, struct pbuf* p);
static void netif_status_callback(struct netif *netif);

static void statusIndication(void *callbackContext, cbWLAN_StatusIndicationInfo status, void *data);
static void packetIndication(void *callbackContext, cbWLAN_PacketIndicationInfo *packetInfo);

/*===========================================================================
 * DEFINITIONS
 *=========================================================================*/

cbIP_wlanIf wlanIf;
/*===========================================================================
 * FUNCTIONS
 *=========================================================================*/

void cbIP_initWlanInterfaceStatic(
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
    cbIP_IPv4Address dhcpStartAddress;

    MBED_ASSERT(callback != NULL && hostname != NULL && IPv4Settings != NULL && ifConfig != NULL);

    gw.addr = IPv4Settings->gateway.value;
    ipaddr.addr = IPv4Settings->address.value;
    netmask.addr = IPv4Settings->netmask.value;
    dns0.addr = IPv4Settings->dns0.value;
    dns1.addr = IPv4Settings->dns1.value;

    memcpy(&ip6addr, &IPv6Settings->linklocal.value, sizeof(ip6addr));

    memcpy(&wlanIf.ifConfig, ifConfig, sizeof(wlanIf.ifConfig));
    wlanIf.statusCallback = callback;
    wlanIf.callbackArg = callbackArg;
    netif_add(&wlanIf.hInterface, &ipaddr, &netmask, &gw, &wlanIf, cb_netif_init, ethernet_input);
    wlanIf.hInterface.hostname = hostname;

    wlanIf.hInterface.ip6_autoconfig_enabled = 0;
    if ((ip6addr.addr[0] == 0) && (ip6addr.addr[1] == 0) &&
        (ip6addr.addr[2] == 0) && (ip6addr.addr[3] == 0)) {
        netif_create_ip6_linklocal_address(&wlanIf.hInterface, 1);
    } else {
        memcpy(&wlanIf.hInterface.ip6_addr[0], &ip6addr, sizeof(ip6addr));
    }
    netif_ip6_addr_set_state((&wlanIf.hInterface), 0, IP6_ADDR_TENTATIVE);

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

    wlanIf.statusCallback = callback;
    wlanIf.hInterface.state = &wlanIf;
    netif_set_status_callback(&wlanIf.hInterface, netif_status_callback);
    netif_set_up(&wlanIf.hInterface);

    if (ifConfig->dhcpServerState == cbIP_DHCP_SERVER_ENABLE) {
        dhcpStartAddress = IPv4Settings->address;
        dhcpStartAddress.value = (dhcpStartAddress.value & IPv4Settings->netmask.value);
        dhcpStartAddress.value += htonl(100);
        cbDHCPS_init(IFNAME, dhcpStartAddress);
    }
}

void cbIP_initWlanInterfaceDHCP(
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

    memcpy(&wlanIf.ifConfig, ifConfig, sizeof(wlanIf.ifConfig));

    netif_add(&wlanIf.hInterface, &ipaddr, &netmask, &gw, &wlanIf, cb_netif_init, ethernet_input);
    wlanIf.hInterface.hostname = hostname;
    wlanIf.callbackArg = callbackArg;
    wlanIf.hInterface.ip6_autoconfig_enabled = 0;
    if ((ip6addr.addr[0] == 0) && (ip6addr.addr[1] == 0) &&
        (ip6addr.addr[2] == 0) && (ip6addr.addr[3] == 0)) {
        netif_create_ip6_linklocal_address(&wlanIf.hInterface, 1);
    } else {
        wlanIf.hInterface.ip6_addr[0] = ip6addr;
    }
    netif_ip6_addr_set_state((&wlanIf.hInterface), 0, IP6_ADDR_TENTATIVE);

    wlanIf.statusCallback = callback;
    netif_set_status_callback(&wlanIf.hInterface, netif_status_callback);

    LWIP_PRINT("Using DHCP\n");
    dhcp_start(&wlanIf.hInterface);
}

void cbIP_removeWlanInterface(void)
{
    LWIP_PRINT("Interface down\n");

    cbWLAN_deregisterStatusCallback(statusIndication, &wlanIf.hInterface);
    dhcp_stop(&wlanIf.hInterface);
    netif_remove(&wlanIf.hInterface);
    dhcp_cleanup(&wlanIf.hInterface);
}

/*===========================================================================
 * INTERNAL FUNCTIONS
 *=========================================================================*/

static void statusIndication(void *callbackContext, cbWLAN_StatusIndicationInfo status, void *data)
{
    (void)data;
    struct netif* netif = (struct netif*)callbackContext;

    switch (status) {
        case cbWLAN_STATUS_STOPPED:
        case cbWLAN_STATUS_ERROR:
        case cbWLAN_STATUS_DISCONNECTED:
        case cbWLAN_STATUS_CONNECTION_FAILURE:
        case cbWLAN_STATUS_CONNECTING:
            netif_set_link_down(netif);
            break;
        case cbWLAN_STATUS_CONNECTED:
        case cbWLAN_STATUS_AP_STA_ADDED:
            netif_set_link_up(netif);
            break;
        default:
            break;
    }
}

static void packetIndication(void *callbackContext, cbWLAN_PacketIndicationInfo *packetInfo)
{
    struct netif* netif = (struct netif*)callbackContext;
    struct pbuf* pbuf = (struct pbuf*)packetInfo->rxData;

    MBED_ASSERT(netif != NULL);
    MBED_ASSERT(pbuf != NULL);

    wlanIf.statusCallback(cbIP_NETWORK_ACTIVITY, NULL, NULL, wlanIf.callbackArg);
    netif->input(pbuf, netif);

    LINK_STATS_INC(link.recv);
}

static err_t cb_netif_init(struct netif* netif)
{
    cbIP_wlanIf* hIf;

    netif->name[0] = IFNAME0;
    netif->name[1] = IFNAME1;
    netif->num = 0;
    netif->output = wlanif_output_ipv4;
    netif->output_ip6 = wlanif_output_ipv6;
    netif->linkoutput = low_level_output;
    hIf = (cbIP_wlanIf*)netif->state;

    netif->hwaddr_len = 6;

    netif->hwaddr[0] = hIf->ifConfig.macAddress[0];
    netif->hwaddr[1] = hIf->ifConfig.macAddress[1];
    netif->hwaddr[2] = hIf->ifConfig.macAddress[2];
    netif->hwaddr[3] = hIf->ifConfig.macAddress[3];
    netif->hwaddr[4] = hIf->ifConfig.macAddress[4];
    netif->hwaddr[5] = hIf->ifConfig.macAddress[5];

    netif->mtu = hIf->ifConfig.MTU;

    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_IGMP;

    cbWLAN_registerStatusCallback(statusIndication, &hIf->hInterface);
    cbWLAN_registerPacketIndicationCallback(packetIndication, &hIf->hInterface);

    return ERR_OK;
}

/*--------------------------------------------------------------------------
 * lwIP interface functions
 *-------------------------------------------------------------------------*/

static err_t wlanif_output_ipv4(struct netif* netif, struct pbuf* p, struct ip_addr* ipaddr)
{
    /* resolve hardware address, then send (or queue) packet */
    return etharp_output(netif, p, ipaddr);
}

static err_t wlanif_output_ipv6(struct netif *netif, struct pbuf *p, ip6_addr_t *ipaddr)
{
    return ethip6_output(netif, p, ipaddr);
}

static err_t low_level_output(struct netif* netif, struct pbuf* p)
{
    if (netif_is_link_up(netif)) {
        pbuf_ref(p);
        wlanIf.statusCallback(cbIP_NETWORK_ACTIVITY, NULL, NULL, wlanIf.callbackArg);
        cbWLAN_sendPacket(p);

        LINK_STATS_INC(link.xmit);

        return ERR_OK;
    }

    LINK_STATS_INC(link.drop);

    return ERR_CONN;
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
        wlanIf.statusCallback(cbIP_NETWORK_UP, wlanIf.callbackArg, &ipV4Settings, &ipV6Settings);
    } else {
        wlanIf.statusCallback(cbIP_NETWORK_DOWN, wlanIf.callbackArg, &ipV4Settings, &ipV6Settings);
    }
}
