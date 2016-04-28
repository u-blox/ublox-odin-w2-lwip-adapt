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

#define __CB_FILE__ "dhcps"

#include "cb_comdefs.h"
#include "cb_dhcps.h"
#include "lwip/udp.h"
#include "lwip/dhcp.h"

#include "lwip/inet.h"

/* for memcpy() and memcmp() */
#include <string.h>


/*===========================================================================
 * DEFINES
 *=========================================================================*/

/* Debug */
#ifndef NDEBUG
#define DEBUG_PRINT(...)                          printf(__LINE__, __CB_FILE__, __VA_ARGS__)
#else
#define DEBUG_PRINT(x, ...)
#endif
#define DEBUG_DHCPS(...)                    DEBUG_PRINT("DHCPS:" __VA_ARGS__)

/* Configuration */
#define DHCP_OPTION_LENGTH                  312     /* Must be at least 312 bytes according to RFC */
#define DHCP_DISCOVER_LEASE_TIME            10      /* As offered by this server (in seconds) */
#define DHCP_DEFAULT_LEASE_TIME             600     /* As offered by this server (in seconds) */
#define DHCP_MAX_CLIENTS                    12      /* The number of clients the server can manage */
#define DHCP_REQUESTED_IP_LENGTH            4       /* The length of the requested IP */
#define DHCP_CLIENT_IDENTIFIER_LENGTH       32      /* The DHCP specification does not impose a hard 
limit on the size of this field, however, the
ISC DHCP server imposes a limit of 32 bytes on
the length. */

/* Port numbers */
#define DHCP_CLIENT_PORT                    68
#define DHCP_SERVER_PORT                    67

/* DHCP header */
#define DHCP_OP_BOOTREQUEST                 1
#define DHCP_OP_BOOTREPLY                   2
#define DHCP_FLAGS_BROADCAST                (1 << 0)

/* DHCP Options */
#define DHCP_OPTION_PAD                     0
#define DHCP_OPTION_SUBNET_MASK             1
#define DHCP_OPTION_DOMIN_NAME_SERVER       6
#define DHCP_OPTION_BROADCAST_ADDRESS       28
#define DHCP_OPTION_REQUESTED_IP            50
#define DHCP_OPTION_IP_ADDRESS_LEASE_TIME   51
#define DHCP_OPTION_MESSAGE_TYPE            53
#define DHCP_OPTION_SERVER_IDENTIFIER       54
#define DHCP_OPTION_MAX_MESSAGE_SIZE        57
#define DHCP_OPTION_CLIENT_IDENTIFIER       61
#define DHCP_OPTION_END                     255

#define DHCPDISCOVER                        1
#define DHCPOFFER                           2
#define DHCPREQUEST                         3
#define DHCPDECLINE                         4
#define DHCPACK                             5
#define DHCPNAK                             6
#define DHCPRELEASE                         7
#define DHCPINFORM                          8


#define cbSPA_OK                ( 0)
#define cbSPA_ERROR             (-1)
#define cbSPA_IO_ERROR          (-2)
#define cbSPA_BUSY              (-3)
#define cbSPA_EOF               (-4)
#define cbSPA_NOT_AVAIL         (-5)


/*===========================================================================
 * TYPES
 *=========================================================================*/

typedef struct {
    cb_uint32 ipAddr;
    cb_uint32 leaseTimeLeft;
    cb_uint8 clientIdentifier[DHCP_CLIENT_IDENTIFIER_LENGTH];
} cbDHCPS_Client;

typedef struct {
    cbDHCPS_Client clients[DHCP_MAX_CLIENTS];
    cb_uint32 nClients;
    struct udp_pcb* pPCB;

    struct netif * netif;
} cbDHCPS_Class;



cb_PACKED_STRUCT_BEGIN(cbDHCP_Message) {
    cb_uint8 op;
    cb_uint8 htype;
    cb_uint8 hlen;
    cb_uint8 hops;
    cb_uint32 xid;
    cb_uint16 secs;
    cb_uint16 flags;
    cb_uint32 ciaddr;
    cb_uint32 yiaddr;
    cb_uint32 siaddr;
    cb_uint32 giaddr;
    cb_uint8 chaddr[16];
    cb_uint8 sname[64];
    cb_uint8 filename[128];
    cb_uint8 options[DHCP_OPTION_LENGTH];
} cb_PACKED_STRUCT_END(cbDHCP_Message);



/*===========================================================================
 * DECLARATIONS
 *=========================================================================*/
static void udpReceive(void* pArg, struct udp_pcb* pPCB, struct pbuf* pBuf, struct ip_addr* pAddr, u16_t port);


/*===========================================================================
 * DEFINITIONS
 *=========================================================================*/
static cbDHCPS_Class dhcps;

/*===========================================================================
 * FUNCTIONS
 *=========================================================================*/

void cbDHCPS_init(cb_char* ifname, cbIP_IPv4Address startAddress)
{
    cb_uint32 i;
    cb_uint32 j;
    cb_uint32 addr;
    cb_uint32 netmask;
    struct netif * netif;

    memset(&dhcps, 0, sizeof(dhcps));

    netif = netif_find(ifname);

    netmask = netif->netmask.addr;

    dhcps.pPCB = udp_new();
    if (dhcps.pPCB != NULL) {
        err_t err;

        err = udp_bind(dhcps.pPCB, 0, 67);
        if (err == ERR_OK) {
            udp_recv(dhcps.pPCB, udpReceive, 0);
            DEBUG_DHCPS("DHCPS on\n");
        } else {
            /* abort? output diagnostic? */
        }
    } else {
        /* abort? output diagnostic? */
    }

    /* Is the defined netmask big enough for the entire list of possible clients? */
    if (~netmask - 1 < DHCP_MAX_CLIENTS) {
        dhcps.nClients = ~netmask - 1;
        DEBUG_DHCPS("nm < %d(nClients)\n", dhcps.nClients);
    } else {
        dhcps.nClients = DHCP_MAX_CLIENTS;
    }

    /* Pre-assign IP addresses in a linear fashion. Skip our own address. */
    addr = (netif->ip_addr.addr & netmask) + (startAddress.value & (~netmask));
    i = 0;
    j = 0;
    while (i < dhcps.nClients && (j < htonl(~netmask))) {
        if (addr != netif->ip_addr.addr) {
            dhcps.clients[i].ipAddr = addr;
            i++;
        }
        addr += htonl(1);
        j++;
    }

    dhcps.netif = netif;
}

void cbDHCPS_destroy()
{
    if (dhcps.pPCB != NULL) {
        udp_recv(dhcps.pPCB, NULL, NULL);
        udp_remove(dhcps.pPCB);
        dhcps.pPCB = NULL;
    }
}

void cbDHCPS_slowTimer(void)
{
    cb_uint32 i;

    for (i = 0; i < dhcps.nClients; i++) {
        if (dhcps.clients[i].leaseTimeLeft > cbDHCP_SLOW_TIMER_INTERVAL) {
            dhcps.clients[i].leaseTimeLeft -= cbDHCP_SLOW_TIMER_INTERVAL;
        } else {
            dhcps.clients[i].leaseTimeLeft = 0;
        }
    }
}

/*===========================================================================
 * INTERNAL FUNCTIONS
 *=========================================================================*/
/*---------------------------------------------------------------------------
 * Debug stuff
 *-------------------------------------------------------------------------*/
#ifndef NDEBUG
static cb_uint8* ip2string(cb_uint32 ipAddr)
{
    struct in_addr addr;
    addr.s_addr = ipAddr;
    return (cb_uint8*)inet_ntoa(addr);
}

static cb_char* ci2string(cb_uint8* ci, cb_uint32 length)
{
    static cb_char s[DHCP_CLIENT_IDENTIFIER_LENGTH * 2 + 1];
    cb_uint32 i;

    memset(s, 0, sizeof(s));
    for (i = 0; i < length && i < DHCP_CLIENT_IDENTIFIER_LENGTH; i++) {
        cbSTR_snprintf(&s[i * 2], 2, "%02x", ci[i]);
    }

    return s;
}
#endif

/*---------------------------------------------------------------------------
 * Manage list of leases and clients
 *-------------------------------------------------------------------------*/
static void makeAddress(cb_uint8* pFullCI, cb_uint8* pShortCI, cb_uint32 length)
{
    memset(pFullCI, 0, DHCP_CLIENT_IDENTIFIER_LENGTH);
    if (length > 0) {
        if (length > DHCP_CLIENT_IDENTIFIER_LENGTH) {
            length = DHCP_CLIENT_IDENTIFIER_LENGTH;
        }
        memcpy(pFullCI, pShortCI, length);
    }
}

static cb_int32 lookupAddress(cb_uint8* pShortCI, cb_int32 length)
{
    cb_uint8 fullCI[DHCP_CLIENT_IDENTIFIER_LENGTH];
    cb_uint32 i;

    /* Expand (pad with zeros) client identifier to full length */
    makeAddress(fullCI, pShortCI, length);

    /* First check if this device has a record since before */
    for (i = 0; i < dhcps.nClients; i++) {
        if (memcmp(dhcps.clients[i].clientIdentifier, fullCI, DHCP_CLIENT_IDENTIFIER_LENGTH) == 0) {
            return i;
        }
    }

    return -1;
}

static cb_uint32 reserveAddress(cb_uint8* pShortCI, cb_int32 length, cb_uint32 leaseTime)
{
    cb_int32 i;

    /* Check if client is already in list. The spec require us to preserve old mappings. */
    i = lookupAddress(pShortCI, length);

    /* If client is unknown, try to find an unused slot (CI = 0) */
    if (i < 0) {
        i = lookupAddress(NULL, 0);
    }

    /* Last resort. If all slots are taken, break preservation of mappings by taking
       a slot that has an expired lease. */
    if (i < 0) {
        for (i = 0; i < (cb_int32)dhcps.nClients; i++) {
            if (dhcps.clients[i].leaseTimeLeft == 0) {
                break;
            }
        }
    }

    /* Got a match? */
    if (i < (cb_int32)dhcps.nClients) {
        dhcps.clients[i].leaseTimeLeft = leaseTime;
        memset(dhcps.clients[i].clientIdentifier, 0, DHCP_CLIENT_IDENTIFIER_LENGTH);
        memcpy(dhcps.clients[i].clientIdentifier, pShortCI, length);
        DEBUG_DHCPS("resv node %d. ip %s, hw = %s, lease = %d\n",
                    i, ip2string(dhcps.clients[i].ipAddr), ci2string(pShortCI, length), dhcps.clients[i].leaseTimeLeft);
        return dhcps.clients[i].ipAddr;
    }

    /* No mappings left. Out of memory... failed to reserve address. */
    DEBUG_DHCPS("No more addr\n");
    return 0;
}

static void releaseAddress(cb_uint8* pShortCI, cb_int32 length)
{
    cb_uint8 fullCI[DHCP_CLIENT_IDENTIFIER_LENGTH];
    cb_uint32 i;

    /* Expand (pad with zeros) client identifier to full length */
    makeAddress(fullCI, pShortCI, length);

    /* This is a bit special. We iterate the entire list for a match so all can
       leases be released, even stale ones. */
    for (i = 0; i < dhcps.nClients; i++) {
        if (memcmp(dhcps.clients[i].clientIdentifier, fullCI, DHCP_CLIENT_IDENTIFIER_LENGTH) == 0) {
            dhcps.clients[i].leaseTimeLeft = 0;
            DEBUG_DHCPS("rls node %d. ip %s. hw = %s\n",
                        i, ip2string(dhcps.clients[i].ipAddr), ci2string(fullCI, DHCP_CLIENT_IDENTIFIER_LENGTH));
        }
    }
}

/*---------------------------------------------------------------------------
 * Find and return pointer to code, length, and data.
 *-------------------------------------------------------------------------*/
static cb_uint8* findOption(cb_uint32 option, cb_uint8* pOptions)
{
    cb_uint32 i = 4; /* 4 first bytes are magic nr */

    while (i < DHCP_OPTION_LENGTH - 4) {
        if (pOptions[i] == option) {
            return &pOptions[i];
        } else if (pOptions[i] == DHCP_OPTION_END) {
            return NULL;
        } else if (pOptions[i] == DHCP_OPTION_PAD) {
            i++;
        } else {
            i += pOptions[i + 1];
            i += 2;
        }
    }

    return NULL;
}


/*---------------------------------------------------------------------------
 * Remove all options. Write magic header and an end marker.
 *-------------------------------------------------------------------------*/
static void resetOptions(cb_uint8* pOptions)
{
    /* Clear option field by paddding */
    memset(pOptions, DHCP_OPTION_PAD, DHCP_OPTION_LENGTH);

    /* Put magic */
    pOptions[0] = 99;
    pOptions[1] = 130;
    pOptions[2] = 83;
    pOptions[3] = 99;

    /* End marker */
    pOptions[4] = DHCP_OPTION_END;
}


/*---------------------------------------------------------------------------
 * Get pointer to option
 *-------------------------------------------------------------------------*/
static cb_int32 getOptionString(cb_uint8 code, void* pString, cb_uint8* length, cb_uint8* pOptions)
{
    cb_uint8* q;
    cb_uint8* p;

    q = pString;
    p = findOption(code, pOptions);
    if (p == NULL) {
        return cbSPA_ERROR;
    } else {
        /* Skip the code */
        p++;

        /* update length if option is shorter */
        if (*p < *length) {
            *length = *p;
        }
        p++;
        memcpy(q, p, *length);

        return cbSPA_OK;
    }
}

static cb_int32 getOption8(cb_uint8 code, cb_uint8* pValue, cb_uint8* pOptions)
{
    cb_uint8 length = 1;

    return getOptionString(code, pValue, &length, pOptions);
}

/*
static cb_int32 getOption32(cb_uint8 code, cb_uint32* pValue, cb_uint8* pOptions)
{
    cb_uint8 length = 4;
    return getOptionString(code, pValue, &length, pOptions);
}
*/

/*---------------------------------------------------------------------------
 * Add options
 *-------------------------------------------------------------------------*/
static cb_int32 addOptionString(cb_uint8 code, void* pString, cb_uint8 length, cb_uint8* pOptions)
{
    cb_uint8* q;
    cb_uint8* p;

    q = pString;
    p = findOption(DHCP_OPTION_END, pOptions);
    if (p == NULL) {
        return cbSPA_ERROR;
    } else {
        *p++ = code;
        *p++ = length;
        memcpy(p, q, length);
        p += length;
        *p++ = DHCP_OPTION_END;     /* insert new end marker */

        return cbSPA_OK;
    }
}

static cb_int32 addOption8(cb_uint8 code, cb_uint8 value, cb_uint8* pOptions)
{
    return addOptionString(code, &value, 1, pOptions);
}

static cb_int32 addOption32(cb_uint8 code, cb_uint32 value, cb_uint8* pOptions)
{
    return addOptionString(code, &value, 4, pOptions);
}

/*---------------------------------------------------------------------------
 * Allocates a pbuf suitable for DHCP response.
 *-------------------------------------------------------------------------*/
static struct pbuf* allocResponse(cb_uint8* pRequest) {
    struct pbuf* pResponse;
    cbDHCP_Message* pResponseMsg;

    /* This simplified DHCP server don't do lots of options. Thus, the
       standard minimal size will do. */
    pResponse = pbuf_alloc(PBUF_TRANSPORT, sizeof(cbDHCP_Message), PBUF_RAM);
    if (!pResponse) {
        return NULL;
    }

    /* Clear and copy header, but no options, from request */
    memset(pResponse->payload, 0, pResponse->len);
    memcpy(pResponse->payload, pRequest, sizeof(cbDHCP_Message) - DHCP_OPTION_LENGTH);

    /* Make it a reply */
    pResponseMsg = pResponse->payload;
    pResponseMsg->op = DHCP_OP_BOOTREPLY;

    /* Set IP address of next server to use in bootstrap */
    pResponseMsg->siaddr = dhcps.netif->ip_addr.addr;

    /* Set server hostname */
    memcpy(pResponseMsg->sname, dhcps.netif->hostname, sizeof(pResponseMsg->sname));

    /* Reset options */
    resetOptions(pResponseMsg->options);

    return pResponse;
}

static void sendResponse(struct pbuf* pResponse, cb_uint8 messageType)
{
    cbDHCP_Message* pMsg;
    struct ip_addr ipAddrLocal;
    struct ip_addr* ipAddr;
    u16_t port;

    cb_ASSERT(pResponse);
    pMsg = pResponse->payload;

    /* If the 'giaddr' field in a DHCP message from a client is non-zero,
       the server sends any return messages to the DHCP server port on the
       BOOTP relay agent whose address appears in 'giaddr'. */
    if (pMsg->giaddr != 0) {
        ipAddrLocal.addr = pMsg->giaddr;
        ipAddr = &ipAddrLocal;
        port = DHCP_SERVER_PORT;
    } else if (messageType == DHCPNAK) {
        /* In all cases, when 'giaddr' is zero, the server broadcasts any DHCPNAK
           messages to 0xffffffff. */
        ipAddr = IP_ADDR_BROADCAST;
        port = DHCP_CLIENT_PORT;
    } else if (pMsg->ciaddr != 0) {
        /* If the 'giaddr' field is zero and the 'ciaddr' field is nonzero, then
           the server unicasts DHCPOFFER and DHCPACK messages to the address in
           'ciaddr'. */
        ipAddrLocal.addr = pMsg->ciaddr;
        ipAddr = &ipAddrLocal;
        port = DHCP_CLIENT_PORT;
    } else if (pMsg->flags & DHCP_FLAGS_BROADCAST) {
        /* If 'giaddr' is zero and 'ciaddr' is zero, and the broadcast bit is
           set, then the server broadcasts DHCPOFFER and DHCPACK messages to
           0xffffffff. */
        ipAddr = IP_ADDR_BROADCAST;
        port = DHCP_CLIENT_PORT;
    } else {
        /* If the broadcast bit is not set and 'giaddr' is zero and
           'ciaddr' is zero, then the server unicasts DHCPOFFER and DHCPACK
           messages to the client's hardware address and 'yiaddr' address. */

        /* Just do a broadcast. Skip the IP unicast/ethernet broadcast stuff. */
        ipAddr = IP_ADDR_BROADCAST;
        port = DHCP_CLIENT_PORT;
    }

    udp_sendto_if(dhcps.pPCB, pResponse, ipAddr, port, dhcps.netif);
}

/*---------------------------------------------------------------------------
 * DHCP DISCOVER
 * Client broadcast to locate available servers.
 * Server responds with a DHCP OFFER.
 *-------------------------------------------------------------------------*/
static void dhcpDiscover(cb_uint8* pRequest)
{
    cb_uint8 ci[DHCP_CLIENT_IDENTIFIER_LENGTH];
    cb_uint8 ciLength;
    struct pbuf* pResponse;
    cbDHCP_Message* pMsg;
    cbDHCP_Message* pRequestMsg;

    cb_uint32 broadcastAddress = (dhcps.netif->ip_addr.addr & dhcps.netif->netmask.addr) | (0xFFFFFFFFUL & ~dhcps.netif->netmask.addr);

    pResponse = allocResponse(pRequest);
    if (!pResponse) {
        return;
    }
    pMsg = pResponse->payload;
    pRequestMsg = (cbDHCP_Message*)pRequest;

    /* Find, fill in, and reserve a temporary address. If the client identifier
       option is present this shall be used as key, otherwise use hw-addr in
       chaddr. */
    ciLength = DHCP_CLIENT_IDENTIFIER_LENGTH;
    if (getOptionString(DHCP_OPTION_CLIENT_IDENTIFIER, ci, &ciLength, pRequestMsg->options) == cbSPA_OK) {
        pMsg->yiaddr = reserveAddress(ci, ciLength, DHCP_DISCOVER_LEASE_TIME);
    } else {
        pMsg->yiaddr = reserveAddress(pMsg->chaddr, sizeof(pMsg->chaddr), DHCP_DISCOVER_LEASE_TIME);
    }

    if (pMsg->yiaddr == 0) {
        pbuf_free(pResponse);
        return;
    }

    /* Add our options */
    addOption8(DHCP_OPTION_MESSAGE_TYPE, DHCPOFFER, pMsg->options);
    addOption32(DHCP_OPTION_SERVER_IDENTIFIER, dhcps.netif->ip_addr.addr, pMsg->options);
    addOption32(DHCP_OPTION_IP_ADDRESS_LEASE_TIME, htonl(DHCP_DEFAULT_LEASE_TIME), pMsg->options);
    addOption32(DHCP_OPTION_SUBNET_MASK, dhcps.netif->netmask.addr, pMsg->options);
    addOption32(DHCP_OPTION_BROADCAST_ADDRESS, broadcastAddress, pMsg->options);

    /* Send a response */
    sendResponse(pResponse, DHCPOFFER);

    pbuf_free(pResponse);
}

/*---------------------------------------------------------------------------
 * DHCP REQUEST
 * Client message to servers either (a) requesting offered parameters from
 * one server and implicitly declining offers from all others, (b) confirming
 * correctness of previously allocated address after, e.g., system reboot, or
 * (c) extending the lease on a particular network address.
 * Server responds with a DHCP ACK.
 *-------------------------------------------------------------------------*/
static void dhcpRequest(cb_uint8* pRequest)
{
    cb_uint8 ci[DHCP_CLIENT_IDENTIFIER_LENGTH];
    cb_uint32 ipReqAddress;
    cb_uint8 ipLength;
    cb_uint8 ciLength;
    /* const cbSETTINGS_DNS *dns; To do: see below */
    struct pbuf* pResponse;
    cbDHCP_Message* pMsg;
    cbDHCP_Message* pRequestMsg;
    cb_boolean bACK;

    bACK = TRUE;

    pResponse = allocResponse(pRequest);
    if (!pResponse) {
        return;
    }
    pMsg = pResponse->payload;
    pRequestMsg = (cbDHCP_Message*)pRequest;

    ipLength = DHCP_REQUESTED_IP_LENGTH;
    if (getOptionString(DHCP_OPTION_REQUESTED_IP, &ipReqAddress, &ipLength, pRequestMsg->options) == cbSPA_OK) {
        /* If client is on the same subnet send a ACK, if not send and NAK*/
        if ((ipReqAddress & dhcps.netif->netmask.addr) == (dhcps.netif->ip_addr.addr & dhcps.netif->netmask.addr)) {
            cb_int32 addressIndex;

            /* Verify that ipReqAddress is within our pool range and not assigned to other client */
            ciLength = DHCP_CLIENT_IDENTIFIER_LENGTH;
            if (getOptionString(DHCP_OPTION_CLIENT_IDENTIFIER, ci, &ciLength, pRequestMsg->options) == cbSPA_OK) {
                addressIndex = lookupAddress(ci, ciLength);
            } else {
                addressIndex = lookupAddress(pMsg->chaddr, sizeof(pMsg->chaddr));
            }

            if (addressIndex < 0 || dhcps.clients[addressIndex].ipAddr != ipReqAddress) {
                bACK = FALSE;
            }
        } else {
            bACK = FALSE;
        }
    }

    if (bACK == TRUE) {
        /* Find, fill in, and reserve an address. If the client identifier option
           is present this shall be used as key, otherwise use hw-addr in chaddr. */
        ciLength = DHCP_CLIENT_IDENTIFIER_LENGTH;
        if (getOptionString(DHCP_OPTION_CLIENT_IDENTIFIER, ci, &ciLength, pRequestMsg->options) == cbSPA_OK) {
            pMsg->yiaddr = reserveAddress(ci, ciLength, DHCP_DEFAULT_LEASE_TIME);
        } else {
            pMsg->yiaddr = reserveAddress(pMsg->chaddr, sizeof(pMsg->chaddr), DHCP_DEFAULT_LEASE_TIME);
        }

        if (pMsg->yiaddr == 0) {
            pbuf_free(pResponse);
            return;
        }
    }

    if (bACK == TRUE) {
        cb_uint32 broadcastAddress = (dhcps.netif->ip_addr.addr & dhcps.netif->netmask.addr) | (0xFFFFFFFFUL & ~dhcps.netif->netmask.addr);

        /* Add our options */
        addOption8(DHCP_OPTION_MESSAGE_TYPE, DHCPACK, pMsg->options);
        addOption32(DHCP_OPTION_SERVER_IDENTIFIER, dhcps.netif->ip_addr.addr, pMsg->options);
        addOption32(DHCP_OPTION_IP_ADDRESS_LEASE_TIME, htonl(DHCP_DEFAULT_LEASE_TIME), pMsg->options);
        addOption32(DHCP_OPTION_SUBNET_MASK, dhcps.netif->netmask.addr, pMsg->options);

        /* To do: Add this functions, check if OK to add */
        /* dns = cbSETTINGS_getDNS();
        addOption32(DHCP_OPTION_ROUTER, ip->gateway, pMsg->options);
        addOptionString(DHCP_OPTION_DNS_SERVER, &dns->dns, 8, pMsg->options); */
        addOption32(DHCP_OPTION_BROADCAST_ADDRESS, broadcastAddress, pMsg->options);

        /* Send a response */
        sendResponse(pResponse, DHCPACK);
    } else {
        /* Add our options */
        addOption8(DHCP_OPTION_MESSAGE_TYPE, DHCPNAK, pMsg->options);
        addOption32(DHCP_OPTION_SERVER_IDENTIFIER, dhcps.netif->ip_addr.addr, pMsg->options);

        pMsg->yiaddr = 0;
        pMsg->siaddr = 0;

        /* Send a response */
        sendResponse(pResponse, DHCPNAK);
    }

    pbuf_free(pResponse);
}

/*---------------------------------------------------------------------------
 * DHCP DECLINE
 * Client to server indicating network address is already in use.
 * Server responds with a ???.
 *-------------------------------------------------------------------------*/
static void dhcpDecline(cb_uint8* cb_UNUSED(pRequest))
{
    /* TODO: Implement! */
}

/*---------------------------------------------------------------------------
 * DHCP RELEASE
 * Client to server relinquishing network address and cancelling remaining
 * lease.
 *-------------------------------------------------------------------------*/
static void dhcpRelease(cb_uint8* pRequest)
{
    cb_uint8 ci[DHCP_CLIENT_IDENTIFIER_LENGTH];
    cb_uint8 ciLength;
    cbDHCP_Message* pRequestMsg;

    /* Find address to releae. If the client identifier option is present this
       shall be used as key, otherwise use hw-addr in chaddr. */
    pRequestMsg = (cbDHCP_Message*)pRequest;
    ciLength = DHCP_CLIENT_IDENTIFIER_LENGTH;
    if (getOptionString(DHCP_OPTION_CLIENT_IDENTIFIER, ci, &ciLength, pRequestMsg->options) == cbSPA_OK) {
        releaseAddress(ci, ciLength);
    } else {
        releaseAddress(pRequestMsg->chaddr, sizeof(pRequestMsg->chaddr));
    }
}

/*---------------------------------------------------------------------------
 * DHCP INFORM
 * Client to server, asking only for local configuration parameters such as
 * name servers, etc. Client already has externally (manually) configured
 * network address.
 * Server responds with a DHCPACK.
 *-------------------------------------------------------------------------*/
static void dhcpInform(cb_uint8* pRequest)
{
    /* const cbSETTINGS_DNS *dns; To do... see below */
    struct pbuf* pResponse;
    cbDHCP_Message* pMsg;

    cb_uint32 broadcastAddress = (dhcps.netif->ip_addr.addr & dhcps.netif->netmask.addr) | (0xFFFFFFFFUL & ~dhcps.netif->netmask.addr);


    pResponse = allocResponse(pRequest);
    if (!pResponse) {
        return;
    }
    pMsg = pResponse->payload;

    /* Add our options */
    addOption8(DHCP_OPTION_MESSAGE_TYPE, DHCPACK, pMsg->options);
    addOption32(DHCP_OPTION_SERVER_IDENTIFIER, dhcps.netif->ip_addr.addr, pMsg->options);
    addOption32(DHCP_OPTION_IP_ADDRESS_LEASE_TIME, htonl(DHCP_DEFAULT_LEASE_TIME), pMsg->options);
    addOption32(DHCP_OPTION_SUBNET_MASK, dhcps.netif->netmask.addr, pMsg->options);

    /* To do: Add this functions, check if OK to add*/
    /*dns = cbSETTINGS_getDNS();
    addOption32(DHCP_OPTION_ROUTER, ip->gateway, pMsg->options);
    addOptionString(DHCP_OPTION_DNS_SERVER, &dns->dns, 8, pMsg->options); */
    addOption32(DHCP_OPTION_BROADCAST_ADDRESS, broadcastAddress, pMsg->options);

    /* Send a response */
    sendResponse(pResponse, DHCPACK);

    pbuf_free(pResponse);
}

/*---------------------------------------------------------------------------
 *
 *-------------------------------------------------------------------------*/
static void handleRequest(void* pRequest)
{
    cbDHCP_Message* pMsg;
    cb_uint8 messageType;

    pMsg = pRequest;

    /* If it is a real DHCP request option field begins with a magic nr */
    if (!(pMsg->options[0] == 99 && pMsg->options[1] == 130 &&
            pMsg->options[2] == 83 && pMsg->options[3] == 99)) {
        return;
    }

    /* Get DHCP message type */
    if (getOption8(DHCP_OPTION_MESSAGE_TYPE, &messageType, pMsg->options) == cbSPA_ERROR) {
        return;
    }

    /* Act depending on message type */
    switch (messageType) {
        case DHCPDISCOVER:
            dhcpDiscover(pRequest);
            break;
        case DHCPREQUEST:
            dhcpRequest(pRequest);
            break;
        case DHCPDECLINE:
            dhcpDecline(pRequest);
            break;
        case DHCPRELEASE:
            dhcpRelease(pRequest);
            break;
        case DHCPINFORM:
            dhcpInform(pRequest);
            break;
        default:
            break;
    }
}

/*---------------------------------------------------------------------------
 * Receiving UDP data
 *-------------------------------------------------------------------------*/
static void udpReceive(void* cb_UNUSED(pArg), struct udp_pcb* cb_UNUSED(pPCB), struct pbuf* pBuf, struct ip_addr* cb_UNUSED(pAddr), u16_t cb_UNUSED(port))
{
    cbDHCP_Message* pMsg;
    cb_uint8* pRequest;
    struct pbuf* pI;
    cb_uint8* pQ;

    /* Is it a BOOTP request? (at this point we assume that first part, op is the first byte, of the DHCP
       message header is in the first pbuf.) */
    pMsg = pBuf->payload;
    if (pMsg->op == DHCP_OP_BOOTREQUEST) {
        /* Make a copy of fragmentated incoming pBuf into a continuous ram buffer
           for easier handling. */
        pRequest = malloc(pBuf->tot_len);
        if (pRequest) {
            pQ = pRequest;
            pI = pBuf;
            while (pI) {
                memcpy(pQ, pI->payload, pI->len);
                pQ += pI->len;
                pI = pI->next;
            }

            // TODO: replace above with pbuf_copy_partial(pBuf, pRequest, 0, pBuf->tot_len);

            /* Do DHCP processing */
            handleRequest(pRequest);
            free(pRequest);
        }
    }

    pbuf_free(pBuf);
}

