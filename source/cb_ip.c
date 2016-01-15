/*---------------------------------------------------------------------------
 * Copyright (c) 2014 connectBlue AB, Sweden.
 * Any reproduction without written permission is prohibited by law.
 *
 * Component: SPA application
 * File     : cb_lwip.c
 *
 * Description: Drives the TCP/IP stack.
 *-------------------------------------------------------------------------*/
#define __CB_FILE__ "cbIP"

#include "string.h"

#include "cb_comdefs.h"
#include "cb_ip.h"
#include "cb_os.h"

#include "cb_timer.h"
#include "cb_hw.h"

#include "lwip/def.h"
#include "arch/sys_arch.h"
#include "lwip/init.h"
#include "lwip/timers.h"
#include "lwip/inet.h"
#include "lwip/ip4_addr.h"
#include "lwip/dns.h"
#include "lwip/netif.h"

#include "cb_os.h"
/*===========================================================================
 * DEFINES
 *=========================================================================*/
// Shortest interval in LWIP seems to be 100ms.
#define LWIP_TMR_INTERVAL   100

#ifndef NDEBUG
#define LWIP_PRINT(...)                cbLOG_PRINT(__VA_ARGS__)
#else
#define LWIP_PRINT(...)
#endif

/*===========================================================================
 * TYPES
 *=========================================================================*/
typedef struct {
    cbTIMER_Id lwipTimerId;
} cbIP;

/*===========================================================================
 * DECLARATIONS
 *=========================================================================*/
static void lwipTimerCallback(cbTIMER_Id id, cb_int32 arg1, cb_int32 arg2);

/*===========================================================================
 * DEFINITIONS
 *=========================================================================*/
static cbIP hIP;

/*===========================================================================
 * FUNCTIONS
 *=========================================================================*/

void cbIP_init(void)
{
    /* Startup lwIP */
    lwip_init();

    hIP.lwipTimerId = cbTIMER_every(LWIP_TMR_INTERVAL, lwipTimerCallback, 0, 0);
}

cb_boolean cbIP_UTIL_aton(const cb_char *str, cbIP_IPv4Address *addr)
{
    cb_int res;
    ip_addr_t ip_addr;
    res = inet_aton(str, &ip_addr);
    addr->value = ip_addr.addr;
    return (cb_boolean)res;
}

cb_char* cbIP_UTIL_ntoa(const cbIP_IPv4Address *addr, char *buf, int buflen)
{
    ip_addr_t ip_addr;
    ip_addr.addr = addr->value;
    return (cb_char*)ipaddr_ntoa_r(&ip_addr, buf, buflen);
}

cb_boolean cbIP_UTIL_ip6addr_aton(const cb_char *str, cbIP_IPv6Address *addr)
{
    cb_int res;
    ip6_addr_t ip_addr;
    res = ip6addr_aton(str, &ip_addr);
    memcpy(&addr->value, ip_addr.addr, sizeof (cbIP_IPv6Address));
    return (cb_boolean)res;
}

cb_char* cbIP_UTIL_ip6addr_ntoa(const cbIP_IPv6Address *addr, char *buf, int buflen)
{
    ip6_addr_t ip_addr;
    memcpy(&ip_addr.addr, &addr->value, sizeof(ip6_addr_t));
    buf = ip6addr_ntoa_r(&ip_addr, buf, buflen);
    if (buf != NULL && strlen(buf) == 1 && buf[0] == ':') {
        buf[1] = ':';
    }
    return (cb_char*)buf;
}

cb_boolean cbIP_gethostbyname(const cb_char *str, cbIP_IPv4Address* ip_addr, cbIP_addrResolvedCallback callback, void* arg)
{  
    err_t status;
    ip_addr_t address;

    cb_ASSERT(ip_addr != NULL);

    status = dns_gethostbyname(str, &address, callback, arg);   // TODO: Unsafe callback as the cbIP_IPv4Address may differ from ip_addr_t.

    if (status == ERR_OK) {
        ip_addr->value = address.addr;
    }

    if (status == ERR_INPROGRESS) {
        return TRUE;
    }

    return FALSE;
}

cbIP_Netif* cbIP_getNetif(cbIP_IPv4Address addr)
{
    for (struct netif* netif = netif_list; netif != NULL; netif = netif->next)
    {
        if (addr.value == netif->ip_addr.addr)
        {
            return (cbIP_Netif*)netif;
        }
    }
    return NULL;
}

void cbIP_setDefaultNetif(cbIP_IPv4Address addr)
{
    cbIP_Netif* netif = cbIP_getNetif(addr);
    if (netif != NULL)
    {
        netif_set_default((struct netif*)netif);
    }
}

/*===========================================================================
 * LWIP system hooks
 *=========================================================================*/

/** Ticks/jiffies since power up. */
u32_t sys_jiffies()
{
    return (u32_t)cbHW_getTicks();
}

/** Returns the current time in milliseconds,
 * may be the same as sys_jiffies or at least based on it. */
u32_t sys_now()
{
    return (u32_t)(cbHW_getTicks() / ((cbHW_getTickFrequency() + 999) / 1000));
}

sys_prot_t sys_arch_protect(void)
{
    return cbOS_enterCritical();
}

void sys_arch_unprotect(sys_prot_t pval)
{
    cbOS_exitCritical((cb_uint32)pval);
}

/*===========================================================================
 * INTERNAL FUNCTIONS
 *=========================================================================*/

static void lwipTimerCallback(cbTIMER_Id id, cb_int32 arg1, cb_int32 arg2)
{
    sys_check_timeouts();
}
