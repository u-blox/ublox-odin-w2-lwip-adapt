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

#define __CB_FILE__ "cbIP"

#include "string.h"

#include "cb_comdefs.h"
#include "cb_ip.h"

#include "cb_hw.h"
#include "cb_wlan_target_data.h"
#include "cb_types.h"
#include "cb_wlan_types.h"
#include "cb_ip_buf.h"

#include "lwip/def.h"
#include "arch/sys_arch.h"
#include "lwip/init.h"
#include "lwip/timers.h"
#include "lwip/inet.h"
#include "lwip/ip4_addr.h"
#include "lwip/dns.h"
#include "lwip/netif.h"

#include "core-util/critical.h"
#include "mbed-drivers/mbed_assert.h"
#include "minar/minar.h"

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

/*===========================================================================
 * DECLARATIONS
 *=========================================================================*/
static void lwipTimerCallback(void);
static struct netif* getNetif(cbIP_IPv4Address addr);
static cb_boolean handleWlanTargetCopyFromDataFrame(cb_uint8* buffer, cbWLANTARGET_dataFrame* frame, cb_uint32 size, cb_uint32 offsetInFrame);
static cb_boolean handleWlanTargetCopyToDataFrame(cbWLANTARGET_dataFrame* frame, cb_uint8* buffer, cb_uint32 size, cb_uint32 offsetInFrame);
static cbWLANTARGET_dataFrame* handleWlanTargetAllocDataFrame(cb_uint32 size);
static void handleWlanTargetFreeDataFrame(cbWLANTARGET_dataFrame* frame);
static cb_uint32 handleWlanTargetGetDataFrameSize(cbWLANTARGET_dataFrame* frame);
static cb_uint8 handleWlanTargetGetDataFrameTID(cbWLANTARGET_dataFrame* frame);

static const cbWLANTARGET_Callback _wlanTargetCallback = 
{
    handleWlanTargetCopyFromDataFrame,
    handleWlanTargetCopyToDataFrame,
    handleWlanTargetAllocDataFrame,
    handleWlanTargetFreeDataFrame,
    handleWlanTargetGetDataFrameSize,
    handleWlanTargetGetDataFrameTID
};


/*===========================================================================
 * DEFINITIONS
 *=========================================================================*/

/*===========================================================================
 * FUNCTIONS
 *=========================================================================*/

void cbIP_init(void)
{
    /* Startup lwIP */
    lwip_init();

    minar::Scheduler::postCallback(lwipTimerCallback).period(minar::milliseconds(LWIP_TMR_INTERVAL));
    cbWLANTARGET_registerCallbacks((cbWLANTARGET_Callback*)&_wlanTargetCallback);
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

    MBED_ASSERT(ip_addr != NULL);

    status = dns_gethostbyname(str, &address, (dns_found_callback)callback, arg);   // TODO: Unsafe callback as the cbIP_IPv4Address may differ from ip_addr_t.

    if (status == ERR_OK) {
        ip_addr->value = address.addr;
    }

    if (status == ERR_INPROGRESS) {
        return TRUE;
    }

    return FALSE;
}

void cbIP_setDefaultNetif(cbIP_IPv4Address addr)
{
    struct netif* netif = getNetif(addr);
    if (netif != NULL) {
        netif_set_default(netif);
    }
}

static struct netif* getNetif(cbIP_IPv4Address addr)
{
    for (struct netif* netif = netif_list; netif != NULL; netif = netif->next) {
        if (addr.value == netif->ip_addr.addr) {
            return netif;
        }
    }
    return NULL;
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
    core_util_critical_section_enter();
    return 0;
}

void sys_arch_unprotect(sys_prot_t pval)
{
    (void) pval;
    core_util_critical_section_exit();
}

/*===========================================================================
 * INTERNAL FUNCTIONS
 *=========================================================================*/

static void lwipTimerCallback()
{
    sys_check_timeouts();
}

cb_boolean handleWlanTargetCopyFromDataFrame(cb_uint8* buffer, cbWLANTARGET_dataFrame* frame, cb_uint32 size, cb_uint32 offsetInFrame)
{
    return cbIP_copyFromDataFrame(buffer, (cbIP_frame*)frame, size, offsetInFrame);
}

cb_boolean handleWlanTargetCopyToDataFrame(cbWLANTARGET_dataFrame* frame, cb_uint8* buffer, cb_uint32 size, cb_uint32 offsetInFrame)
{
    return cbIP_copyToDataFrame((cbIP_frame*)frame, buffer, size, offsetInFrame);
}

cbWLANTARGET_dataFrame* handleWlanTargetAllocDataFrame(cb_uint32 size)
{
    return (cbWLANTARGET_dataFrame*)cbIP_allocDataFrame(size);
}

void handleWlanTargetFreeDataFrame(cbWLANTARGET_dataFrame* frame)
{
    cbIP_freeDataFrame((cbIP_frame*)frame);
}

cb_uint32 handleWlanTargetGetDataFrameSize(cbWLANTARGET_dataFrame* frame)
{
    return cbIP_getDataFrameSize((cbIP_frame*)frame);
}

cb_uint8 handleWlanTargetGetDataFrameTID(cbWLANTARGET_dataFrame* frame)
{
    (void)frame;
    return cbWLAN_AC_BE;
}
