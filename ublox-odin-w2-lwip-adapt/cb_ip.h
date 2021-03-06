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

#ifndef _CB_IP_H_
#define _CB_IP_H_

#include "cb_comdefs.h"
#include "lwip/def.h"
#include "arch/sys_arch.h"

#ifdef __cplusplus
extern "C" {
#endif

/*===========================================================================
 * DEFINES
 *=========================================================================*/

// Fill an IPv4 address for little endian system.
#define cbIP_SET_IP4_ADDR(address, a, b, c, d) \
    (address).value = ((cb_uint32)((d) & 0xff) << 24) | \
                      ((cb_uint32)((c) & 0xff) << 16) | \
                      ((cb_uint32)((b) & 0xff) << 8) | \
                       (cb_uint32)((a) & 0xff)

/*===========================================================================
 * TYPES
 *=========================================================================*/
typedef cb_uint8 cbIP_MACAddress[6];

typedef struct cbIP_IPv4Address {
    cb_uint32 value;
} cbIP_IPv4Address;

typedef struct cbIP_IPv4Settings {
    cbIP_IPv4Address address;
    cbIP_IPv4Address netmask;
    cbIP_IPv4Address gateway;
    cbIP_IPv4Address dns0;
    cbIP_IPv4Address dns1;
} cbIP_IPv4Settings;

typedef struct cbIP_IPv6Address {
    cb_uint32 value[4];
} cbIP_IPv6Address;

typedef struct cbIP_IPv6Settings {
    cbIP_IPv6Address linklocal;
} cbIP_IPv6Settings;

typedef union {
    cbIP_IPv4Address ip4;
    cbIP_IPv6Address ip6;
} cbIP_IPxAddress;

typedef enum {
    cbIPv4,
    cbIPv6,
} cbIP_Version;

typedef struct
{
    cbIP_IPxAddress addr;
    cbIP_Version ipVersion;
} cbIP_IPAddress;

typedef enum {
    cbIP_DHCP_SERVER_DISABLE,
    cbIP_DHCP_SERVER_ENABLE,
} cbIP_DHCP_Server;

typedef struct cbIP_interfaceSettings
{
    cb_uint16 MTU;
    cbIP_MACAddress macAddress;
    cbIP_DHCP_Server dhcpServerState;
} cbIP_interfaceSettings;

typedef enum {
    cbIP_NETWORK_DOWN,
    cbIP_NETWORK_UP,
    cbIP_NETWORK_ACTIVITY
} cbIP_Status;

typedef void (*cbIP_statusIndication)(
    cbIP_Status status, 
    void* callbackArg, 
    cbIP_IPv4Settings const * const ipV4settings, 
    cbIP_IPv6Settings const * const ipV6settings);

typedef void(*cbIP_addrResolvedCallback)(
    const char *name, 
    cbIP_IPv4Address *ipaddr, 
    void *hClient);

/*===========================================================================
 * FUNCTIONS
 *=========================================================================*/

/**
 * Initialize the IP stack.
 *
 */
void cbIP_init(void);

void cbIP_initWlanInterfaceStatic(
    char* hostname, 
    const cbIP_IPv4Settings * const IPv4Settings, 
    const cbIP_IPv6Settings * const IPv6Settings, 
    cbIP_interfaceSettings const * const ifConfig, 
    cbIP_statusIndication callback, 
    void* callbackArg);

void cbIP_initWlanInterfaceDHCP(
    char* hostname, 
    const cbIP_IPv6Settings * const IPv6Settings, 
    cbIP_interfaceSettings const * const ifConfig, 
    cbIP_statusIndication callback, 
    void* callbackArg);

void cbIP_initEthInterfaceStatic(
    char* hostname, 
    const cbIP_IPv4Settings * const IPv4Settings, 
    cbIP_interfaceSettings const * const ifConfig, 
    cbIP_statusIndication callback);

void cbIP_initEthInterfaceDHCP(
    char* hostname, 
    cbIP_interfaceSettings const * const ifConfig, 
    cbIP_statusIndication callback);

void cbIP_initPanInterfaceStatic(
    char* hostname,
    const cbIP_IPv4Settings * const IPv4Settings,
    const cbIP_IPv6Settings * const IPv6Settings,
    cbIP_interfaceSettings const * const ifConfig,
    cbIP_statusIndication callback,
    void* callbackArg);

void cbIP_initPanInterfaceDHCP(
    char* hostname,
    const cbIP_IPv6Settings * const IPv6Settings,
    cbIP_interfaceSettings const * const ifConfig,
    cbIP_statusIndication callback,
    void* callbackArg);

void cbIP_removeWlanInterface(void);

cb_boolean cbIP_UTIL_aton(const cb_char *str, cbIP_IPv4Address *addr);

cb_char* cbIP_UTIL_ntoa(const cbIP_IPv4Address *addr, char *buf, int buflen);

cb_boolean cbIP_UTIL_ip6addr_aton(const cb_char *str, cbIP_IPv6Address *addr);

cb_char* cbIP_UTIL_ip6addr_ntoa(const cbIP_IPv6Address *addr, char *buf, int buflen);

cb_boolean cbIP_gethostbyname(const cb_char *str, cbIP_IPv4Address* ip_addr, cbIP_addrResolvedCallback callback, void* arg);

void cbIP_setDefaultNetif(cbIP_IPv4Address addr);

u32_t sys_now();

#ifdef __cplusplus
}
#endif

#endif /* _CB_IP_H_ */
