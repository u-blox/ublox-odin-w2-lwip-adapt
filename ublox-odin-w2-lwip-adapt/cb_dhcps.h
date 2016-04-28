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

#ifndef _CB_DHCPS_H_
#define _CB_DHCPS_H_

#include "cb_comdefs.h"
#include "cb_ip.h"

/*===========================================================================
 * DEFINES
 *=========================================================================*/

/* Interval in seconds when to call cbDHCPS_slowTimer() */
#define cbDHCP_SLOW_TIMER_INTERVAL      10


/*===========================================================================
 * TYPES
 *=========================================================================*/

/*===========================================================================
 * FUNCTIONS
 *=========================================================================*/

/*---------------------------------------------------------------------------
 * Init and start UDP listener on port 67.
 *-------------------------------------------------------------------------*/
void cbDHCPS_init(cb_char* ifname, cbIP_IPv4Address startAddress);

void cbDHCPS_destroy();


/*---------------------------------------------------------------------------
 * To be called every cbDHCP_SLOW_TIMER_INTERVAL. Manages lease time.
 *-------------------------------------------------------------------------*/
void cbDHCPS_slowTimer(void);

#endif /* _CB_DHCPS_H_ */
