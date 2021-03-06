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

#ifndef _CB_IP_BUF_H_
#define _CB_IP_BUF_H_

#include "cb_comdefs.h"

#ifdef __cplusplus
extern "C" {
#endif

/*===========================================================================
 * DEFINES
 *=========================================================================*/

/*===========================================================================
 * TYPES
 *=========================================================================*/
typedef struct cbIP_frame cbIP_frame;

/*===========================================================================
 * FUNCTIONS
 *=========================================================================*/

/**
 * Copy data from frame data memory to buffer.
 *
 * @param buffer            The destination buffer.
 * @param frame             Source frame memory pointer (@ref cbIP_allocDataFrame).
 * @param size              Number of bytes to copy.
 * @param offsetInFrame     Offset into frame memory.
 * @return                  @ref TRUE if successful, otherwise @ref FALSE.
 */
cb_boolean cbIP_copyFromDataFrame(cb_uint8* buffer, cbIP_frame* frame, cb_uint32 size, cb_uint32 offsetInFrame);

/**
 * Copy data from buffer to frame data memory.
 *
 * @param frame             Destination frame memory pointer (@ref cbIP_allocDataFrame).
 * @param buffer            The source buffer.
 * @param size              Number of bytes to copy.
 * @param offsetInFrame     Offset into frame memory.
 * @return                  @ref TRUE if successful, otherwise @ref FALSE.
 */
cb_boolean cbIP_copyToDataFrame(cbIP_frame* frame, cb_uint8* buffer, cb_uint32 size, cb_uint32 offsetInFrame);

/**
 * Allocate memory in frame data memory.
 *
 * @param size              Number of bytes to allocate.
 * @return                  Pointer to the frame memory.
 * 
 * @ref cbIP_freeDataFrame
 */
cbIP_frame* cbIP_allocDataFrame(cb_uint32 size);

/**
* Allocate frame data from RAM memory.
*
* @param size              Number of bytes to allocate.
* @return                  Pointer to the frame memory.
*
* @ref cbIP_freeDataFrame
*/
cbIP_frame* cbIP_allocDataFrameFromRAM(cb_uint32 size);

/**
 * Destroy memory in frame data memory.
 *
 * @param frame             Pointer to the frame memory that should be destroyed.
 * @ref cbIP_allocDataFrame
 */
void cbIP_freeDataFrame(cbIP_frame* frame);

/**
 * Get the size of the data in the frame.
 *
 * @param frame             Pointer to the frame memory that should be destroyed.
 * @ref cbIP_allocDataFrame
 */
cb_uint32 cbIP_getDataFrameSize(cbIP_frame* frame);

cb_uint8* cbIP_getDataFramePayload(cbIP_frame* frame);

void cbIP_DataFrameAddRef(cbIP_frame* frame);
cb_uint8 cbIP_DataFrameDelRef(cbIP_frame* frame);


typedef struct cbIP_memStats {
    cb_uint32 available;
    cb_uint32 used;
    cb_uint32 maxUsed;
} cbIP_memStats;

typedef struct cbIP_protocolStats {
    cb_uint32 sent;
    cb_uint32 received;
    cb_uint32 dropped;
} cbIP_protocolStats;

#define cbIP_EXTRA_MEM_STATS 2

typedef struct cbIP_Stats {
    cbIP_memStats mem;
    cbIP_memStats extra[cbIP_EXTRA_MEM_STATS];

    cbIP_protocolStats link;
    cbIP_protocolStats ip;
    cbIP_protocolStats tcp;
    cbIP_protocolStats udp;
    cbIP_protocolStats icmp;
    cbIP_protocolStats arp;

    cbIP_memStats UDPPcb;
    cbIP_memStats TCPPcb;

} cbIP_Stats;

void cbIP_getBufStats(cbIP_Stats* ipStats);

cbIP_frame* cbIP_getNextFrame(cbIP_frame* frame);
cb_uint32 cbIP_getDataSegmentSize(cbIP_frame* frame);

typedef void (*data_free_f)(cbIP_frame* frame, void* arg0, void* arg1);
cbIP_frame* cbIP_allocRefFrame(cb_uint8* payload, cb_uint32 size, data_free_f free, void* arg0, void* arg1);
void cbIP_DataFrameChain(cbIP_frame* head, cbIP_frame* tail);
cbIP_frame* cbIP_DataFrameDechain(cbIP_frame* frame);
cbIP_frame* cbIP_DataFrameGather(cbIP_frame* frame);
#ifdef __cplusplus
}
#endif

#endif /* _CB_IP_BUF_H_ */

