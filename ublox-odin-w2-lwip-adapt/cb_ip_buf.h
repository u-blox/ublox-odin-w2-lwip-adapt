/*---------------------------------------------------------------------------
 * Copyright (c) 2014 connectBlue AB, Sweden.
 * Any reproduction without written permission is prohibited by law.
 *
 * Component: cb_ip
 * File     : cb_ip_buf.h
 *
 * Description:
 *-------------------------------------------------------------------------*/
#ifndef _CB_IP_BUF_H_
#define _CB_IP_BUF_H_

#include "cb_comdefs.h"

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


#endif /* _CB_IP_BUF_H_ */
