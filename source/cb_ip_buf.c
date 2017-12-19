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

#define __CB_FILE__ "cbIP_BUF"

#include "cb_ip_buf.h"

#include "lwip/pbuf.h"
#include "string.h"
#include "lwip/stats.h"

/*===========================================================================
 * DEFINES
 *=========================================================================*/

/*===========================================================================
 * TYPES
 *=========================================================================*/

/*===========================================================================
 * DECLARATIONS
 *=========================================================================*/

/*===========================================================================
 * DEFINITIONS
 *=========================================================================*/

/*===========================================================================
 * FUNCTIONS
 *=========================================================================*/

cb_boolean cbIP_copyFromDataFrame(cb_uint8* buffer, cbIP_frame* frame, cb_uint32 size, cb_uint32 offsetInFrame)
{
    struct pbuf* pbuf = (struct pbuf*)frame;
    cb_uint32 pbufOffset = 0;
    cb_uint32 copySize;
    cb_uint32 bytesCopied = 0;

    cb_ASSERT(frame != NULL);
    cb_ASSERT(buffer != NULL);

    while (pbuf != NULL) {
        if ((pbufOffset + pbuf->len) >= offsetInFrame) {
            copySize = cb_MIN(size, pbuf->len - (offsetInFrame - pbufOffset));
            memcpy(buffer, (cb_uint8 *)pbuf->payload + (offsetInFrame - pbufOffset), copySize);
            buffer += copySize;
            bytesCopied += copySize;
            pbuf = pbuf->next;
            break;
        }
        pbufOffset += pbuf->len;
        pbuf = pbuf->next;
    }

    while (pbuf != NULL && bytesCopied < size) {
        copySize = cb_MIN(pbuf->len, size - bytesCopied);
        memcpy(buffer, pbuf->payload, copySize);
        buffer += copySize;
        bytesCopied += copySize;
        pbuf = pbuf->next;
    }

    cb_ASSERT(bytesCopied <= size);

    return (bytesCopied == size);
}


cb_boolean cbIP_copyToDataFrame(cbIP_frame* frame, cb_uint8* buffer, cb_uint32 size, cb_uint32 offsetInFrame)
{
    struct pbuf* pbuf = (struct pbuf*)frame;
    cb_uint32 pbufOffset = 0;
    cb_uint32 copySize;
    cb_uint32 bytesCopied = 0;

    cb_ASSERT(frame != NULL);
    cb_ASSERT(buffer != NULL);

    while (pbuf != NULL) {
        if ((pbufOffset + pbuf->len) >= offsetInFrame) {
            copySize = cb_MIN(size, pbuf->len - (offsetInFrame - pbufOffset));
            memcpy((cb_uint8 *)pbuf->payload + (offsetInFrame - pbufOffset), buffer, copySize);
            buffer += copySize;
            bytesCopied += copySize;
            pbuf = pbuf->next;
            break;
        }
        pbufOffset += pbuf->len;
        pbuf = pbuf->next;
    }

    while (pbuf != NULL && bytesCopied < size) {
        copySize = cb_MIN(pbuf->len, size - bytesCopied);
        memcpy(pbuf->payload, buffer, copySize);
        buffer += copySize;
        bytesCopied += copySize;
        pbuf = pbuf->next;
    }

    cb_ASSERT(bytesCopied <= size);

    return (bytesCopied == size);
}

cbIP_frame* cbIP_allocDataFrame(cb_uint32 size)
{
    struct pbuf* pbuf;
    pbuf = pbuf_alloc(PBUF_RAW, (u16_t)size, PBUF_POOL);
    return (cbIP_frame*)pbuf;
}

cbIP_frame* cbIP_allocDataFrameFromRAM(cb_uint32 size)
{
    struct pbuf* pbuf;
    pbuf = pbuf_alloc(PBUF_RAW, (u16_t)size, PBUF_RAM);
    return (cbIP_frame*)pbuf;
}

struct cbIP_pbuf_custom {
    struct pbuf_custom pbuf_custom;
    data_free_f free;
    void *arg0;
    void *arg1;
};

static void pbuf_free_custom(struct pbuf *pbuf)
{
    cb_ASSERT(pbuf != NULL);

    struct cbIP_pbuf_custom *p = (struct cbIP_pbuf_custom *)pbuf;
    p->free((cbIP_frame*)p, p->arg0, p->arg1);
    cbHEAP_free(p);
    p = NULL;
}

cbIP_frame* cbIP_allocRefFrame(cb_uint8* payload, cb_uint32 size, data_free_f free, void* arg0, void* arg1)
{
    struct pbuf* pbuf;

    struct cbIP_pbuf_custom *p = (struct cbIP_pbuf_custom*)cbHEAP_malloc(sizeof(struct cbIP_pbuf_custom));
    p->pbuf_custom.custom_free_function = pbuf_free_custom;
    p->arg0 = arg0;
    p->arg1 = arg1;
    p->free = free;
    pbuf = pbuf_alloced_custom(PBUF_RAW, size, PBUF_REF, &p->pbuf_custom, payload, size);

    return (cbIP_frame*)pbuf;
}

void cbIP_DataFrameChain(cbIP_frame* head, cbIP_frame* tail)
{
    pbuf_chain((struct pbuf*)head, (struct pbuf*)tail);
}

cbIP_frame* cbIP_DataFrameDechain(cbIP_frame* frame)
{
    return (cbIP_frame*)pbuf_dechain((struct pbuf*)frame);
}

void cbIP_freeDataFrame(cbIP_frame* frame)
{
    struct pbuf* pbuf = (struct pbuf*)frame;
    pbuf_free(pbuf);
}

cb_uint32 cbIP_getDataFrameSize(cbIP_frame* frame)
{
    struct pbuf* pbuf = (struct pbuf*)frame;

    if (frame == NULL) {
        return 0;
    }

    return pbuf->tot_len;
}
cb_uint32 cbIP_getDataSegmentSize(cbIP_frame* frame)
{
    struct pbuf* pbuf = (struct pbuf*)frame;

    if (frame == NULL) {
        return 0;
    }

    return pbuf->len;
}
cbIP_frame* cbIP_getNextFrame(cbIP_frame* frame)
{
    if (frame == NULL) {
        return NULL;
    }
    return (cbIP_frame*)((struct pbuf*)frame)->next;
}
cb_uint8* cbIP_getDataFramePayload(cbIP_frame* frame)
{
    struct pbuf* pbuf = (struct pbuf*)frame;

    if (frame == NULL) {
        return NULL;
    }
    //cb_ASSERT(pbuf->next == NULL);          TODO("Can't handle chained pbufs here");
    //cb_ASSERT(pbuf->tot_len == pbuf->len);  TODO("Can't handle chained pbufs here");

    return (cb_uint8*)pbuf->payload;
}

void cbIP_DataFrameAddRef(cbIP_frame* frame)
{
    cb_ASSERT(frame != NULL);
    pbuf_ref((struct pbuf*)frame);
}

cbIP_frame* cbIP_DataFrameGather(cbIP_frame* frame)
{
    return (cbIP_frame*)pbuf_coalesce((struct pbuf*)frame, PBUF_RAW);
}

cb_uint8 cbIP_DataFrameDelRef(cbIP_frame* frame)
{
    cb_ASSERT(frame != NULL);
    return pbuf_free((struct pbuf*)frame);
}


void cbIP_getBufStats(cbIP_Stats* ipStats)
{
    cb_ASSERT(ipStats != NULL);

    memset(ipStats, 0, sizeof(cbIP_Stats));


#if MEM_USE_POOLS
    // TODO: Summarize from custom pools (lwippools.h).
    ipStats->mem.used = 0;
    ipStats->mem.available = 0;
    ipStats->mem.maxUsed = 0;
#else 
    ipStats->mem.used = lwip_stats.mem.used;
    ipStats->mem.available = lwip_stats.mem.avail;
    ipStats->mem.maxUsed = lwip_stats.mem.max;
#endif


/*
Current order of memp:
    RAW_PCB = 0
    UDP_PCB = 1
    TCP_PCB = 2
    TCP_PCB_LISTEN = 3  
    TCP_SEG = 4
    REASSDATA = 5
    FRAG_PBUF = 6
    ARP_QUEUE = 7
    SYS_TIMEOUT = 8
    PBUF = 9
    PBUF_POOL = 10
*/

    ipStats->extra[0].used = lwip_stats.memp[MEMP_PBUF].used;
    ipStats->extra[0].available = lwip_stats.memp[MEMP_PBUF].avail;
    ipStats->extra[0].maxUsed = lwip_stats.memp[MEMP_PBUF].max;
    
    ipStats->extra[1].used = lwip_stats.memp[MEMP_PBUF_POOL].used;
    ipStats->extra[1].available = lwip_stats.memp[MEMP_PBUF_POOL].avail;
    ipStats->extra[1].maxUsed = lwip_stats.memp[MEMP_PBUF_POOL].max;

    ipStats->link.received = lwip_stats.link.recv;
    ipStats->link.sent = lwip_stats.link.xmit;
    ipStats->link.dropped = lwip_stats.link.drop;

    ipStats->ip.received = lwip_stats.ip.recv;
    ipStats->ip.sent = lwip_stats.ip.xmit;
    ipStats->ip.dropped = lwip_stats.ip.drop;

    ipStats->tcp.received = lwip_stats.tcp.recv;
    ipStats->tcp.sent = lwip_stats.tcp.xmit;
    ipStats->tcp.dropped = lwip_stats.tcp.drop;

    ipStats->udp.received = lwip_stats.udp.recv;
    ipStats->udp.sent = lwip_stats.udp.xmit;
    ipStats->udp.dropped = lwip_stats.udp.drop;

    ipStats->icmp.received = lwip_stats.icmp.recv;
    ipStats->icmp.sent = lwip_stats.icmp.xmit;
    ipStats->icmp.dropped = lwip_stats.icmp.drop;

    ipStats->arp.received = lwip_stats.etharp.recv;
    ipStats->arp.sent = lwip_stats.etharp.xmit;
    ipStats->arp.dropped = lwip_stats.etharp.drop;

    ipStats->TCPPcb.available = lwip_stats.memp[MEMP_TCP_PCB].avail;
    ipStats->TCPPcb.used = lwip_stats.memp[MEMP_TCP_PCB].used;
    ipStats->TCPPcb.maxUsed = lwip_stats.memp[MEMP_TCP_PCB].max;

    ipStats->UDPPcb.available = lwip_stats.memp[MEMP_UDP_PCB].avail;
    ipStats->UDPPcb.used = lwip_stats.memp[MEMP_UDP_PCB].used;
    ipStats->UDPPcb.maxUsed = lwip_stats.memp[MEMP_UDP_PCB].max;
}

/*===========================================================================
 * INTERNAL FUNCTIONS
 *=========================================================================*/


