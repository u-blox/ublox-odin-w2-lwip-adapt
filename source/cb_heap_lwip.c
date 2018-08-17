/*---------------------------------------------------------------------------
 * Copyright (c) 2014 connectBlue AB, Sweden.
 * Any reproduction without written permission is prohibited by law.
 *
 * Component: HEAP
 * File     : cb_heap_lwip.c
 *
 * Description: Heap implementation with static buffer sizes.
 *              The buffer sizes and total heap size is configured in 
 *              cb_rtsl_config.h
 *-------------------------------------------------------------------------*/
#define __CB_FILE__ "cb_heap_lwip.c"

#include <stdio.h>
#include <limits.h>
#include <string.h>
#include "cb_comdefs.h"
#include "cb_rtsl_config.h"
#include "cb_log.h"
#include "lwip/mem.h"

#ifdef cbHEAP_DEBUG
#include "cb_log.h"
#endif

#undef cbHEAP_STATISTICS // really???
#ifdef cbHEAP_STATISTICS
#include "lwip/memp.h";
#endif

/*===========================================================================
 * DEFINES
 *=========================================================================*/
#ifndef cbHEAP_DEBUG
#define cbHEAP_DBG_TAIL (0)
#else
#define cbHEAP_DBG_TAIL (4)
#define cbHEAP_LOGGED_MIN_SIZE 700
#define cbHEAP_NOF_HEADERS 300
#endif

#ifdef cbHEAP_STATISTICS
#define N_REAL_SIZE_ELEMENT 128
#endif
/*===========================================================================
 * TYPES
 *=========================================================================*/
typedef struct
{
    cb_uint32   nBytes; // Number of bytes allocated from data byte array
    cb_int8     data[cbHEAPSTATIC_SIZE];

} cbHEAP_StaticHeap;

typedef struct {

    cb_uint32   nBytes; // Number of bytes allocated from data byte array
    cb_uint32   nBytesAllocated;
    cb_uint32   data[cbHEAP_FAST_SIZE / 4];
} cbHEAP_Fast_Heap;

typedef struct cbHEAP_BufferHead 
{

#ifdef cbHEAP_DEBUG    
    cb_uint16                   check;
    cb_char                     *filename;
    cb_int16                    line;
    cb_int32                    size;
#endif
    cb_boolean                  free;
    cb_uint8                    sizeIndex;
    cb_uint8                    align[2];

    struct cbHEAP_BufferHead    *pNext; 
        
#ifdef cbHEAP_DEBUG    
    cb_uint16                   check2;
#endif

} cbHEAP_BufferHeader;

#ifdef cbHEAP_STATISTICS
typedef struct {
    cb_uint16 size;
    cb_uint8 count;
    cb_uint8 maxCount;
    cb_uint16* realSize;
    cb_boolean sorted;
    cb_uint8 realsizeIndex;
}mem_statistics;

struct memp_header {
    cb_uint32 poolnr;
};
#endif

/*===========================================================================
 * DECLARATIONS
 *=========================================================================*/
static void fast_init(void);
#ifdef cbHEAP_DEBUG
void *_cbHEAP_mallocStatic(cb_uint32 line, cb_char* filename, cb_uint32 size);
#else
void *cbHEAP_mallocStatic(cb_uint32 size);
#endif

#ifdef cbHEAP_STATISTICS
static void decStatistics(void* pbuf);
void incStatistics(cb_uint16 realsize, void* data);
#else 
#define decStatistics(x)
#define incStatistics(x, y)
#endif
/*===========================================================================
 * DEFINITIONS
 *=========================================================================*/

static cbHEAP_StaticHeap cbHEAPSTATIC_SECTION_CONFIG_INLINE heapStatic;
static const cb_uint16 cbHEAP_Fast_bufferSizeConfig[cbHEAP_FAST_N_BUFFER_SIZES] = cbHEAP_FAST_BUFFER_CONFIG;

static cbHEAP_Fast_Heap cbHEAP_FAST_SECTION_CONFIG_INLINE fheap;
static cbHEAP_BufferHeader* heapFastBuffers[cbHEAP_FAST_N_BUFFER_SIZES];
static cb_uint16 cbHEAP_Fast_bufferSize[cbHEAP_FAST_N_BUFFER_SIZES];

#ifdef cbHEAP_STATISTICS
static mem_statistics memstats[8];
const cb_uint8 memtab_offset = 15;
static cb_uint8 knownAlloc = 0;
static cb_uint8 knownFree = 0;
#define KNOWN_ALLOC_INC knownAlloc++
#define KNOWN_ALLOC_DEC knownAlloc--
#define KNOWN_FREE_INC knownFree++
#define KNOWN_FREE_DEC knownFree--
#else
#define KNOWN_ALLOC_INC
#define KNOWN_ALLOC_DEC
#define KNOWN_FREE_INC
#define KNOWN_FREE_DEC
#endif

/*===========================================================================
 * FUNCTIONS
 *=========================================================================*/
void cbHEAP_init(void)
{
#ifdef cbHEAP_STATISTICS
    heapStatic.nBytes = 0;
    memset(memstats, 0xff, ELEMENTS_OF(memstats) * sizeof(mem_statistics));
    for (int i = 0; i < ELEMENTS_OF(memstats); i++) {
        cb_uint16* pRealSize = cbHEAP_mallocStatic(N_REAL_SIZE_ELEMENT * sizeof(cb_uint16));
        memset(pRealSize, 0xff, N_REAL_SIZE_ELEMENT * sizeof(cb_uint16));
        memstats[i].realSize = pRealSize;
    }
#endif
    fast_init();
}

void *cbHEAP_malloc(cb_uint32 size)
{
    KNOWN_ALLOC_INC;
    void* data = mem_malloc(size);
    incStatistics((cb_uint16)size, data);
    if (data == NULL) {
        cbLOG_PRINT("out of memory %u\n", size);
        cb_ASSERT2(FALSE, size);
    }
    KNOWN_ALLOC_DEC;
    return data;
}

void cbHEAP_free(void* pBuf)
{
    if (pBuf != NULL) {
        KNOWN_FREE_INC;
        decStatistics(pBuf);
        mem_free(pBuf);
        KNOWN_FREE_DEC;
    }
}

#ifdef cbHEAP_DEBUG
void *_cbHEAP_mallocStatic(cb_uint32 line, cb_char* filename, cb_uint32 size)
#else
void *cbHEAP_mallocStatic(cb_uint32 size)
#endif
{
    cbHEAP_BufferHeader*    pBuffer;
    void*                   pData;
    cb_uint32               bufSize;

#ifdef cbHEAP_DEBUG
    cbLOG_PRINT("cbHEAP_mallocStatic(allocSize=%d, heapsizeLeft=%d, filename=%s, line=%d)\n", size, cbHEAPSTATIC_SIZE - heapStatic.nBytes, filename, line);
#endif

    bufSize = size + sizeof(cbHEAP_BufferHeader)+cbHEAP_DBG_TAIL;

    // Make 4 bytes alignment
    bufSize += bufSize % 4;

#ifdef cbHEAP_MALLOC_RETURN_NULL
    if ((cbHEAPSTATIC_SIZE - heapStatic.nBytes) < bufSize)
    {
        return NULL;
    }
#else
    cb_ASSERTC((cbHEAPSTATIC_SIZE - heapStatic.nBytes) >= bufSize);
#endif

    pBuffer = (cbHEAP_BufferHeader*)&(heapStatic.data[heapStatic.nBytes]);

    heapStatic.nBytes += bufSize;

    pBuffer->pNext = (cbHEAP_BufferHeader*)bufSize; // Force buffer size into next buffer pointer.
    pBuffer->free = FALSE;

    pData = (void*)((cb_uint32)pBuffer + sizeof(cbHEAP_BufferHeader));

    return pData;
}

void *cbHEAP_fast_malloc(cb_uint32 size)
{
    cb_boolean          found = FALSE;
    cbHEAP_BufferHeader *pBuffer = NULL;
    void                *pData = NULL;

    for (cb_uint8 i = 0; (i < cbHEAP_FAST_N_BUFFER_SIZES) && (found == FALSE); i++) {
        if (cbHEAP_Fast_bufferSize[i] >= (size + sizeof(cbHEAP_BufferHeader) + cbHEAP_DBG_TAIL)) {
            if (heapFastBuffers[i] != NULL) {
                pBuffer = heapFastBuffers[i];
                heapFastBuffers[i] = pBuffer->pNext;

                cb_ASSERT(pBuffer->free == TRUE);
                cb_ASSERT(pBuffer->sizeIndex == i);

                pBuffer->pNext = NULL;
                pBuffer->free = FALSE;
                found = TRUE;
            } else if ((cb_uint32)(cbHEAP_FAST_SIZE - fheap.nBytes) >= (cb_uint32)(cbHEAP_Fast_bufferSize[i] + 3)) {
                pBuffer = (cbHEAP_BufferHeader*)&(fheap.data[(fheap.nBytes + 3) / 4]);

                fheap.nBytes += cbHEAP_Fast_bufferSize[i];

                pBuffer->pNext = NULL;
                pBuffer->free = FALSE;
                pBuffer->sizeIndex = i;

                found = TRUE;
            }
        }
    }

    if (found == TRUE) {
        pData = (void*)((cb_uint32)pBuffer + sizeof(cbHEAP_BufferHeader));
        fheap.nBytesAllocated += cbHEAP_Fast_bufferSize[pBuffer->sizeIndex];
    } else {
        cb_ASSERT2(FALSE, size);
        return NULL;
    }
    return pData;
}

void cbHEAP_fast_free(void* pBuf)
{
    cbHEAP_BufferHeader*    pBuffer = (cbHEAP_BufferHeader *)((cb_uint32)pBuf - sizeof(cbHEAP_BufferHeader));
    if (pBuf == NULL) {
        return; // Nothing to do.
    }

    cb_ASSERT((cb_uint32*)pBuf >= fheap.data);
    cb_ASSERT((cb_uint32*)pBuf < (fheap.data + cbHEAP_FAST_SIZE / 4));
    cb_ASSERT(pBuffer->free == FALSE);
    cb_ASSERT(pBuffer->pNext == NULL);
    cb_ASSERT(pBuffer->sizeIndex < cbHEAP_FAST_N_BUFFER_SIZES);

    fheap.nBytesAllocated -= cbHEAP_Fast_bufferSize[pBuffer->sizeIndex];

    pBuffer->free = TRUE;

    pBuffer->pNext = heapFastBuffers[pBuffer->sizeIndex];
    heapFastBuffers[pBuffer->sizeIndex] = pBuffer;
}

cb_uint32 cbHEAP_getAllocatedHeap(void)
{
    return fheap.nBytesAllocated;
}

void *cbHEAP_calloc(cb_uint32 count, cb_uint32 size)
{
    void* pM = cbHEAP_fast_malloc(count * size);
    if (pM != NULL) {
        memset(pM, 0, count * size);
    }
    return pM;
}

/************************************************************************/
/*                                                                      */
/************************************************************************/
static void fast_init(void)
{
    cb_uint32 i;

    fheap.nBytes = 0;
    heapStatic.nBytes = 0;
    fheap.nBytesAllocated = 0;

    for (i = 0; i < cbHEAP_FAST_N_BUFFER_SIZES; i++) {
        cbHEAP_Fast_bufferSize[i] = (cb_uint16)(cbHEAP_Fast_bufferSizeConfig[i] + sizeof(cbHEAP_BufferHeader)+cbHEAP_DBG_TAIL);
    }

    for (i = 0; i < cbHEAP_FAST_N_BUFFER_SIZES; i++) {
        cb_ASSERT((cbHEAP_Fast_bufferSize[i] % 4) == 0);

        heapFastBuffers[i] = NULL;
    }
}

#ifdef cbHEAP_STATISTICS
void quickSort(cb_uint16 a[], cb_uint32 l, cb_uint32 r);
cb_uint32 getHeapAllocation(cb_uint32 bufferIndex, cb_uint32* pBuffer, cb_uint32 maxSize)
{
    if (bufferIndex >= ELEMENTS_OF(memstats)) {
        return 0;
    }
    cb_uint32 i = 0;
    cb_uint16* pRealSize = memstats[bufferIndex].realSize;
    while (i < N_REAL_SIZE_ELEMENT &&  pRealSize[0]!= cb_UINT16_MAX && i < maxSize) {    
        pBuffer[i] = pRealSize[i];
        i++;
    }
    if (i > 0 && memstats[bufferIndex].sorted == FALSE) {
        memstats[bufferIndex].sorted = TRUE;
        quickSort(pRealSize, 0, i - 1);
        cb_uint32 middle = (i - 1) / 2;
        if (middle > 0 && ((i - 1) > 1))
        {
            cb_uint32 mIndexHigh = middle;
            cb_uint32 mIndexLow = middle;
            cb_uint16* buffer = pRealSize;
            while (buffer[mIndexHigh] == buffer[mIndexHigh + 1] && mIndexHigh < (i-1)) {
                mIndexHigh++;
            }
            while (buffer[mIndexLow] == buffer[mIndexLow - 1] && mIndexLow > 0) {
                mIndexLow--;
            }
            if (mIndexHigh > (i - (mIndexLow + 1))) {
                middle = mIndexLow;
            }
            cbLOG_PRINT("Buffer Split: %u[%u]\n",middle, buffer[middle]);
        }
    }

    return i;
}

cb_int16 getpBufIndex(void* pBuf)
{
    struct memp_header *hmem;
    /* get the original struct memp_malloc_helper */
    hmem = (struct memp_header*)(void*)((u8_t*)pBuf - LWIP_MEM_ALIGN_SIZE(sizeof(cb_uint32)));

    cb_uint8 index = (cb_uint8)(hmem->poolnr & 0xff);
    return index - memtab_offset;
}

void decStatistics(void* pbuf)
{
    if (pbuf == NULL) {
        return;
    }
    cb_int16 index = getpBufIndex(pbuf);
    if (index >= 0) {
        memstats[index].sorted = FALSE;
        cb_uint16 size = memp_sizes[index + memtab_offset];

        if (memstats[index].size != cb_UINT16_MAX && memstats[index].size == size) {
            memstats[index].count--;
        }
        else if (memstats[index].size == cb_UINT16_MAX) {
            cb_ASSERT(FALSE);
        }
    }
}
void incStatistics(cb_uint16 realsize, void* data)
{
    cb_int16 index = getpBufIndex(data);
    if (index >= 0) {
        memstats[index].sorted = FALSE;
        cb_uint16 size = memp_sizes[index + memtab_offset];
        if (memstats[index].size != cb_UINT16_MAX && memstats[index].size == size) {
            memstats[index].count++;
            if (memstats[index].count > memstats[index].maxCount) {
                memstats[index].maxCount = memstats[index].count;
            }
            if (memstats[index].realsizeIndex < N_REAL_SIZE_ELEMENT)
            {
                cb_uint16* pRealSize = memstats[index].realSize;
                pRealSize[memstats[index].realsizeIndex++] = realsize;
            }
        }
        else if (memstats[index].size == cb_UINT16_MAX) {
            memstats[index].size = size;
            memstats[index].count = 1;
            memstats[index].maxCount = 1;
            memstats[index].realSize[0] = realsize;
            memstats[index].realsizeIndex = 1;
        }
    }
}
#endif /* cbHEAP_STATISTICS */

#ifdef SKUNK
void testSort()
{
    int a[] = { 7, 12, 1, -2, 0, 15, 4, 11, 9 };
    int i;
    quickSort(a, 0, 8);
    for (i = 0; i < 9; ++i)
        cbLOG_PRINT("%d,",a[i]);
    cbLOG_PRINT("\n\nSorted array is:  ");
    for (i = 0; i < 9; ++i)
        cbLOG_PRINT(" %d ", a[i]);
}

void quickSort(cb_uint16 a[], cb_uint32 l, cb_uint32 r)
{
    cb_uint32 j;
    if (l < r) {
        // divide and conquer
        j = partition(a, l, r);
        quickSort(a, l, j - 1);
        quickSort(a, j + 1, r);
    }
}

int partition(cb_uint16 a[], cb_uint32 l, cb_uint32 r)
{
    cb_uint32 pivot, i, j, t;
    pivot = a[l];
    i = l; j = r + 1;

    while (1) {
        do ++i; while (a[i] <= pivot && i <= r);
        do --j; while (a[j] > pivot);
        if (i >= j) break;
        t = a[i]; a[i] = a[j]; a[j] = t;
    }
    t = a[l]; a[l] = a[j]; a[j] = t;
    return j;
}
#endif
