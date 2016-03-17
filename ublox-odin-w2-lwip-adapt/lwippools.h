

LWIP_MALLOC_MEMPOOL_START
LWIP_MALLOC_MEMPOOL(20, 32)
LWIP_MALLOC_MEMPOOL(10, 192)
LWIP_MALLOC_MEMPOOL(40, 632)        // TCP_MSS + PBUF_LINK_HLEN + PBUF_IP_HLEN + PBUF_TRANSPORT_HLEN + SIZEOF_STRUCT_PBUF = 536 + 14 + ETH_PAD_SIZE (0) + 40 + 20 + 16 = 626 + alignment => 632
LWIP_MALLOC_MEMPOOL(1, 1540)       // Ethernet II max frame size (including crc). Since we use pbuf_pool, this should hardly be needed.. 1518 + 16 + alignment => 1540
LWIP_MALLOC_MEMPOOL_END

