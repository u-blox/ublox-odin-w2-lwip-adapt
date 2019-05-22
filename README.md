# ublox-odin-w2-lwip-adapt
This module contains an adaptation layer between the [lwIP stack](http://savannah.nongnu.org/projects/lwip/) and u-blox ODIN-W2 Wi-Fi/Ethernet/Bluetooth PAN network interfaces. lwipopts_conf.h is located here. If other lwIP settings or layer 2 switching is needed this module can be forked or completely replaced.

The memory allocations from the ODIN-W2 driver is using either lwIP memory allocations(cbIP_allocDataFrame and cbIP_allocDataFrameFromRAM) or the heap functions cbHEAP_malloc, cbHEAP_mallocStatic, cbHEAP_fast_malloc and cbHEAP_calloc.  

The default configuration is that the cbHEAP_malloc is using lwIP memory and placed in normal RAM while the cbHEAP_mallocStatic, cbHEAP_fast_malloc and cbHEAP_calloc are placed in CCM. However this can be re-arranged by modifiying the linker odin-w2.ld script but the normal heap i.e. cbHEAP_malloc must be DMA:able so it must reside in the RAM area. The static and fast heap have no such requirement and can be placed in either RAM or CCM. It's also possible to just map the heap allocations to use the global mbed heap via mbed_ualloc.  

If needed the static heap can be measured and fine-tuned by examine the heapStatic.nBytes parameter in cb_heap_lwip.c after a scenario has been run. The static heap memory is mostly used when initializing the Bluetooth stack.  

The memory sizes in lwipopts_conf.h is an example on a configuration and should be adapted to a specific use case. The same goes for the pool sizes in lwippools.h.  
