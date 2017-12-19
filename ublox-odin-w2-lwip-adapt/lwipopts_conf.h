/* 
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

#ifndef __LWIPOPTS_CONF_H__
#define __LWIPOPTS_CONF_H__

/* Override LWIP options here */
#define  LWIP_SUPPORT_CUSTOM_PBUF 1

#undef MEM_SIZE
#define MEM_SIZE                        (1024 * 24)

#undef MEMP_SEPARATE_POOLS
#define MEMP_SEPARATE_POOLS             1

#undef MEMP_NUM_TCP_SEG
#define MEMP_NUM_TCP_SEG                150//(30 * 3)    // should be at least TCP_SND_QUEUELEN (24) for each tcp socket (2 + any service).

#undef PBUF_POOL_SIZE
#define PBUF_POOL_SIZE                  119

#endif // __LWIPOPTS_CONF_H__

