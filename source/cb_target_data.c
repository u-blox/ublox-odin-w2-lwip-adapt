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

/**
 * @file cb_target.c Handles the lowest layer of communication to the target 
 * above the SPI/SDIO bus.
 * @ingroup target
 */

#define __CB_FILE__ "target_data"

#include "cb_target_data.h"
#include "cb_types.h"
#include "cb_wlan_types.h"

#include <stdlib.h>
#include <string.h>

#include "cb_ip_buf.h"


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

cb_boolean cbTARGET_copyFromDataFrame(cbTARGET_Handle *hTarget, cb_uint8* buffer, cbTARGET_dataFrame* frame, cb_uint32 size, cb_uint32 offsetInFrame)
{
    (void)hTarget;
    return cbIP_copyFromDataFrame(buffer, (cbIP_frame*)frame, size, offsetInFrame);
}

cb_boolean cbTARGET_copyToDataFrame(cbTARGET_Handle *hTarget, cbTARGET_dataFrame* frame, cb_uint8* buffer, cb_uint32 size, cb_uint32 offsetInFrame)
{
    (void)hTarget;
    return cbIP_copyToDataFrame((cbIP_frame*)frame, buffer, size, offsetInFrame);
}

cbTARGET_dataFrame* cbTARGET_allocDataFrame(cbTARGET_Handle *hTarget, cb_uint32 size)
{
    (void)hTarget;
    return (cbTARGET_dataFrame*)cbIP_allocDataFrame(size);
}

void cbTARGET_freeDataFrame(cbTARGET_Handle *hTarget, cbTARGET_dataFrame* frame)
{
    (void)hTarget;
    cbIP_freeDataFrame((cbIP_frame*)frame);
}

cb_uint32 cbTARGET_getDataFrameSize(cbTARGET_Handle *hTarget, cbTARGET_dataFrame* frame)
{
    (void)hTarget;
    return cbIP_getDataFrameSize((cbIP_frame*)frame);
}

cb_uint8 cbTARGET_getDataFrameTID(cbTARGET_Handle *hTarget, cbTARGET_dataFrame* frame)
{
    (void)hTarget;
    (void)frame;
    return cbWLAN_AC_BE;
}


/*===========================================================================
 * INTERNAL FUNCTIONS
 *=========================================================================*/

/*---------------------------------------------------------------------------
 * 
 *-------------------------------------------------------------------------*/
