/*---------------------------------------------------------------------------
 * Copyright (c) 2008 connectBlue AB, Sweden.
 * Any reproduction without written permission is prohibited by law.
 *
 * Component   : Wlan driver
 * File        : cb_target.c
 *
 * Description : WLAN chipset representation
 *-------------------------------------------------------------------------*/

/**
 * @file cb_target.c Handles the lowest layer of communication to the target 
 * above the SPI bus.
 * @ingroup target
 */

#define __CB_FILE__ "target_data"

#include "cb_target_data.h"
//#include "cb_target_internal.h"
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
    return cbIP_copyFromDataFrame(buffer, (cbIP_frame*)frame, size, offsetInFrame);
}

cb_boolean cbTARGET_copyToDataFrame(cbTARGET_Handle *hTarget, cbTARGET_dataFrame* frame, cb_uint8* buffer, cb_uint32 size, cb_uint32 offsetInFrame)
{
    return cbIP_copyToDataFrame((cbIP_frame*)frame, buffer, size, offsetInFrame);
}

cbTARGET_dataFrame* cbTARGET_allocDataFrame(cbTARGET_Handle *hTarget, cb_uint32 size)
{
    return (cbTARGET_dataFrame*)cbIP_allocDataFrame(size);
}

void cbTARGET_freeDataFrame(cbTARGET_Handle *hTarget, cbTARGET_dataFrame* frame)
{
    cbIP_freeDataFrame((cbIP_frame*)frame);
}

cb_uint32 cbTARGET_getDataFrameSize(cbTARGET_Handle *hTarget, cbTARGET_dataFrame* frame)
{
    //return cbIP_getDataFrameSize((cbIP_frame*)frame);
    return FALSE;
}

cb_uint8 cbTARGET_getDataFrameTID(cbTARGET_Handle *hTarget, cbTARGET_dataFrame* frame)
{
    return cbWLAN_AC_BE;
}


/*===========================================================================
 * INTERNAL FUNCTIONS
 *=========================================================================*/

/*---------------------------------------------------------------------------
 * 
 *-------------------------------------------------------------------------*/
