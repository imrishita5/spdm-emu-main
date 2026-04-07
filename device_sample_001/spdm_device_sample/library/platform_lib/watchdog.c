/**
 *  Copyright Notice:
 *  Copyright 2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/debuglib.h"

/**
 * If no heartbeat arrives in seconds, the watchdog timeout event
 * should terminate the session.
 *
 * @param  session_id     Indicate the SPDM session ID.
 * @param  seconds        heartbeat period, in seconds.
 *
 **/
bool libspdm_start_watchdog(uint32_t session_id, uint16_t seconds)
{
    /* Stub: In bare-metal firmware, watchdog would use hardware timer/WDT.
       For this responder mock, we skip watchdog functionality. */
    (void)session_id;
    (void)seconds;
    return true;
}

/**
 * stop watchdog.
 *
 * @param  session_id     Indicate the SPDM session ID.
 *
 **/
bool libspdm_stop_watchdog(uint32_t session_id)
{
    /* Stub: Stop the watchdog timer. */
    (void)session_id;
    return true;
}

/**
 * Reset the watchdog in heartbeat response.
 *
 * @param  session_id     Indicate the SPDM session ID.
 *
 **/
bool libspdm_reset_watchdog(uint32_t session_id)
{
    /* Stub: Reset the watchdog timer. */
    (void)session_id;
    return true;
}
