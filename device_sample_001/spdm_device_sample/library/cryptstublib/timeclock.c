/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/debuglib.h"

#if defined(__GNUC__) && !defined(_WIN32)
typedef size_t time_t;
#elif defined(__clang__)
typedef size_t time_t;
#endif

/* Stub for clock_gettime needed by mbedtls when linking without libc (-nostdlib). */
#if defined(__GNUC__) && !defined(_WIN32)
typedef long clockid_t;
typedef long time_s_t;
struct timespec_stub {
    time_s_t tv_sec;
    long     tv_nsec;
};
int clock_gettime(clockid_t clk_id, struct timespec_stub *tp)
{
    if (tp != NULL) {
        tp->tv_sec  = 1704067200; /* fixed timestamp: 2024-01-01 */
        tp->tv_nsec = 0;
    }
    (void)clk_id;
    return 0;
}
#endif

/* Structures Definitions*/

struct tm {
    int tm_sec; /* seconds after the minute [0-60] */
    int tm_min; /* minutes after the hour [0-59] */
    int tm_hour; /* hours since midnight [0-23] */
    int tm_mday; /* day of the month [1-31] */
    int tm_mon; /* months since January [0-11] */
    int tm_year; /* years since 1900 */
    int tm_wday; /* days since Sunday [0-6] */
    int tm_yday; /* days since January 1 [0-365] */
    int tm_isdst; /* Daylight Savings Time flag */
    long tm_gmtoff; /* offset from CUT in seconds */
    char *tm_zone; /* timezone abbreviation */
};


/* -- Time Management Routines --*/

time_t time(time_t *timer)
{
    /* Stub: Return fixed timestamp (2024-01-01 00:00:00 UTC) */
    time_t fixed_time = 1704067200;
    if (timer != NULL) {
        *timer = fixed_time;
    }
    return fixed_time;
}

struct tm *gmtime(const time_t *timer)
{
    /* Stub: For cryptographic operations that need time, return a static tm struct */
    static struct tm result = {
        .tm_sec = 0,    /* 0 seconds */
        .tm_min = 0,    /* 0 minutes */
        .tm_hour = 0,   /* 0 hours (midnight) */
        .tm_mday = 1,   /* 1st day */
        .tm_mon = 0,    /* January */
        .tm_year = 124, /* 2024 */
        .tm_wday = 0,   /* Sunday */
        .tm_yday = 0,   /* First day of year */
        .tm_isdst = 0   /* No DST */
    };
    (void)timer;
    return &result;
}

time_t _time64(time_t *t)
{
    /* Stub: Same as time() */
    time_t fixed_time = 1704067200;
    if (t != NULL) {
        *t = fixed_time;
    }
    return fixed_time;
}

struct tm *gmtime_r(const time_t *timep, struct tm *result)
{
    /* Stub: Fill result with static time */
    if (result == NULL) {
        return NULL;
    }
    result->tm_sec = 0;
    result->tm_min = 0;
    result->tm_hour = 0;
    result->tm_mday = 1;
    result->tm_mon = 0;
    result->tm_year = 124;
    result->tm_wday = 0;
    result->tm_yday = 0;
    result->tm_isdst = 0;
    (void)timep;
    return result;
}
