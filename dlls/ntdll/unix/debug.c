/*
 * Debugging functions
 *
 * Copyright 2000 Alexandre Julliard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <assert.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/statvfs.h>

#include "ntstatus.h"
#include "windef.h"
#include "winnt.h"
#include "winternl.h"
#include "unix_private.h"
#include "wine/debug.h"

WINE_DECLARE_DEBUG_CHANNEL(pid);
WINE_DECLARE_DEBUG_CHANNEL(timestamp);
WINE_DEFAULT_DEBUG_CHANNEL(ntdll);

struct debug_info
{
    unsigned int str_pos;       /* current position in strings buffer */
    unsigned int out_pos;       /* current position in output buffer */
    char         strings[1020]; /* buffer for temporary strings */
    char         output[1020];  /* current output line */
};

C_ASSERT( sizeof(struct debug_info) == 0x800 );

static struct debug_info initial_info;  /* debug info for initial thread */
static unsigned char default_flags = (1 << __WINE_DBCL_ERR) | (1 << __WINE_DBCL_FIXME);
static int nb_debug_options = -1;
static int options_size;
static struct __wine_debug_channel *debug_options;

static const char * const debug_classes[] = { "fixme", "err", "warn", "trace" };

/* iOS-Madeira (flight-recorder, Cameron Nov 21: "is there like an ultimate perfect log ... you always
 * have to add stuff to it"): extra trace channels that are formatted as usual but NOT written to the
 * log (fd 2). Each line goes into a fixed ring of 512-byte slots in a shared file mapping,
 * $HOME/Library/Caches/flight-recorder.bin (not Documents: no Files app, no backup; mode 0600; real
 * blocks allocated before it is mapped, so a full disk can't SIGBUS a game), which outlives a crash or an iOS kill. The app copies the
 * last 60 s of it into madeira-log.txt when a game run ends (LogTrail.swift, FlightRecorder).
 * Channels: MADEIRA_FLIGHT_CHANNELS, WINEDEBUG syntax (default below). Lines WINEDEBUG itself asks
 * for still go to the log as before. Size: MADEIRA_FLIGHT_MB (1-64, default 8).
 * Off switch: MADEIRA_FLIGHT=0 (no channels added, nothing else changes).
 * File layout (read by the app; keep both in step): a 4096-byte header, then slots. */
#define FLIGHT_MAGIC   0x3152464dU   /* "MFR1" */
#define FLIGHT_SLOT    512
/* Cheap by default (review 1): DLL loads plus the warn class of the loader, process and thread code.
 * trace+seh / trace+module / trace+process / trace+thread are hot in some games: opt in per game. */
#define FLIGHT_DEFAULT "trace+loaddll,warn+loaddll,warn+module,warn+process,warn+thread"
struct flight_header
{
    unsigned int       magic;
    unsigned int       slot_size;
    unsigned int       slots;
    unsigned int       version;     /* 1 */
    unsigned long long next;        /* sequence number of the next line (lines ever written) */
    unsigned long long opened_ms;   /* wall clock when this launch mapped it */
};
struct flight_slot
{
    unsigned long long seq;         /* line number + 1; 0 while being written */
    unsigned long long ms;          /* wall clock, ms since 1970 */
    unsigned short     len;
    unsigned short     reserved;
    char               text[FLIGHT_SLOT - 20];
};
C_ASSERT( sizeof(struct flight_slot) == FLIGHT_SLOT );
static struct flight_header *flight;
static struct flight_slot *flight_slots;
static unsigned int flight_count;
/* What WINEDEBUG alone asked for: lines it covers keep going to the log. */
static struct __wine_debug_channel *print_options;
static int nb_print_options;
static unsigned char print_default;

/* get the debug info pointer for the current thread */
static inline struct debug_info *get_info( struct thread_data *data )
{
    return data ? (struct debug_info *)data->debug_info : &initial_info;
}

/* add a string to the output buffer */
static int append_output( struct debug_info *info, const char *str, size_t len )
{
    if (len >= sizeof(info->output) - info->out_pos)
    {
       fprintf( stderr, "wine_dbg_output: debugstr buffer overflow (contents: '%s')\n", info->output );
       info->out_pos = 0;
       abort();
    }
    memcpy( info->output + info->out_pos, str, len );
    info->out_pos += len;
    return len;
}

/* add a new debug option at the end of the option list */
static void add_option( const char *name, unsigned char set, unsigned char clear )
{
    int min = 0, max = nb_debug_options - 1, pos, res;

    if (!name[0])  /* "all" option */
    {
        default_flags = (default_flags & ~clear) | set;
        return;
    }
    if (strlen(name) >= sizeof(debug_options[0].name)) return;

    while (min <= max)
    {
        pos = (min + max) / 2;
        res = strcmp( name, debug_options[pos].name );
        if (!res)
        {
            debug_options[pos].flags = (debug_options[pos].flags & ~clear) | set;
            return;
        }
        if (res < 0) max = pos - 1;
        else min = pos + 1;
    }
    if (nb_debug_options >= options_size)
    {
        options_size = max( options_size * 2, 16 );
        debug_options = realloc( debug_options, options_size * sizeof(debug_options[0]) );
    }

    pos = min;
    if (pos < nb_debug_options) memmove( &debug_options[pos + 1], &debug_options[pos],
                                         (nb_debug_options - pos) * sizeof(debug_options[0]) );
    strcpy( debug_options[pos].name, name );
    debug_options[pos].flags = (default_flags & ~clear) | set;
    nb_debug_options++;
}

/* parse a set of debugging option specifications and add them to the option list */
static void parse_options( const char *str, const char *app_name )
{
    char *opt, *next, *options;
    unsigned int i;

    if (!(options = strdup(str))) return;
    for (opt = options; opt; opt = next)
    {
        char *p;
        unsigned char set = 0, clear = 0;

        if ((next = strchr( opt, ',' ))) *next++ = 0;

        if ((p = strchr( opt, ':' )))
        {
            *p = 0;
            if (strcasecmp( opt, app_name )) continue;
            opt = p + 1;
        }

        p = opt + strcspn( opt, "+-" );
        if (!p[0]) p = opt;  /* assume it's a debug channel name */

        if (p > opt)
        {
            for (i = 0; i < ARRAY_SIZE(debug_classes); i++)
            {
                int len = strlen(debug_classes[i]);
                if (len != (p - opt)) continue;
                if (!memcmp( opt, debug_classes[i], len ))  /* found it */
                {
                    if (*p == '+') set |= 1 << i;
                    else clear |= 1 << i;
                    break;
                }
            }
            if (i == ARRAY_SIZE(debug_classes)) /* bad class name, skip it */
                continue;
        }
        else
        {
            if (*p == '-') clear = ~0;
            else set = ~0;
        }
        if (*p == '+' || *p == '-') p++;
        if (!p[0]) continue;

        if (!strcmp( p, "all" ))
            default_flags = (default_flags & ~clear) | set;
        else
            add_option( p, set, clear );
    }
    free( options );
}

/* print the usage message */
static void debug_usage(void)
{
    static const char usage[] =
        "Syntax of the WINEDEBUG variable:\n"
        "  WINEDEBUG=[[process:]class]+xxx,[[process:]class]-yyy,...\n\n"
        "Example: WINEDEBUG=+relay,warn-heap\n"
        "    turns on relay traces, disable heap warnings\n"
        "Available message classes: err, warn, fixme, trace\n";
    write( 2, usage, sizeof(usage) - 1 );
    exit(1);
}

/* iOS-Madeira (flight-recorder): only "trace+name" / "warn+name" entries (review 10): the ring's
 * channel list can never turn a normal log class off or touch "all", pid or timestamp. */
static void flight_parse_channels( const char *list )
{
    char *copy, *opt, *next;

    if (!(copy = strdup( list ))) return;
    for (opt = copy; opt; opt = next)
    {
        unsigned char set;
        const char *name;

        if ((next = strchr( opt, ',' ))) *next++ = 0;
        if (!strncmp( opt, "trace+", 6 )) { set = 1 << __WINE_DBCL_TRACE; name = opt + 6; }
        else if (!strncmp( opt, "warn+", 5 )) { set = 1 << __WINE_DBCL_WARN; name = opt + 5; }
        else continue;
        if (!name[0] || !strcmp( name, "all" ) || !strcmp( name, "pid" ) || !strcmp( name, "timestamp" )) continue;
        add_option( name, set, 0 );
    }
    free( copy );
}

/* iOS-Madeira (flight-recorder): map the ring and add its channels on top of WINEDEBUG's. */
static void flight_init( const char *app_name )
{
    const char *on = getenv( "MADEIRA_FLIGHT" ), *home = getenv( "HOME" );
    const char *channels = getenv( "MADEIRA_FLIGHT_CHANNELS" ), *mb_text = getenv( "MADEIRA_FLIGHT_MB" );
    const char *verbose = getenv( "MADEIRA_DEBUG_VERBOSE" );
    static const char zeros[65536];
    char path[1024];
    unsigned int mb = mb_text ? atoi( mb_text ) : 8, slots;
    size_t size, done;
    struct stat st;
    struct statvfs vfs;
    void *map;
    int fd, n;

    if (on && (on[0] == '0' || !strcasecmp( on, "off" ) || !strcasecmp( on, "false" ) || !strcasecmp( on, "no" ))) return;
    if (verbose && verbose[0] && verbose[0] != '0') return;   /* everything goes to the log already */
    if (!home || !home[0]) return;
    if (mb < 1 || mb > 64) mb = 8;
    slots = (mb << 20) / FLIGHT_SLOT;
    size = 4096 + (size_t)slots * FLIGHT_SLOT;
    n = snprintf( path, sizeof(path), "%s/Library/Caches/flight-recorder.bin", home );
    if (n < 0 || n >= (int)sizeof(path)) return;
    /* Review 3: never map a sparse or shrinking file. A file of another size is replaced (a new inode,
     * so a reader that still has the old one open is not cut short); a new file gets real blocks. */
    if (!stat( path, &st ) && (size_t)st.st_size != size) unlink( path );
    if ((fd = open( path, O_RDWR | O_CREAT | O_CLOEXEC, 0600 )) == -1) return;
#ifdef F_SETPROTECTIONCLASS
    fcntl( fd, F_SETPROTECTIONCLASS, 4 );   /* class D (none): readable while the phone is locked */
#endif
    if (fstat( fd, &st ) == -1) { close( fd ); return; }
    if ((size_t)st.st_size != size)
    {
        /* keep 256 MB free for the game: no ring on a nearly full phone */
        if (fstatvfs( fd, &vfs ) == -1 || (unsigned long long)vfs.f_bavail * vfs.f_frsize < size + (256ull << 20))
        {
            close( fd ); unlink( path ); return;
        }
        for (done = 0; done < size; )
        {
            size_t chunk = size - done < sizeof(zeros) ? size - done : sizeof(zeros);
            ssize_t w = pwrite( fd, zeros, chunk, done );
            if (w <= 0) { close( fd ); unlink( path ); return; }   /* ENOSPC or a short write: no ring */
            done += w;
        }
        if (fsync( fd ) == -1) { close( fd ); unlink( path ); return; }
    }
    map = mmap( NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0 );
    close( fd );
    if (map == MAP_FAILED) return;

    /* Snapshot what WINEDEBUG prints before the ring's channels are added. */
    if (!(print_options = malloc( (nb_debug_options + 1) * sizeof(*print_options) ))) { munmap( map, size ); return; }
    if (nb_debug_options) memcpy( print_options, debug_options, nb_debug_options * sizeof(*print_options) );
    nb_print_options = nb_debug_options;
    print_default = default_flags;

    flight_slots = (struct flight_slot *)((char *)map + 4096);
    {
        struct flight_header *h = map;
        struct timeval tv;

        if (h->magic != FLIGHT_MAGIC || h->slot_size != FLIGHT_SLOT || h->slots != slots || h->version != 1)
        {
            memset( map, 0, 4096 );   /* a new file: every slot's seq is 0 */
            h->slot_size = FLIGHT_SLOT;
            h->slots = slots;
            h->version = 1;
            __atomic_store_n( &h->magic, FLIGHT_MAGIC, __ATOMIC_RELEASE );
        }
        gettimeofday( &tv, NULL );
        h->opened_ms = (unsigned long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
    }
    flight_count = slots;
    flight_parse_channels( channels && channels[0] ? channels : FLIGHT_DEFAULT );
    __atomic_store_n( &flight, (struct flight_header *)map, __ATOMIC_RELEASE );
    (void)app_name;
}

/* iOS-Madeira (flight-recorder): the print flags WINEDEBUG alone gave `name`. */
static unsigned char flight_print_flags( const char *name )
{
    int min = 0, max = nb_print_options - 1, pos, res;

    while (min <= max)
    {
        pos = (min + max) / 2;
        res = strcmp( name, print_options[pos].name );
        if (!res) return print_options[pos].flags;
        if (res < 0) max = pos - 1;
        else min = pos + 1;
    }
    return print_default;
}

/* iOS-Madeira (flight-recorder): one line into the next slot. Lock-free: one atomic add. */
static void flight_put( const char *str, size_t len )
{
    struct flight_slot *slot;
    unsigned long long seq;
    struct timeval tv;
    size_t n = len;

    gettimeofday( &tv, NULL );
    seq = __atomic_fetch_add( &flight->next, 1, __ATOMIC_RELAXED );
    slot = &flight_slots[seq % flight_count];
    __atomic_store_n( &slot->seq, 0, __ATOMIC_RELAXED );
    __atomic_thread_fence( __ATOMIC_RELEASE );
    while (n && (str[n - 1] == '\n' || str[n - 1] == '\r')) n--;
    if (n > sizeof(slot->text)) n = sizeof(slot->text);
    memcpy( slot->text, str, n );
    slot->len = n;
    slot->ms = (unsigned long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
    __atomic_store_n( &slot->seq, seq + 1, __ATOMIC_RELEASE );
}

/* iOS-Madeira (flight-recorder): a trace or warn line that only the ring asked for goes into the
 * ring instead of fd 2; decided from the line's own "class:channel:" header, because the PE side's
 * lines arrive here as text. Returns 1 when it took the line. A "\1" line (no header) goes to the
 * log as before (review 4: the debug_info area is shared with the PE side, so no per-thread flag). */
static int flight_take( const char *str, size_t len )
{
    const char *p = str, *end = str + len, *name;
    unsigned char flags;
    int i, cls;
    char channel[16];

    if (!flight || len < 8) return 0;
    /* "123.456:" timestamp, "0024:" pid, "0028:" tid, each optional */
    for (i = 0; i < 3; i++)
    {
        const char *q = p;
        while (q < end && ((*q >= '0' && *q <= '9') || (*q >= 'a' && *q <= 'f') || *q == '.' || *q == ' ')) q++;
        if (q > p && q < end && *q == ':') p = q + 1;
        else break;
    }
    if (end - p > 6 && !memcmp( p, "trace:", 6 )) { cls = __WINE_DBCL_TRACE; p += 6; }
    else if (end - p > 5 && !memcmp( p, "warn:", 5 )) { cls = __WINE_DBCL_WARN; p += 5; }
    else return 0;   /* err and fixme lines always go to the log */
    name = p;
    while (p < end && *p != ':' && p - name < 15) p++;
    if (p >= end || *p != ':' || p == name) return 0;
    memcpy( channel, name, p - name );
    channel[p - name] = 0;

    flags = flight_print_flags( channel );
    if (flags & (1 << cls)) return 0;   /* WINEDEBUG asked for it: the log, as before */
    flight_put( str, len );
    return 1;
}

/* initialize all options at startup */
static void init_options(void)
{
    char *wine_debug = getenv("WINEDEBUG");
    const char *app_name, *p;
    struct stat st1, st2;

    nb_debug_options = 0;

    /* check for stderr pointing to /dev/null */
    if (!fstat( 2, &st1 ) && S_ISCHR(st1.st_mode) &&
        !stat( "/dev/null", &st2 ) && S_ISCHR(st2.st_mode) &&
        st1.st_rdev == st2.st_rdev)
    {
        default_flags = 0;
        return;
    }
    setbuf( stdout, NULL );
    setbuf( stderr, NULL );

    if (!wine_debug) return;
    if (!strcmp( wine_debug, "help" )) debug_usage();

    app_name = main_argv[1];
    while ((p = strpbrk( app_name, "/\\" ))) app_name = p + 1;

    parse_options( wine_debug, app_name );
    flight_init( app_name );   /* iOS-Madeira (flight-recorder) */
}

/***********************************************************************
 *		__wine_dbg_get_channel_flags  (NTDLL.@)
 *
 * Get the flags to use for a given channel, possibly setting them too in case of lazy init
 */
unsigned char __cdecl __wine_dbg_get_channel_flags( struct __wine_debug_channel *channel )
{
    int min, max, pos, res;
    unsigned char flags;

    if (!(channel->flags & (1 << __WINE_DBCL_INIT))) return channel->flags;

    if (nb_debug_options == -1) init_options();

    flags = default_flags;
    min = 0;
    max = nb_debug_options - 1;
    while (min <= max)
    {
        pos = (min + max) / 2;
        res = strcmp( channel->name, debug_options[pos].name );
        if (!res)
        {
            flags = debug_options[pos].flags;
            break;
        }
        if (res < 0) max = pos - 1;
        else min = pos + 1;
    }

    if (!(flags & (1 << __WINE_DBCL_INIT))) channel->flags = flags; /* not dynamically changeable */
    return flags;
}

/***********************************************************************
 *		__wine_dbg_strdup  (NTDLL.@)
 */
const char * __cdecl __wine_dbg_strdup( const char *str )
{
    struct debug_info *info = get_info( get_thread_data() );
    unsigned int pos = info->str_pos;
    size_t n = strlen( str ) + 1;

    assert( n <= sizeof(info->strings) );
    if (pos + n > sizeof(info->strings)) pos = 0;
    info->str_pos = pos + n;
    return memcpy( info->strings + pos, str, n );
}

/***********************************************************************
 *		unixcall_wine_dbg_write
 */
NTSTATUS unixcall_wine_dbg_write( void *args )
{
    struct wine_dbg_write_params *params = args;

    if (flight_take( params->str, params->len )) return params->len;   /* iOS-Madeira (flight-recorder) */
    return write( 2, params->str, params->len );
}

#ifdef _WIN64
/***********************************************************************
 *		wow64_wine_dbg_write
 */
NTSTATUS wow64_wine_dbg_write( void *args )
{
    struct
    {
        ULONG        str;
        unsigned int len;
    } const *params32 = args;

    /* `args` is a host pointer (the WoW64 module converts
     * the outer one), but the string it points at is still a GUEST address. */
    if (flight_take( ios_wow_host_ptr(params32->str), params32->len )) return params32->len;   /* iOS-Madeira (flight-recorder) */
    return write( 2, ios_wow_host_ptr(params32->str), params32->len );
}
#endif

/***********************************************************************
 *		__wine_dbg_output  (NTDLL.@)
 */
int __cdecl __wine_dbg_output( const char *str )
{
    struct debug_info *info = get_info( get_thread_data() );
    const char *end = strrchr( str, '\n' );
    int ret = 0;

    if (end)
    {
        ret += append_output( info, str, end + 1 - str );
        if (!flight_take( info->output, info->out_pos ))   /* iOS-Madeira (flight-recorder) */
            write( 2, info->output, info->out_pos );
        info->out_pos = 0;
        str = end + 1;
    }
    if (*str) ret += append_output( info, str, strlen( str ));
    return ret;
}

/***********************************************************************
 *		__wine_dbg_header  (NTDLL.@)
 */
int __cdecl __wine_dbg_header( enum __wine_debug_class cls, struct __wine_debug_channel *channel,
                               const char *function )
{
    static const char * const classes[] = { "fixme", "err", "warn", "trace" };
    struct thread_data *data;
    struct debug_info *info;
    char *pos;

    if (!(__wine_dbg_get_channel_flags( channel ) & (1 << cls))) return -1;

    data = get_thread_data();
    info = get_info( data );
    pos  = info->output;

    /* only print header if we are at the beginning of the line */
    if (info->out_pos) return 0;

    if (data)
    {
        if (TRACE_ON(timestamp))
        {
            UINT ticks = NtGetTickCount();
            pos += snprintf( pos, sizeof(info->output) - (pos - info->output), "%3u.%03u:", ticks / 1000, ticks % 1000 );
        }
        if (TRACE_ON(pid)) pos += snprintf( pos, sizeof(info->output) - (pos - info->output), "%04x:",
                                         /* Madeira: pseudo-processes share this unix lib, so the process-global pid is
                                          * only right for the first one; read the caller's TEB when it has one. */
                                         data->teb ? HandleToULong(data->teb->ClientId.UniqueProcess) : pid );
        if (data->tid) pos += snprintf( pos, sizeof(info->output) - (pos - info->output), "%04x:", data->tid );
    }
    if (function && cls < ARRAY_SIZE( classes ))
        pos += snprintf( pos, sizeof(info->output) - (pos - info->output), "%s:%s:%s ",
                         classes[cls], channel->name, function );
    info->out_pos = pos - info->output;
    return info->out_pos;
}

/***********************************************************************
 *		dbg_init
 */
void dbg_init(void)
{
    struct __wine_debug_channel *options, default_option = { default_flags };

    if (nb_debug_options == -1) init_options();

    options = (struct __wine_debug_channel *)((char *)peb + (is_win64 ? 2 : 1) * page_size);
    memcpy( options, debug_options, nb_debug_options * sizeof(*options) );
    free( debug_options );
    debug_options = options;
    options[nb_debug_options] = default_option;
}


/***********************************************************************
 *              NtTraceControl  (NTDLL.@)
 */
NTSTATUS WINAPI NtTraceControl( ULONG code, void *inbuf, ULONG inbuf_len,
                                void *outbuf, ULONG outbuf_len, ULONG *size )
{
    FIXME( "code %u, inbuf %p, inbuf_len %u, outbuf %p, outbuf_len %u, size %p\n",
           code, inbuf, inbuf_len, outbuf, outbuf_len, size );
    return STATUS_SUCCESS;
}


/***********************************************************************
 *              NtSetDebugFilterState  (NTDLL.@)
 */
NTSTATUS WINAPI NtSetDebugFilterState( ULONG component_id, ULONG level, BOOLEAN state )
{
    FIXME( "component_id %#x, level %u, state %#x stub.\n", component_id, level, state );

    return STATUS_SUCCESS;
}
