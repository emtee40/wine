/*
 * wlanapi DBus backed implementation
 *
 * Copyright 2024 Vibhav Pant
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

#include <dlfcn.h>

#ifdef SONAME_LIBDBUS_1
#include <dbus/dbus.h>
#endif

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <winternl.h>

#include <wine/debug.h>

#include "dbus.h"

WINE_DEFAULT_DEBUG_CHANNEL( wlanapi );

#ifdef SONAME_LIBDBUS_1

#define DO_FUNC( f ) typeof( f ) (*p_##f)
DBUS_FUNCS;
#undef DO_FUNC

BOOL load_dbus_functions( void )
{
    void *handle = dlopen( SONAME_LIBDBUS_1, RTLD_NOW );

    if (handle == NULL) goto failed;

#define DO_FUNC( f )                                                                               \
    if (!(p_##f = dlsym( handle, #f )))                                                            \
    {                                                                                              \
        ERR( "failed to load symbol %s: %s\n", #f, dlerror() );                                    \
        goto failed;                                                                               \
    }
    DBUS_FUNCS;
#undef DO_FUNC
    p_dbus_threads_init_default();
    return TRUE;

failed:
    WARN( "failed to load DBus support: %s\n", dlerror() );
    return FALSE;
}

NTSTATUS init_dbus_connection( UINT_PTR *handle )
{
    DBusError error;
    DBusConnection *connection;
    NTSTATUS ret = STATUS_SUCCESS;

    p_dbus_error_init( &error );
    connection = p_dbus_bus_get_private( DBUS_BUS_SYSTEM, &error );
    if (connection == NULL)
    {
        ERR( "Failed to get system dbus connection: %s: %s.\n", debugstr_a( error.name ),
             debugstr_a( error.message ) );
        ret = STATUS_NOT_SUPPORTED;
    }
    else
        *handle = (UINT_PTR)connection;
    p_dbus_error_free( &error );

    return ret;
}

void close_dbus_connection( void *c )
{
    p_dbus_connection_close( c );
    p_dbus_connection_unref( c );
}
#else /* SONAME_LIBDBUS_1 */
BOOL load_dbus_functions( void ) { return FALSE; }
NTSTATUS init_dbus_connection( UINT_PTR *handle ) { return STATUS_NOT_SUPPORTED; }
void close_dbus_connection( void *c ) { return STATUS_NOT_SUPPORTED; }
#endif
