/*
 * wlanapi unixlib implementation
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

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <winternl.h>

#include <wine/unixlib.h>

#include "unixlib.h"
#include "unixlib_priv.h"

static BOOL initialized;

NTSTATUS wlan_init( void *params )
{
    initialized = load_dbus_functions();
    return STATUS_SUCCESS;
}

NTSTATUS wlan_open_handle( void *params )
{
    struct wlan_open_handle_params *args = params;
    NTSTATUS status;
    if (!initialized)
        return STATUS_NOT_SUPPORTED;

    status = init_dbus_connection( &args->handle );
    return status;
}

NTSTATUS wlan_close_handle( void *params )
{
    struct wlan_close_handle_params *args = params;
    if (!initialized)
        return STATUS_NOT_SUPPORTED;

    close_dbus_connection( (void *)args->handle );
    return STATUS_SUCCESS;
}

const unixlib_entry_t __wine_unix_call_funcs[] = {
    wlan_init,
    wlan_open_handle,
    wlan_close_handle
};

C_ASSERT( ARRAYSIZE( __wine_unix_call_funcs ) == unix_funcs_count );
