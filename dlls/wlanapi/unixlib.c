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

#include <stdlib.h>

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <winternl.h>
#include <wlanapi.h>

#include <wine/list.h>
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

NTSTATUS wlan_get_interfaces( void *params )
{
    struct wlan_get_interfaces_params *args = params;
    struct list *ifaces;
    NTSTATUS status;

    if (!initialized)
        return STATUS_NOT_SUPPORTED;

    ifaces = malloc( sizeof( *ifaces ) );
    if (!ifaces) return STATUS_NO_MEMORY;

    list_init( ifaces );
    status = networkmanager_get_wifi_devices( (void *)args->handle, ifaces );
    if (status != STATUS_SUCCESS)
    {
        free( ifaces );
        return status;
    }

    args->interfaces = (UINT_PTR)ifaces;
    args->len = list_count( ifaces );
    return STATUS_SUCCESS;
}

NTSTATUS wlan_copy_and_free_interfaces( void *params )
{
    struct wlan_copy_and_free_interfaces_params *args = params;
    struct wlan_interface *ifaces = (struct wlan_interface *)args->interfaces;
    struct wlan_interface *cur, *next;
    SIZE_T i = 0;

    LIST_FOR_EACH_ENTRY_SAFE(cur, next, &ifaces->entry, struct wlan_interface, entry)
    {
        args->info[i++] = cur->info;
        list_remove( &cur->entry );
        free( cur );
    }

    free( ifaces );
    return STATUS_SUCCESS;
}

NTSTATUS wlan_free_interfaces( void *params )
{
    struct wlan_free_interfaces_params *args = params;
    struct wlan_interface *ifaces = (struct wlan_interface *)args->interfaces;
    struct wlan_interface *cur, *next;

    LIST_FOR_EACH_ENTRY_SAFE(cur, next, &ifaces->entry, struct wlan_interface, entry)
    {
        list_remove( &cur->entry );
        free( cur );
    }

    free( ifaces );
    return STATUS_SUCCESS;
}

const unixlib_entry_t __wine_unix_call_funcs[] = {
    wlan_init,
    wlan_open_handle,
    wlan_close_handle,

    wlan_get_interfaces,
    wlan_copy_and_free_interfaces,

    wlan_free_interfaces,
};

C_ASSERT( ARRAYSIZE( __wine_unix_call_funcs ) == unix_funcs_count );
