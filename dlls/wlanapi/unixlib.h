/*
 * Unix interface definitions
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

#ifndef __WINE_WLANAPI_UNIXLIB_H
#define __WINE_WLANAPI_UNIXLIB_H

#include <windef.h>

struct wlan_open_handle_params
{
    UINT_PTR handle;
};

struct wlan_close_handle_params
{
    UINT_PTR handle;
};

struct wlan_get_interfaces_params
{
    UINT_PTR handle;

    UINT_PTR interfaces;
    SIZE_T len;
};

struct unix_wlan_interface_info
{
    GUID guid;
    CHAR description[256];
    WLAN_INTERFACE_STATE state;
};

struct wlan_copy_and_free_interfaces_params
{
    UINT_PTR interfaces;

    struct unix_wlan_interface_info *info;
};

struct wlan_free_interfaces_params
{
    UINT_PTR interfaces;
};

enum wlanpi_funcs
{
    unix_wlan_init,

    unix_wlan_open_handle,
    unix_wlan_close_handle,

    unix_wlan_get_interfaces,
    unix_wlan_copy_and_free_interfaces,
    unix_wlan_free_interfaces,

    unix_funcs_count
};

#define UNIX_WLAN_CALL( func, params ) WINE_UNIX_CALL( unix_##func, (params) )

#endif /* __WINE_WLANAPI_UNIXLIB_H */
