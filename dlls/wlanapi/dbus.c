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

#include <stdlib.h>
#include <dlfcn.h>

#ifdef SONAME_LIBDBUS_1
#include <dbus/dbus.h>
#endif

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <winternl.h>
#include <wlanapi.h>

#include <wine/debug.h>
#include <wine/list.h>

#include "unixlib.h"
#include "unixlib_priv.h"
#include "dbus.h"

WINE_DEFAULT_DEBUG_CHANNEL( wlanapi );

#ifdef SONAME_LIBDBUS_1

#define DO_FUNC( f ) typeof( f ) (*p_##f)
DBUS_FUNCS;
#undef DO_FUNC

#define NETWORKMANAGER_SERVICE "org.freedesktop.NetworkManager"

#define NETWORKMANAGER_INTERFACE_MANAGER "org.freedesktop.NetworkManager"
#define NETWORKMANAGER_INTERFACE_DEVICE "org.freedesktop.NetworkManager.Device"

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

const static int dbus_timeout = -1;


static NTSTATUS dbus_error_to_ntstatus( const DBusError *error )
{

#define DBUS_ERROR_CASE(n, s) if(p_dbus_error_has_name( error, (n)) ) return (s)

    DBUS_ERROR_CASE( DBUS_ERROR_UNKNOWN_OBJECT, STATUS_INVALID_PARAMETER );
    DBUS_ERROR_CASE( DBUS_ERROR_NO_MEMORY, STATUS_NO_MEMORY );
    DBUS_ERROR_CASE( DBUS_ERROR_NOT_SUPPORTED, STATUS_NOT_SUPPORTED );
    DBUS_ERROR_CASE( DBUS_ERROR_ACCESS_DENIED, STATUS_ACCESS_DENIED );
    return STATUS_INTERNAL_ERROR;
#undef DBUS_ERROR_CASE
}

#define NM_DEVICE_TYPE_WIFI 2

static BOOL networkmanager_device_is_wifi( void *connection, const char *object_path )
{
    DBusMessage *request, *reply;
    DBusError error;
    DBusMessageIter iter, variant;
    dbus_bool_t success;
    BOOL is_wifi;
    const char *device_iface = NETWORKMANAGER_INTERFACE_DEVICE;
    const char *devicetype_prop = "DeviceType";

    request = p_dbus_message_new_method_call( NETWORKMANAGER_SERVICE, object_path,
                                              DBUS_INTERFACE_PROPERTIES, "Get" );
    if (!request) return FALSE;
    success = p_dbus_message_append_args( request, DBUS_TYPE_STRING, &device_iface,
                                          DBUS_TYPE_STRING, &devicetype_prop, DBUS_TYPE_INVALID );
    if (!success)
    {
        p_dbus_message_unref( request );
        return FALSE;
    }

    p_dbus_error_init( &error );
    reply = p_dbus_connection_send_with_reply_and_block( connection, request, dbus_timeout, &error );
    p_dbus_message_unref( request );
    if (!reply)
    {
        p_dbus_error_free( &error );
        return FALSE;
    }
    p_dbus_error_free( &error );
    p_dbus_error_init( &error );

    p_dbus_message_iter_init( reply, &iter );
    p_dbus_message_iter_recurse( &iter, &variant );
    if (p_dbus_message_iter_get_arg_type( &variant) == DBUS_TYPE_UINT32)
    {
        dbus_uint32_t device_type;

        p_dbus_message_iter_get_basic( &variant, &device_type );
        is_wifi = device_type == NM_DEVICE_TYPE_WIFI;
    }
    else
    {
        ERR( "Unexpected signature for property DeviceType: %c\n",
             p_dbus_message_iter_get_arg_type( &variant ) );
        is_wifi = FALSE;
    }

    p_dbus_error_free( &error );
    p_dbus_message_unref( reply );

    return is_wifi;
}

/* NetworkManager device objects do not have any UUID-like propertiy which we could use to
   deterministically derive an interface GUID for Win32. However, all device objects have
   the object path prefix "/org/freedesktop/NetworkManager/Devices/" followed by a numerical
   index. We use index as the last 4 bytes of this GUID to create a Win32 WLAN interface GUID. */
const static GUID NETWORKMANAGER_DEVICE_BASE_INTERFACE_GUID = {
    0xa53634f7, 0xc1bc, 0x4d41, { 0xbc, 0x06, 0xd3, 0xf7, 0x00, 0x00, 0x00, 0x00 } };

static BOOL networkmanager_device_path_to_guid( const char *object_path, GUID *guid )
{
    const static char device_prefix[] = "/org/freedesktop/NetworkManager/Devices/";
    BOOL is_device = strncmp( object_path, device_prefix, sizeof( device_prefix ) );
    UINT32 idx;

    if (!is_device) return FALSE;
    idx = atoi( object_path + sizeof(device_prefix) - 1 );
    if (!idx) /* NetworkManager doesn't seem to use 0 as an index for devices. */
    {
        ERR( "Could not parse index from device path %s:\n", debugstr_a( object_path ));
        return FALSE;
    }

    *guid = NETWORKMANAGER_DEVICE_BASE_INTERFACE_GUID;
    memcpy( &guid->Data4[4], &idx, 4 );

    return TRUE;
}

static const char *dbus_next_dict_entry( DBusMessageIter *iter, DBusMessageIter *variant )
{
    DBusMessageIter sub;
    const char *name;

    if (p_dbus_message_iter_get_arg_type( iter ) != DBUS_TYPE_DICT_ENTRY)
        return NULL;

    p_dbus_message_iter_recurse( iter, &sub );
    p_dbus_message_iter_next( iter );
    p_dbus_message_iter_get_basic( &sub, &name );
    p_dbus_message_iter_next( &sub );
    p_dbus_message_iter_recurse( &sub, variant );
    return name;
}

#define NM_DEVICE_STATE_UNKNOWN      0
#define NM_DEVICE_STATE_UNMANAGED    10
#define NM_DEVICE_STATE_UNAVAILABLE  20
#define NM_DEVICE_STATE_DISCONNECTED 30
#define NM_DEVICE_STATE_PREPARE      40
#define NM_DEVICE_STATE_CONFIG       50
#define NM_DEVICE_STATE_NEED_AUTH    60
#define NM_DEVICE_STATE_IP_CONFIG    70
#define NM_DEVICE_STATE_IP_CHECK     80
#define NM_DEVICE_STATE_SECONDARIES  90
#define NM_DEVICE_STATE_ACTIVATED    100
#define NM_DEVICE_STATE_DEACTIVATING 110
#define NM_DEVICE_STATE_FAILED       120

static BOOL networkmanager_wifi_device_get_info( void *connection, const char *object_path,
                                                 struct unix_wlan_interface_info *info )
{
    DBusMessage *request, *reply;
    DBusError error;
    DBusMessageIter dict, prop_iter, variant;
    const char *prop_name;
    const char *device_iface = NETWORKMANAGER_INTERFACE_DEVICE;

    if (!networkmanager_device_path_to_guid( object_path, &info->guid )) return FALSE;
    request = p_dbus_message_new_method_call( NETWORKMANAGER_SERVICE, object_path,
                                              DBUS_INTERFACE_PROPERTIES, "GetAll" );
    if (!request) return FALSE;

    p_dbus_message_append_args( request, DBUS_TYPE_STRING, &device_iface, DBUS_TYPE_INVALID );
    p_dbus_error_init( &error );
    reply = p_dbus_connection_send_with_reply_and_block( connection, request, dbus_timeout, &error );
    p_dbus_message_unref( request );
    if (!reply)
    {
        ERR( "Could not get properties for %s: %s: %s.\n", debugstr_a( object_path ), error.name,
             error.message );
        p_dbus_error_free( &error );
        return FALSE;
    }

    p_dbus_error_free( &error );
    p_dbus_message_iter_init( reply, &dict );
    p_dbus_message_iter_recurse( &dict, &prop_iter );
    while ((prop_name = dbus_next_dict_entry( &prop_iter, &variant )))
    {
        if (!strcmp( prop_name, "Interface" ) &&
            p_dbus_message_iter_get_arg_type( &variant ) == DBUS_TYPE_STRING)
        {
            const char *interface;
            size_t len;

            p_dbus_message_iter_get_basic( &variant, &interface );
            len =  min( strlen( interface ), sizeof( info->description ) - 1 );
            memcpy( info->description, interface, len);
            info->description[len] = '\0';
        }
        else if (!strcmp( prop_name, "State" ) &&
                 p_dbus_message_iter_get_arg_type( &variant ) == DBUS_TYPE_UINT32)
        {
            dbus_uint32_t state;

            p_dbus_message_iter_get_basic( &variant, &state );
            switch (state)
            {
                case NM_DEVICE_STATE_UNKNOWN:
                case NM_DEVICE_STATE_UNMANAGED:
                case NM_DEVICE_STATE_UNAVAILABLE:
                case NM_DEVICE_STATE_FAILED:
                case NM_DEVICE_STATE_SECONDARIES:
                    info->state = wlan_interface_state_not_ready;
                    break;
                case NM_DEVICE_STATE_CONFIG:
                case NM_DEVICE_STATE_PREPARE:
                    info->state = wlan_interface_state_associating;
                    break;
                case NM_DEVICE_STATE_IP_CONFIG:
                case NM_DEVICE_STATE_IP_CHECK:
                    info->state = wlan_interface_state_discovering;
                    break;
                case NM_DEVICE_STATE_NEED_AUTH:
                    info->state = wlan_interface_state_authenticating;
                    break;
                case NM_DEVICE_STATE_ACTIVATED:
                    info->state = wlan_interface_state_connected;
                    break;
                case NM_DEVICE_STATE_DEACTIVATING:
                    info->state = wlan_interface_state_disconnecting;
                    break;
                case NM_DEVICE_STATE_DISCONNECTED:
                    info->state = wlan_interface_state_disconnected;
                    break;
                default:
                    FIXME( "Unknown NMDeviceState value %d\n", (int)state );
                    info->state = wlan_interface_state_not_ready;
                    break;
            }
        }
    }
    p_dbus_message_unref(reply);
    return TRUE;
}

NTSTATUS networkmanager_get_wifi_devices( void *connection, struct list *devices )
{
    DBusMessage *request, *reply;
    char **object_paths = NULL;
    int n_objects, i;
    dbus_bool_t success;
    DBusError error;

    request =
        p_dbus_message_new_method_call( NETWORKMANAGER_SERVICE, "/org/freedesktop/NetworkManager",
                                        NETWORKMANAGER_INTERFACE_MANAGER, "GetDevices" );
    if (!request) return STATUS_NO_MEMORY;

    p_dbus_error_init( &error );
    reply =
        p_dbus_connection_send_with_reply_and_block( connection, request, dbus_timeout, &error );
    p_dbus_message_unref( request );
    if (!reply)
    {
        NTSTATUS ret = dbus_error_to_ntstatus( &error );
        ERR( "Could not get list of network devices: %s: %s.\n", debugstr_a( error.name ),
             debugstr_a( error.message ) );
        p_dbus_error_free( &error );
        return ret;
    }

    p_dbus_error_free( &error );
    p_dbus_error_init( &error );
    success = p_dbus_message_get_args( reply, &error, DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH,
                                      &object_paths, &n_objects, DBUS_TYPE_INVALID );
    if (!success)
    {
        NTSTATUS ret = dbus_error_to_ntstatus( &error );
        ERR( "Could not read object paths from GetDevices reply: %s: %s.\n",
             debugstr_a( error.name ), debugstr_a( error.message ) );
        p_dbus_error_free( &error );
        p_dbus_message_unref( reply );
        return ret;
    }

    p_dbus_error_free( &error );
    for (i = 0; i < n_objects; i++)
    {
        const char *object_path = object_paths[i];
        struct unix_wlan_interface_info info = {0};

        if (networkmanager_device_is_wifi( connection, object_path ) &&
            networkmanager_device_path_to_guid( object_path, &info.guid ) &&
            networkmanager_wifi_device_get_info( connection, object_path, &info ))
        {
            struct wlan_interface *entry = malloc( sizeof(*entry) );
            if (!entry) continue;
            entry->info = info;
            list_add_head( devices, &entry->entry );
        }
    }

    p_dbus_free_string_array( object_paths );
    p_dbus_message_unref( reply );
    return STATUS_SUCCESS;
}

#else /* SONAME_LIBDBUS_1 */
BOOL load_dbus_functions( void ) { return FALSE; }
NTSTATUS init_dbus_connection( UINT_PTR *handle ) { return STATUS_NOT_SUPPORTED; }
void close_dbus_connection( void *c ) { return STATUS_NOT_SUPPORTED; }
#endif
