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
#include <assert.h>

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
#define NETWORKMANAGER_INTERFACE_DEVICE_WIRELESS "org.freedesktop.NetworkManager.Device.Wireless"
#define NETWORKMANAGER_INTERFACE_ACCESS_POINT "org.freedesktop.NetworkManager.AccessPoint"
#define NETWORKMANAGER_INTERFACE_CONNECTION_ACTIVE "org.freedesktop.NetworkManager.Connection.Active"
#define NETWORKMANAGER_INTERFACE_SETTINGS "org.freedesktop.NetworkManager.Settings"
#define NETWORKMANAGER_INTERFACE_SETTINGS_CONNECTION "org.freedesktop.NetworkManager.Settings.Connection"

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
#define NETWORKMANAGER_DEVICE_PATH_PREFIX "/org/freedesktop/NetworkManager/Devices/"

static BOOL networkmanager_valid_device_guid( const GUID *guid )
{
    return !memcmp( &NETWORKMANAGER_DEVICE_BASE_INTERFACE_GUID, guid, offsetof( GUID, Data4[4] ) );
}

static __WINE_MALLOC char *networkmanager_device_guid_to_path( const GUID *guid )
{
    char *path;
    UINT32 idx = *(UINT32 *)&guid->Data4[4];
    size_t orig_size = sizeof( NETWORKMANAGER_DEVICE_PATH_PREFIX ) + 3;
    size_t size;

    path = malloc( orig_size );
    if (!path) return NULL;

    size = snprintf( path, orig_size, NETWORKMANAGER_DEVICE_PATH_PREFIX "%u", idx );
    if (size >= orig_size)
    {
        char *ptr = realloc( path, size );
        if (!ptr)
        {
            free( path );
            return NULL;
        }
        path = ptr;
        snprintf( path, size, NETWORKMANAGER_DEVICE_PATH_PREFIX "%u", idx );
    }

    return path;
}

static BOOL networkmanager_device_path_to_guid( const char *object_path, GUID *guid )
{
    BOOL is_device = strncmp( object_path, NETWORKMANAGER_DEVICE_PATH_PREFIX, sizeof( NETWORKMANAGER_DEVICE_PATH_PREFIX ) );
    UINT32 idx;

    if (!is_device) return FALSE;
    idx = atoi( object_path + sizeof( NETWORKMANAGER_DEVICE_PATH_PREFIX ) - 1 );
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

static void parse_mac_address( const char *addr_str, BYTE dest[6] )
{
    int addr[6], i;

    sscanf( addr_str, "%x:%x:%x:%x:%x:%x", &addr[0], &addr[1], &addr[2], &addr[3], &addr[4],
            &addr[5] );
    for (i = 0 ; i < 6; i++)
        dest[i] = addr[i];
}

static BOOL networkmanager_get_access_point_info( void *connection, const char *object_path,
                                                  struct wlan_bss_info *network )
{
    DBusMessage *request, *reply;
    DBusMessageIter dict, prop_iter, variant;
    DBusError error;
    dbus_bool_t success;
    const char *prop_name;
    const char *iface_accesspoint = NETWORKMANAGER_INTERFACE_ACCESS_POINT;

    TRACE( "(%p, %s, %p)\n", connection, debugstr_a( object_path ), network );
    request = p_dbus_message_new_method_call( NETWORKMANAGER_SERVICE, object_path,
                                              DBUS_INTERFACE_PROPERTIES, "GetAll" );
    if (!request) return FALSE;
    success = p_dbus_message_append_args( request, DBUS_TYPE_STRING, &iface_accesspoint,
                                          DBUS_TYPE_INVALID );
    if (!success)
    {
        p_dbus_message_unref( request );
        return FALSE;
    }

    p_dbus_error_init( &error );
    reply =
        p_dbus_connection_send_with_reply_and_block( connection, request, dbus_timeout, &error );
    p_dbus_message_unref( request );
    if (!reply)
    {
        ERR( "Could not get proerties for access point %s: %s: %s.\n", debugstr_a( object_path ),
             debugstr_a( error.name ), debugstr_a( error.message ) );
        p_dbus_error_free( &error );
        return FALSE;
    }


    p_dbus_error_free( &error );
    p_dbus_message_iter_init( reply, &dict );
    p_dbus_message_iter_recurse( &dict, &prop_iter );
    while ((prop_name = dbus_next_dict_entry( &prop_iter, &variant )))
    {
        if (!strcmp( prop_name, "Flags" ) &&
            p_dbus_message_iter_get_arg_type( &variant ) == DBUS_TYPE_UINT32)
        {
            p_dbus_message_iter_get_basic( &variant, &network->flags );
        }
        else if (!strcmp( prop_name, "WpaFlags" ) &&
                 p_dbus_message_iter_get_arg_type( &variant ) == DBUS_TYPE_UINT32)
        {
            p_dbus_message_iter_get_basic( &variant, &network->wpa_flags );
        }
        else if (!strcmp( prop_name, "RsnFlags" ) &&
                 p_dbus_message_iter_get_arg_type( &variant ) == DBUS_TYPE_UINT32)
        {
            p_dbus_message_iter_get_basic( &variant, &network->rsn_flags );
        }
        else if (!strcmp( prop_name, "Ssid" ) &&
                 p_dbus_message_iter_get_arg_type( &variant ) == DBUS_TYPE_ARRAY &&
                 p_dbus_message_iter_get_element_type( &variant ) == DBUS_TYPE_BYTE)
        {
            DBusMessageIter iter;
            const char *ssid;
            int len;

            p_dbus_message_iter_recurse( &variant, &iter );
            p_dbus_message_iter_get_fixed_array( &iter, &ssid, &len );
            if (len > sizeof( network->ssid ))
                WARN( "SSID %s for %s is too long\n", debugstr_a( object_path ),
                      debugstr_an( ssid, len ) );

            memcpy( network->ssid, ssid, min( len, sizeof( network->ssid ) ) );
            network->ssid_len = min( len, sizeof( network->ssid ) );
        }
        else if (!strcmp( prop_name, "Frequency" ) &&
                 p_dbus_message_iter_get_arg_type( &variant ) == DBUS_TYPE_UINT32)
        {
            p_dbus_message_iter_get_basic( &variant, &network->frequency );
        }
        else if (!strcmp( prop_name, "HwAddress") &&
                 p_dbus_message_iter_get_arg_type( &variant ) == DBUS_TYPE_STRING)
        {
            const char *addr_str;

            p_dbus_message_iter_get_basic( &variant, &addr_str );
            if (strlen( addr_str ) != 17)
                ERR( "Unexpected HwAddress %s for %s\n", debugstr_a( addr_str ),
                     debugstr_a( object_path ) );

            parse_mac_address( addr_str, network->hw_address );
        }
        else if (!strcmp( prop_name, "Mode" ) &&
            p_dbus_message_iter_get_arg_type( &variant ) == DBUS_TYPE_UINT32)
        {
            p_dbus_message_iter_get_basic( &variant, &network->mode );
        }
        else if (!strcmp( prop_name, "MaxBitrate") &&
                 p_dbus_message_iter_get_arg_type( &variant ) == DBUS_TYPE_UINT32)
        {
            p_dbus_message_iter_get_basic( &variant, &network->max_bitrate );
        }
        else if (!strcmp( prop_name, "Bandwidth" ) &&
                 p_dbus_message_iter_get_arg_type( &variant ) == DBUS_TYPE_UINT32)
        {
            p_dbus_message_iter_get_basic( &variant, &network->bandwidth );
        }
        else if (!strcmp( prop_name, "Strength" ) &&
                 p_dbus_message_iter_get_arg_type( &variant ) == DBUS_TYPE_BYTE)
        {
            p_dbus_message_iter_get_basic( &variant, &network->strength );
        }
        else if (!strcmp( prop_name, "LastSeen") &&
                 p_dbus_message_iter_get_arg_type( &variant ) == DBUS_TYPE_INT32)
        {
            p_dbus_message_iter_get_basic( &variant, &network->last_seen );
        }

    }

    p_dbus_message_unref( reply );
    return TRUE;
}

static char *__WINE_MALLOC networkmanager_device_get_active_ap( void *connection,
                                                                const char *device_path )
{
    DBusMessage *request, *reply;
    DBusMessageIter iter, variant;
    DBusError error;
    const char *str;
    char *dup;
    const char *device_iface = NETWORKMANAGER_INTERFACE_DEVICE,
               *conn_active_iface = NETWORKMANAGER_INTERFACE_CONNECTION_ACTIVE;
    const char *activeconn_prop = "ActiveConnection", *specobj_prop = "SpecificObject";
    dbus_bool_t success;

    request = p_dbus_message_new_method_call( NETWORKMANAGER_SERVICE, device_path,
                                              DBUS_INTERFACE_PROPERTIES,
                                              "Get" );
    if (!request) return NULL;
    success = p_dbus_message_append_args( request, DBUS_TYPE_STRING, &device_iface,
                                          DBUS_TYPE_STRING, &activeconn_prop, DBUS_TYPE_INVALID );
    if (!success)
    {
        p_dbus_message_unref( request );
        return NULL;
    }

    p_dbus_error_init( &error );
    reply = p_dbus_connection_send_with_reply_and_block( connection, request, dbus_timeout, &error );
    p_dbus_message_unref( request );
    if (!reply)
    {
        p_dbus_error_free( &error );
        return NULL;
    }
    p_dbus_error_free( &error );

    p_dbus_message_iter_init( reply, &iter );
    p_dbus_message_iter_recurse( &iter, &variant );
    if (p_dbus_message_iter_get_arg_type( &variant ) != DBUS_TYPE_OBJECT_PATH)
    {
        ERR( "Unexpected signature for property ActiveConnection: %c\n",
            p_dbus_message_iter_get_arg_type( &variant ) );
        return NULL;
    }
    p_dbus_message_iter_get_basic( &variant, &str );

    request = p_dbus_message_new_method_call( NETWORKMANAGER_SERVICE, str,
                                              DBUS_INTERFACE_PROPERTIES, "Get" );
    p_dbus_message_unref( reply );

    if (!request) return NULL;
    success = p_dbus_message_append_args( request, DBUS_TYPE_STRING, &conn_active_iface,
                                          DBUS_TYPE_STRING, &specobj_prop, DBUS_TYPE_INVALID );
    if (!success)
    {
        p_dbus_message_unref( request );
        return NULL;
    }

    p_dbus_error_init( &error );
    reply = p_dbus_connection_send_with_reply_and_block( connection, request, dbus_timeout, &error );
    p_dbus_message_unref( request );
    if (!reply)
    {
        ERR( "Could not get properties for %s: %s: %s.\n", debugstr_a( device_path ), error.name,
             error.message );
        p_dbus_error_free( &error );
        return NULL;
    }
    p_dbus_error_free( &error );
    p_dbus_message_iter_init( reply, &iter );
    p_dbus_message_iter_recurse( &iter, &variant );
    if ( p_dbus_message_iter_get_arg_type( &variant ) != DBUS_TYPE_OBJECT_PATH )
    {
        ERR( "Unexpected signature for property SpecificObject: %c\n",
            p_dbus_message_iter_get_arg_type( &variant ) );
        return NULL;
    }

    p_dbus_message_iter_get_basic( &variant, &str );
    dup = strdup( str );
    p_dbus_message_unref( reply );

    return dup;
}

NTSTATUS networkmanager_get_access_points( void *connection, const GUID *device,
                                           const DOT11_SSID *ssid, BOOL security,
                                           struct list *access_points )
{
    DBusMessage *request, *reply;
    DBusError error;
    dbus_bool_t success;
    char *device_path, *active_ap = NULL;
    char **object_paths;
    int n_objects, i;

    TRACE( "(%p, %s, %p)\n", connection, debugstr_guid( device ), access_points );

    if (!networkmanager_valid_device_guid( device )) return STATUS_INVALID_PARAMETER;
    device_path = networkmanager_device_guid_to_path( device );
    if (!device_path) return STATUS_NO_MEMORY;

    request = p_dbus_message_new_method_call( NETWORKMANAGER_SERVICE, device_path,
                                              NETWORKMANAGER_INTERFACE_DEVICE_WIRELESS,
                                              "GetAllAccessPoints" );
    active_ap = networkmanager_device_get_active_ap( connection, device_path );

    free( device_path );
    if (!request)
    {
        free( active_ap );
        return STATUS_NO_MEMORY;
    }

    p_dbus_error_init( &error );
    reply =
        p_dbus_connection_send_with_reply_and_block( connection, request, dbus_timeout, &error );
    p_dbus_message_unref( request );
    if (!reply)
    {
        NTSTATUS ret = dbus_error_to_ntstatus( &error );
        ERR( "Could not get list of access points: %s: %s.\n", debugstr_a( error.name ),
             debugstr_a( error.message ) );
        p_dbus_error_free( &error );
        free( active_ap );
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
        free( active_ap );
        return ret;
    }

    p_dbus_error_free( &error );
    for (i = 0; i < n_objects; i++)
    {
        const char *object_path = object_paths[i];
        struct wlan_bss_info info = {0};

        if (networkmanager_get_access_point_info( connection, object_path, &info ))
        {
            struct wlan_network *network;

            if (ssid && !(info.ssid_len == ssid->uSSIDLength &&
                          !memcmp( info.ssid, ssid->ucSSID, sizeof( info.ssid ) )))
                continue;
            if (security && !(info.flags & 1)) /* NM_802_11_AP_FLAGS_PRIVACY */
                continue;

            network = calloc( 1, sizeof( *network ) );
            if (!network) continue;
            network->info = info;
            network->info.connected = active_ap && !strcmp( active_ap, object_path );
            list_add_tail( access_points, &network->entry );
        }
    }

    free( active_ap );
    p_dbus_free_string_array( object_paths );
    p_dbus_message_unref( reply );
    return STATUS_SUCCESS;
}

static BOOL networkmanager_requestscan_call_set_ssid( DBusMessageIter *dict, const DOT11_SSID *ssid )
{
    DBusMessageIter entry, variant = DBUS_MESSAGE_ITER_INIT_CLOSED,
                           ssids = DBUS_MESSAGE_ITER_INIT_CLOSED,
                           ssid_bytes = DBUS_MESSAGE_ITER_INIT_CLOSED;
    const char *ssids_key = "ssids";
    unsigned char ssid_copy[32];
    INT i;
    dbus_bool_t success;

    memcpy( ssid_copy, ssid->ucSSID, sizeof( ssid->ucSSID ) );

    success = p_dbus_message_iter_open_container( dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry );
    if (!success) return FALSE;

    success = p_dbus_message_iter_append_basic( &entry, DBUS_TYPE_STRING, &ssids_key );
    if (!success) goto failed;
    success = p_dbus_message_iter_open_container( &entry, DBUS_TYPE_VARIANT, "aay", &variant );
    if (!success) goto failed;

    success = p_dbus_message_iter_open_container( &variant, DBUS_TYPE_ARRAY, "ay", &ssids );
    if (!success) goto failed;
    success = p_dbus_message_iter_open_container( &ssids, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE_AS_STRING,
                                                  &ssid_bytes );
    if (!success) goto failed;
    for (i = 0; i < ssid->uSSIDLength; i++)
    {
        success = p_dbus_message_iter_append_basic( &ssid_bytes, DBUS_TYPE_BYTE, &ssid_copy[i] );
        if (!success) goto failed;
    }

    p_dbus_message_iter_close_container( &ssids, &ssid_bytes );
    p_dbus_message_iter_close_container( &variant, &ssids );
    p_dbus_message_iter_close_container( &entry, &variant );
    p_dbus_message_iter_close_container( dict, &entry );
    return TRUE;

 failed:
    p_dbus_message_iter_abandon_container_if_open( &ssids, &ssid_bytes );
    p_dbus_message_iter_abandon_container_if_open( &variant, &ssids );
    p_dbus_message_iter_abandon_container_if_open( &entry, &variant );
    p_dbus_message_iter_abandon_container_if_open( dict, &entry );
    return FALSE;
}

NTSTATUS networkmanager_start_scan( void *connection, const GUID *interface,
                                    const DOT11_SSID *ssid )
{
    DBusMessage *request, *reply;
    DBusMessageIter iter, options;
    DBusError error;
    dbus_bool_t success;
    char *device_path;

    TRACE( "(%p, %p, %p)\n", connection, debugstr_guid( interface ), ssid );

    if (!networkmanager_valid_device_guid( interface )) return STATUS_INVALID_PARAMETER;
    device_path = networkmanager_device_guid_to_path( interface );
    if (!device_path) return STATUS_NO_MEMORY;

    request =
        p_dbus_message_new_method_call( NETWORKMANAGER_SERVICE, device_path,
                                        NETWORKMANAGER_INTERFACE_DEVICE_WIRELESS, "RequestScan" );
    free( device_path );
    if (!request) return STATUS_NO_MEMORY;

    p_dbus_message_iter_init_append( request, &iter );
    success = p_dbus_message_iter_open_container( &iter, DBUS_TYPE_ARRAY, "{sv}", &options );
    if (!success)
    {
        p_dbus_message_unref( request );
        return STATUS_NO_MEMORY;
    }

    if (ssid)
    {
        assert( ssid->uSSIDLength <= sizeof( ssid->ucSSID ) );
        networkmanager_requestscan_call_set_ssid( &options, ssid );
    }
    p_dbus_message_iter_close_container( &iter, &options );

    p_dbus_error_init( &error );
    reply =
        p_dbus_connection_send_with_reply_and_block( connection, request, dbus_timeout, &error );
    p_dbus_message_unref( request );
    if (!reply)
    {
        NTSTATUS ret = dbus_error_to_ntstatus( &error );
        ERR( "Error calling RequestScan on interface %s: %s: %s.\n", debugstr_guid( interface ),
             debugstr_a( error.name ), debugstr_a( error.message ) );
        p_dbus_error_free( &error );
        return ret;
    }
    p_dbus_message_unref( reply );

    return STATUS_SUCCESS;
}

struct networkmanager_settings
{
    const char *id;
    dbus_bool_t autoconnect;
    const char *type;
    const char *interface;
};

static BOOL networkmanager_settings_get_section_dict( DBusMessage *getsettings_reply,
                                                      const char *name, DBusMessageIter *dict )
{
    DBusMessageIter iter, sections;

    p_dbus_message_iter_init( getsettings_reply, &iter );
    p_dbus_message_iter_recurse( &iter, &sections );
    while (p_dbus_message_iter_has_next( &sections ))
    {
        DBusMessageIter section;
        const char *section_name;

        p_dbus_message_iter_recurse( &sections, &section );
        p_dbus_message_iter_get_basic( &section, &section_name );
        if (!strcmp( section_name, name ))
        {
            p_dbus_message_iter_next( &section );
            p_dbus_message_iter_recurse( &section, dict );
            return TRUE;
        }
        p_dbus_message_iter_next( &sections );
    }

    return FALSE;
}

static BOOL networkmanager_read_settings( DBusMessage *getsettings_reply,
                                          struct networkmanager_settings *settings,
                                          const char *filter_id )
{
    DBusMessageIter dict, variant;
    const char *prop_name;

    if (networkmanager_settings_get_section_dict( getsettings_reply, "connection", &dict ))
    {
        settings->autoconnect = 1;

        while((prop_name = dbus_next_dict_entry( &dict, &variant )))
        {
            if (!strcmp( prop_name, "id" ) &&
                p_dbus_message_iter_get_arg_type( &variant ) == DBUS_TYPE_STRING)
                p_dbus_message_iter_get_basic( &variant, &settings->id );
            else if (!strcmp( prop_name, "autoconnect" ) &&
                     p_dbus_message_iter_get_arg_type( &variant ) == DBUS_TYPE_BOOLEAN)
                p_dbus_message_iter_get_basic( &variant, &settings->autoconnect );
            else if (!strcmp( prop_name, "type" ) &&
                     p_dbus_message_iter_get_arg_type( &variant ) == DBUS_TYPE_STRING)
                p_dbus_message_iter_get_basic( &variant, &settings->type );
            else if (!strcmp( prop_name, "interface-name" ) &&
                     p_dbus_message_iter_get_arg_type( &variant ) == DBUS_TYPE_STRING)
                p_dbus_message_iter_get_basic( &variant, &settings->interface );
        }
    }
    if (filter_id && !(settings->id && !strcmp(settings->id, filter_id)))
        return FALSE;

    return TRUE;
}

NTSTATUS networkmanager_wifi_device_get_setting_ids( void *connection, const GUID *device,
                                                     struct list *ids)
{
    DBusMessage *request, *reply;
    DBusError error;
    char **object_paths;
    int n_objects, i;
    dbus_bool_t success;
    char *device_path;
    struct unix_wlan_interface_info device_info = {0};

    if (!networkmanager_valid_device_guid( device )) return STATUS_INVALID_PARAMETER;
    device_path = networkmanager_device_guid_to_path( device );
    if (!device_path) return STATUS_NO_MEMORY;
    if (!networkmanager_wifi_device_get_info( connection, device_path, &device_info))
    {
        free( device_path );
        return STATUS_INTERNAL_ERROR;
    }
    free( device_path );

    request = p_dbus_message_new_method_call(
        NETWORKMANAGER_SERVICE, "/org/freedesktop/NetworkManager/Settings",
        NETWORKMANAGER_INTERFACE_SETTINGS, "ListConnections" );
    if (!request) return STATUS_NO_MEMORY;

    p_dbus_error_init( &error );
    reply =
        p_dbus_connection_send_with_reply_and_block( connection, request, dbus_timeout, &error );
    p_dbus_message_unref( request );
    if (!reply)
    {
        NTSTATUS ret = dbus_error_to_ntstatus( &error );
        ERR( "Could not get list of connections settings: %s: %s.\n", debugstr_a( error.name ),
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
        ERR( "Could not read object paths from ListConnections reply: %s: %s.\n",
             debugstr_a( error.name ), debugstr_a( error.message ) );
        p_dbus_error_free( &error );
        p_dbus_message_unref( reply );
        return ret;
    }

    p_dbus_error_free( &error );
    for (i = 0; i < n_objects; i++)
    {
        DBusMessage *getsettings_req, *getsettings_reply;
        const char *object_path = object_paths[i];
        struct networkmanager_settings settings = {0};

        getsettings_req = p_dbus_message_new_method_call(
            NETWORKMANAGER_SERVICE, object_path, NETWORKMANAGER_INTERFACE_SETTINGS_CONNECTION,
                                                         "GetSettings" );
        if (!getsettings_req) continue;
        p_dbus_error_init( &error );
        getsettings_reply = p_dbus_connection_send_with_reply_and_block( connection, getsettings_req,
                                                                         dbus_timeout, &error );
        p_dbus_message_unref( getsettings_req );
        if (!getsettings_reply)
        {
            ERR( "Could not get settings for %s: %s: %s.\n", debugstr_a( object_path ),
             debugstr_a( error.name ), debugstr_a( error.message ) );
            p_dbus_error_free( &error );
            continue;
        }
        p_dbus_error_free( &error );
        if (networkmanager_read_settings( getsettings_reply, &settings, NULL ) && settings.id &&
            settings.type && !strcmp( settings.type, "802-11-wireless" ) &&
            settings.interface && !strcmp ( settings.interface, device_info.description ))
        {
            struct wlan_profile *entry;
            SIZE_T len;

            entry = malloc( sizeof( *entry ) );
            if (!entry) continue;

            len = min( strlen( settings.id ), sizeof( entry->name ) - 1 );
            memcpy( entry->name, settings.id, len );
            entry->name[len] = '\0';
            list_add_tail( ids, &entry->entry );
        }
        p_dbus_message_unref( getsettings_reply );
    }

    p_dbus_free_string_array( object_paths );
    p_dbus_message_unref( reply );
    return STATUS_SUCCESS;
}

#else /* SONAME_LIBDBUS_1 */
BOOL load_dbus_functions( void ) { return FALSE; }
NTSTATUS init_dbus_connection( UINT_PTR *handle ) { return STATUS_NOT_SUPPORTED; }
void close_dbus_connection( void *c ) { return STATUS_NOT_SUPPORTED; }
NTSTATUS networkmanager_get_wifi_devices( void *connection, struct list *devices )
{
    return STATUS_NOT_SUPPORTED;
}
NTSTATUS networkmanager_get_access_points( void *connection, GUID device,
                                           struct list *access_points )
{
    return STATUS_NOT_SUPPORTED;
}
#endif

#define NM_802_11_MODE_UNKNOWN 0
#define NM_802_11_MODE_ADHOC   1
#define NM_802_11_MODE_INFRA   2
#define NM_802_11_MODE_AP      3
#define NM_802_11_MODE_MESH    4

#define NM_802_11_AP_FLAGS_NONE    0x00000000
#define NM_802_11_AP_FLAGS_PRIVACY 0x00000001
#define NM_802_11_AP_FLAGS_WPS     0x00000002
#define NM_802_11_AP_FLAGS_WPS_PBC 0x00000004
#define NM_802_11_AP_FLAGS_WPS_PIN 0x00000008

#define NM_802_11_AP_SEC_NONE                     0x00000000
#define NM_802_11_AP_SEC_PAIR_WEP40               0x00000001
#define NM_802_11_AP_SEC_PAIR_WEP104              0x00000002
#define NM_802_11_AP_SEC_PAIR_TKIP                0x00000004
#define NM_802_11_AP_SEC_PAIR_CCMP                0x00000008
#define NM_802_11_AP_SEC_GROUP_WEP40              0x00000010
#define NM_802_11_AP_SEC_GROUP_WEP104             0x00000020
#define NM_802_11_AP_SEC_GROUP_TKIP               0x00000040
#define NM_802_11_AP_SEC_GROUP_CCMP               0x00000080
#define NM_802_11_AP_SEC_KEY_MGMT_PSK             0x00000100
#define NM_802_11_AP_SEC_KEY_MGMT_802_1X          0x00000200
#define NM_802_11_AP_SEC_KEY_MGMT_SAE             0x00000400
#define NM_802_11_AP_SEC_KEY_MGMT_OWE             0x00000800
#define NM_802_11_AP_SEC_KEY_MGMT_OWE_TM          0x00001000
#define NM_802_11_AP_SEC_KEY_MGMT_EAP_SUITE_B_192 0x00002000

void wlan_bss_info_to_WLAN_AVAILABLE_NETWORK( const struct wlan_bss_info *info,
                                              WLAN_AVAILABLE_NETWORK *dest )
{
    memset( dest, 0, sizeof( *dest ) );

    memcpy( dest->dot11Ssid.ucSSID, info->ssid, sizeof( info->ssid ) );
    dest->dot11Ssid.uSSIDLength = info->ssid_len;
    dest->dot11BssType = info->mode == NM_802_11_MODE_INFRA ? dot11_BSS_type_infrastructure
                                                            : dot11_BSS_type_independent;
    dest->uNumberOfBssids = 1;
    dest->bNetworkConnectable = TRUE;
    dest->uNumberOfPhyTypes = 1;
    /* Use dot11_phy_type_any for now, as NetworkManager AccessPoints object do not have an equivalent
     * property. */
    dest->dot11PhyTypes[0] = dot11_phy_type_any;
    dest->bMorePhyTypes = FALSE;
    dest->wlanSignalQuality = info->strength;
    dest->bSecurityEnabled = !(info->flags & NM_802_11_AP_FLAGS_PRIVACY);

    if (info->rsn_flags)
    {
        if (info->rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_802_1X)
        {
            dest->dot11DefaultAuthAlgorithm = DOT11_AUTH_ALGO_RSNA;
            if (info->rsn_flags & NM_802_11_AP_SEC_GROUP_TKIP)
                dest->dot11DefaultCipherAlgorithm = DOT11_CIPHER_ALGO_TKIP;
            else if (info->rsn_flags & NM_802_11_AP_SEC_PAIR_CCMP)
                dest->dot11DefaultCipherAlgorithm = DOT11_CIPHER_ALGO_CCMP;
            else if (info->rsn_flags & (NM_802_11_AP_SEC_GROUP_TKIP | NM_802_11_AP_SEC_GROUP_CCMP))
                dest->dot11DefaultCipherAlgorithm = DOT11_CIPHER_ALGO_RSN_USE_GROUP;
        }
        if (info->rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_EAP_SUITE_B_192)
        {
            dest->dot11DefaultAuthAlgorithm = DOT11_AUTH_ALGO_WPA3_ENT_192;
            if (info->rsn_flags & NM_802_11_AP_SEC_GROUP_TKIP)
                dest->dot11DefaultCipherAlgorithm = DOT11_CIPHER_ALGO_TKIP;
            else if (info->rsn_flags & NM_802_11_AP_SEC_PAIR_CCMP)
                dest->dot11DefaultCipherAlgorithm = DOT11_CIPHER_ALGO_CCMP;
            else if (info->rsn_flags & (NM_802_11_AP_SEC_GROUP_TKIP | NM_802_11_AP_SEC_GROUP_CCMP))
                dest->dot11DefaultCipherAlgorithm = DOT11_CIPHER_ALGO_RSN_USE_GROUP;
        }
        if (info->rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_SAE)
        {
            dest->dot11DefaultAuthAlgorithm = DOT11_AUTH_ALGO_WPA3_SAE;
            dest->dot11DefaultCipherAlgorithm = info->rsn_flags & NM_802_11_AP_SEC_PAIR_TKIP
                                                    ? DOT11_CIPHER_ALGO_TKIP
                                                    : DOT11_CIPHER_ALGO_CCMP;
        }
        if (info->rsn_flags & (NM_802_11_AP_SEC_KEY_MGMT_OWE | NM_802_11_AP_SEC_KEY_MGMT_OWE_TM))
        {
            dest->dot11DefaultAuthAlgorithm = DOT11_AUTH_ALGO_OWE;
            dest->dot11DefaultCipherAlgorithm = info->rsn_flags & NM_802_11_AP_SEC_PAIR_TKIP
                                                    ? DOT11_CIPHER_ALGO_TKIP
                                                    : DOT11_CIPHER_ALGO_CCMP;
        }
    }
    else if (info->wpa_flags)
    {
        if (info->wpa_flags & NM_802_11_AP_SEC_KEY_MGMT_802_1X)
        {
            dest->dot11DefaultAuthAlgorithm = DOT11_AUTH_ALGO_WPA;
            if (info->wpa_flags & NM_802_11_AP_SEC_GROUP_TKIP)
                dest->dot11DefaultCipherAlgorithm = DOT11_CIPHER_ALGO_TKIP;
            else if (info->wpa_flags & NM_802_11_AP_SEC_PAIR_CCMP)
                dest->dot11DefaultCipherAlgorithm = DOT11_CIPHER_ALGO_CCMP;
            else if (info->wpa_flags & (NM_802_11_AP_SEC_GROUP_TKIP | NM_802_11_AP_SEC_GROUP_CCMP))
                dest->dot11DefaultCipherAlgorithm = DOT11_CIPHER_ALGO_WPA_USE_GROUP;
        }
        if (info->wpa_flags & (NM_802_11_AP_SEC_PAIR_WEP40 | NM_802_11_AP_SEC_PAIR_WEP104))
        {
            dest->dot11DefaultAuthAlgorithm = DOT11_AUTH_ALGO_80211_SHARED_KEY;
            dest->dot11DefaultCipherAlgorithm =
                info->wpa_flags & ( NM_802_11_AP_SEC_PAIR_WEP40 | NM_802_11_AP_SEC_GROUP_WEP40 )
                    ? DOT11_CIPHER_ALGO_WEP40
                    : DOT11_CIPHER_ALGO_WEP104;
        }
        if (info->wpa_flags & NM_802_11_AP_SEC_KEY_MGMT_PSK)
        {
            dest->dot11DefaultAuthAlgorithm = DOT11_AUTH_ALGO_WPA_PSK;
            if (info->wpa_flags & NM_802_11_AP_SEC_GROUP_TKIP)
                dest->dot11DefaultCipherAlgorithm = DOT11_CIPHER_ALGO_TKIP;
            else if (info->wpa_flags & NM_802_11_AP_SEC_PAIR_CCMP)
                dest->dot11DefaultCipherAlgorithm = DOT11_CIPHER_ALGO_CCMP;
            else if (info->wpa_flags & (NM_802_11_AP_SEC_GROUP_TKIP | NM_802_11_AP_SEC_GROUP_CCMP))
                dest->dot11DefaultCipherAlgorithm = DOT11_CIPHER_ALGO_WPA_USE_GROUP;
        }
    }

    if (info->connected)
        dest->dwFlags |= WLAN_AVAILABLE_NETWORK_CONNECTED;
}

void wlan_bss_info_to_WLAN_BSS_ENTRY( const struct wlan_bss_info *info, WLAN_BSS_ENTRY *dest )
{
    memset( dest, 0, sizeof( *dest ));

    FIXME( "(%p, %p) semi-stub\n", info, dest );
    memcpy( dest->dot11Ssid.ucSSID, info->ssid, sizeof( info->ssid ) );
    dest->dot11Ssid.uSSIDLength = info->ssid_len;

    memcpy( dest->dot11Bssid, info->hw_address, sizeof( info->hw_address ) );
    dest->dot11BssType = info->mode == NM_802_11_MODE_INFRA ? dot11_BSS_type_infrastructure
                                                            : dot11_BSS_type_independent;
    dest->uLinkQuality = info->strength;
    dest->bInRegDomain = TRUE;
    dest->usBeaconPeriod = 1;
}
