/* WinRT Windows.Gaming.Input implementation
 *
 * Copyright 2022 Rémi Bernon for CodeWeavers
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

#include "private.h"

#include "initguid.h"
#include "ddk/hidsdi.h"
#include "dinput.h"
#include "provider.h"
#include "hidusage.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(input);

DEFINE_GUID( device_path_guid, 0x00000000, 0x0000, 0x0000, 0x8d, 0x4a, 0x23, 0x90, 0x3f, 0xb6, 0xbd, 0xf8 );

static CRITICAL_SECTION provider_cs;
static CRITICAL_SECTION_DEBUG provider_cs_debug =
{
    0, 0, &provider_cs,
    { &provider_cs_debug.ProcessLocksList, &provider_cs_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": provider_cs") }
};
static CRITICAL_SECTION provider_cs = { &provider_cs_debug, -1, 0, 0, 0, 0 };

static struct list provider_list = LIST_INIT( provider_list );

struct provider
{
    IWineGameControllerProvider IWineGameControllerProvider_iface;
    IGameControllerProvider IGameControllerProvider_iface;
    IAgileObject IAgileObject_iface;
    const WCHAR *class_name;
    LONG refcount;

    IDirectInputDevice8W *dinput_device;
    WCHAR device_path[MAX_PATH];
    struct list entry;

    struct WineGameControllerVibration vibration;

    char *report_buf;
    PHIDP_PREPARSED_DATA preparsed;
    HIDP_VALUE_CAPS haptics_rumble_caps;
    HIDP_VALUE_CAPS haptics_buzz_caps;
    HIDP_VALUE_CAPS haptics_left_caps;
    HIDP_VALUE_CAPS haptics_right_caps;
    BYTE haptics_report;
    HIDP_CAPS caps;
    HANDLE device;
};

static void provider_destroy( struct provider *impl )
{
    IDirectInputDevice8_Release( impl->dinput_device );
    HidD_FreePreparsedData( impl->preparsed );
    CloseHandle( impl->device );
    free( impl->report_buf );
    free( impl );
}

INTERFACE_IMPL_IWineGameControllerProvider( provider, IGameControllerProvider, IAgileObject, END );

static BOOL CALLBACK count_ffb_axes( const DIDEVICEOBJECTINSTANCEW *obj, void *args )
{
    DWORD *count = args;
    if (obj->dwType & DIDFT_FFACTUATOR) (*count)++;
    return DIENUM_CONTINUE;
}

static HRESULT WINAPI provider_get_Type( IWineGameControllerProvider *iface, WineGameControllerType *value )
{
    struct provider *impl = provider_from_IWineGameControllerProvider( iface );
    DIDEVICEINSTANCEW instance = {.dwSize = sizeof(DIDEVICEINSTANCEW)};
    HRESULT hr;

    TRACE( "iface %p, value %p.\n", iface, value );

    if (FAILED(hr = IDirectInputDevice8_GetDeviceInfo( impl->dinput_device, &instance ))) return hr;

    switch (GET_DIDEVICE_TYPE( instance.dwDevType ))
    {
    case DI8DEVTYPE_DRIVING: *value = WineGameControllerType_RacingWheel; break;
    case DI8DEVTYPE_GAMEPAD: *value = WineGameControllerType_Gamepad; break;
    default:
    {
        DWORD count = 0;
        hr = IDirectInputDevice8_EnumObjects( impl->dinput_device, count_ffb_axes, &count, DIDFT_AXIS );
        if (SUCCEEDED(hr) && count == 1) *value = WineGameControllerType_RacingWheel;
        else *value = WineGameControllerType_Joystick;
        break;
    }
    }

    return S_OK;
}

static HRESULT WINAPI provider_get_AxisCount( IWineGameControllerProvider *iface, INT32 *value )
{
    struct provider *impl = provider_from_IWineGameControllerProvider( iface );
    DIDEVCAPS caps = {.dwSize = sizeof(DIDEVCAPS)};
    HRESULT hr;

    TRACE( "iface %p, value %p.\n", iface, value );

    if (SUCCEEDED(hr = IDirectInputDevice8_GetCapabilities( impl->dinput_device, &caps )))
        *value = caps.dwAxes;
    return hr;
}

static HRESULT WINAPI provider_get_ButtonCount( IWineGameControllerProvider *iface, INT32 *value )
{
    struct provider *impl = provider_from_IWineGameControllerProvider( iface );
    DIDEVCAPS caps = {.dwSize = sizeof(DIDEVCAPS)};
    HRESULT hr;

    TRACE( "iface %p, value %p.\n", iface, value );

    if (SUCCEEDED(hr = IDirectInputDevice8_GetCapabilities( impl->dinput_device, &caps )))
        *value = caps.dwButtons;
    return hr;
}

static HRESULT WINAPI provider_get_SwitchCount( IWineGameControllerProvider *iface, INT32 *value )
{
    struct provider *impl = provider_from_IWineGameControllerProvider( iface );
    DIDEVCAPS caps = {.dwSize = sizeof(DIDEVCAPS)};
    HRESULT hr;

    TRACE( "iface %p, value %p.\n", iface, value );

    if (SUCCEEDED(hr = IDirectInputDevice8_GetCapabilities( impl->dinput_device, &caps )))
        *value = caps.dwPOVs;
    return hr;
}

static HRESULT WINAPI provider_get_State( IWineGameControllerProvider *iface, struct WineGameControllerState *out )
{
    struct provider *impl = provider_from_IWineGameControllerProvider( iface );
    DIJOYSTATE2 state = {0};
    UINT32 i = 0;
    HRESULT hr;

    TRACE( "iface %p, out %p.\n", iface, out );

    if (FAILED(hr = IDirectInputDevice8_GetDeviceState( impl->dinput_device, sizeof(state), &state )))
    {
        WARN( "Failed to read device state, hr %#lx\n", hr );
        return S_OK;
    }

    i = ARRAY_SIZE(state.rgbButtons);
    while (i--) out->buttons[i] = (state.rgbButtons[i] != 0);

    i = ARRAY_SIZE(state.rgdwPOV);
    while (i--)
    {
        if (state.rgdwPOV[i] == ~0) out->switches[i] = GameControllerSwitchPosition_Center;
        else out->switches[i] = state.rgdwPOV[i] * 8 / 36000 + 1;
    }

    i = 0;
    out->axes[i++] = state.lX / 65535.;
    out->axes[i++] = state.lY / 65535.;
    out->axes[i++] = state.lZ / 65535.;
    out->axes[i++] = state.lRx / 65535.;
    out->axes[i++] = state.lRy / 65535.;
    out->axes[i++] = state.lRz / 65535.;
    out->axes[i++] = state.rglSlider[0] / 65535.;
    out->axes[i++] = state.rglSlider[1] / 65535.;
    out->axes[i++] = state.lVX / 65535.;
    out->axes[i++] = state.lVY / 65535.;
    out->axes[i++] = state.lVZ / 65535.;
    out->axes[i++] = state.lVRx / 65535.;
    out->axes[i++] = state.lVRy / 65535.;
    out->axes[i++] = state.lVRz / 65535.;
    out->axes[i++] = state.rglVSlider[0] / 65535.;
    out->axes[i++] = state.rglVSlider[1] / 65535.;
    out->axes[i++] = state.lAX / 65535.;
    out->axes[i++] = state.lAY / 65535.;
    out->axes[i++] = state.lAZ / 65535.;
    out->axes[i++] = state.lARx / 65535.;
    out->axes[i++] = state.lARy / 65535.;
    out->axes[i++] = state.lARz / 65535.;
    out->axes[i++] = state.rglASlider[0] / 65535.;
    out->axes[i++] = state.rglASlider[1] / 65535.;
    out->axes[i++] = state.lFX / 65535.;
    out->axes[i++] = state.lFY / 65535.;
    out->axes[i++] = state.lFZ / 65535.;
    out->axes[i++] = state.lFRx / 65535.;
    out->axes[i++] = state.lFRy / 65535.;
    out->axes[i++] = state.lFRz / 65535.;
    out->axes[i++] = state.rglFSlider[0] / 65535.;
    out->axes[i++] = state.rglFSlider[1] / 65535.;
    out->timestamp = GetTickCount64();

    return S_OK;
}

static HRESULT WINAPI provider_get_Vibration( IWineGameControllerProvider *iface, struct WineGameControllerVibration *out )
{
    struct provider *impl = provider_from_IWineGameControllerProvider( iface );
    TRACE( "iface %p, out %p.\n", iface, out );
    *out = impl->vibration;
    return S_OK;
}

static HRESULT WINAPI provider_put_Vibration( IWineGameControllerProvider *iface, struct WineGameControllerVibration value )
{
    struct provider *impl = provider_from_IWineGameControllerProvider( iface );
    ULONG report_len = impl->caps.OutputReportByteLength;
    PHIDP_PREPARSED_DATA preparsed = impl->preparsed;
    char *report_buf = impl->report_buf;
    USHORT collection;
    NTSTATUS status;
    BOOL ret;

    TRACE( "iface %p, value %p.\n", iface, &value );

    if (!memcmp( &impl->vibration, &value, sizeof(value) )) return S_OK;
    impl->vibration = value;

    status = HidP_InitializeReportForID( HidP_Output, impl->haptics_report, preparsed, report_buf, report_len );
    if (status != HIDP_STATUS_SUCCESS) WARN( "HidP_InitializeReportForID returned %#lx\n", status );

    collection = impl->haptics_rumble_caps.LinkCollection;
    status = HidP_SetUsageValue( HidP_Output, HID_USAGE_PAGE_HAPTICS, collection, HID_USAGE_HAPTICS_INTENSITY,
                                 impl->vibration.rumble, preparsed, report_buf, report_len );
    if (status != HIDP_STATUS_SUCCESS) WARN( "HidP_SetUsageValue INTENSITY returned %#lx\n", status );

    collection = impl->haptics_buzz_caps.LinkCollection;
    status = HidP_SetUsageValue( HidP_Output, HID_USAGE_PAGE_HAPTICS, collection, HID_USAGE_HAPTICS_INTENSITY,
                                 impl->vibration.buzz, preparsed, report_buf, report_len );
    if (status != HIDP_STATUS_SUCCESS) WARN( "HidP_SetUsageValue INTENSITY returned %#lx\n", status );

    collection = impl->haptics_left_caps.LinkCollection;
    status = HidP_SetUsageValue( HidP_Output, HID_USAGE_PAGE_HAPTICS, collection, HID_USAGE_HAPTICS_INTENSITY,
                                 impl->vibration.left, preparsed, report_buf, report_len );
    if (status != HIDP_STATUS_SUCCESS) WARN( "HidP_SetUsageValue INTENSITY returned %#lx\n", status );

    collection = impl->haptics_right_caps.LinkCollection;
    status = HidP_SetUsageValue( HidP_Output, HID_USAGE_PAGE_HAPTICS, collection, HID_USAGE_HAPTICS_INTENSITY,
                                 impl->vibration.right, preparsed, report_buf, report_len );
    if (status != HIDP_STATUS_SUCCESS) WARN( "HidP_SetUsageValue INTENSITY returned %#lx\n", status );

    ret = HidD_SetOutputReport( impl->device, report_buf, report_len );
    if (!ret) WARN( "HidD_SetOutputReport failed with error %lu\n", GetLastError() );

    return S_OK;
}

static HRESULT WINAPI provider_get_ForceFeedbackMotor( IWineGameControllerProvider *iface, IForceFeedbackMotor **value )
{
    struct provider *impl = provider_from_IWineGameControllerProvider( iface );
    DIDEVCAPS caps = {.dwSize = sizeof(DIDEVCAPS)};
    HRESULT hr;

    TRACE( "iface %p, value %p.\n", iface, value );

    if (SUCCEEDED(hr = IDirectInputDevice8_GetCapabilities( impl->dinput_device, &caps )) && (caps.dwFlags & DIDC_FORCEFEEDBACK))
        return force_feedback_motor_create( impl->dinput_device, value );

    *value = NULL;
    return S_OK;
}

INTERFACE_VTBL_IWineGameControllerProvider( provider );

static HRESULT WINAPI provider_IGameControllerProvider_get_FirmwareVersionInfo( IGameControllerProvider *iface, GameControllerVersionInfo *value )
{
    FIXME( "iface %p, value %p stub!\n", iface, value );
    return E_NOTIMPL;
}

static HRESULT WINAPI provider_IGameControllerProvider_get_HardwareProductId( IGameControllerProvider *iface, UINT16 *value )
{
    DIPROPDWORD vid_pid = {.diph = {.dwHeaderSize = sizeof(DIPROPHEADER), .dwSize = sizeof(DIPROPDWORD)}};
    struct provider *impl = provider_from_IGameControllerProvider( iface );
    HRESULT hr;

    TRACE( "iface %p, value %p.\n", iface, value );

    if (SUCCEEDED(hr = IDirectInputDevice8_GetProperty( impl->dinput_device, DIPROP_VIDPID, &vid_pid.diph )))
        *value = HIWORD(vid_pid.dwData);
    return hr;
}

static HRESULT WINAPI provider_IGameControllerProvider_get_HardwareVendorId( IGameControllerProvider *iface, UINT16 *value )
{
    DIPROPDWORD vid_pid = {.diph = {.dwHeaderSize = sizeof(DIPROPHEADER), .dwSize = sizeof(DIPROPDWORD)}};
    struct provider *impl = provider_from_IGameControllerProvider( iface );
    HRESULT hr;

    TRACE( "iface %p, value %p.\n", iface, value );

    if (SUCCEEDED(hr = IDirectInputDevice8_GetProperty( impl->dinput_device, DIPROP_VIDPID, &vid_pid.diph )))
        *value = LOWORD(vid_pid.dwData);
    return hr;
}

static HRESULT WINAPI provider_IGameControllerProvider_get_HardwareVersionInfo( IGameControllerProvider *iface, GameControllerVersionInfo *value )
{
    FIXME( "iface %p, value %p stub!\n", iface, value );
    return E_NOTIMPL;
}

static HRESULT WINAPI provider_IGameControllerProvider_get_IsConnected( IGameControllerProvider *iface, boolean *value )
{
    FIXME( "iface %p, value %p stub!\n", iface, value );
    return E_NOTIMPL;
}

INTERFACE_VTBL_IGameControllerProvider( provider_IGameControllerProvider );
INTERFACE_VTBL_IAgileObject( provider_IAgileObject );

static void check_haptics_caps( struct provider *provider, HANDLE device, PHIDP_PREPARSED_DATA preparsed,
                                HIDP_LINK_COLLECTION_NODE *collections, HIDP_VALUE_CAPS *caps )
{
    USHORT count, report_len = provider->caps.FeatureReportByteLength;
    ULONG parent = caps->LinkCollection, waveform = 0;
    char *report_buf = provider->report_buf;
    HIDP_VALUE_CAPS value_caps;
    USAGE_AND_PAGE phy_usages;
    NTSTATUS status;

    while (collections[parent].LinkUsagePage != HID_USAGE_PAGE_HAPTICS ||
           collections[parent].LinkUsage != HID_USAGE_HAPTICS_SIMPLE_CONTROLLER)
        if (!(parent = collections[parent].Parent)) break;

    if (collections[parent].LinkUsagePage != HID_USAGE_PAGE_HAPTICS ||
        collections[parent].LinkUsage != HID_USAGE_HAPTICS_SIMPLE_CONTROLLER)
    {
        WARN( "Failed to find haptics simple controller collection\n" );
        return;
    }
    phy_usages.UsagePage = collections[collections[parent].Parent].LinkUsagePage;
    phy_usages.Usage = collections[collections[parent].Parent].LinkUsage;

    status = HidP_InitializeReportForID( HidP_Feature, caps->ReportID, preparsed, report_buf, report_len );
    if (status != HIDP_STATUS_SUCCESS) WARN( "HidP_InitializeReportForID returned %#lx\n", status );
    if (!HidD_GetFeature( device, report_buf, report_len ))
    {
        WARN( "Failed to get waveform list report, error %lu\n", GetLastError() );
        return;
    }

    status = HidP_GetUsageValue( HidP_Feature, caps->UsagePage, caps->LinkCollection,
                                 caps->NotRange.Usage, &waveform, preparsed, report_buf, report_len );
    if (status != HIDP_STATUS_SUCCESS) WARN( "HidP_GetUsageValue returned %#lx\n", status );

    count = 1;
    status = HidP_GetSpecificValueCaps( HidP_Output, HID_USAGE_PAGE_HAPTICS, parent,
                                        HID_USAGE_HAPTICS_INTENSITY, &value_caps, &count, preparsed );
    if (status != HIDP_STATUS_SUCCESS || !count) WARN( "Failed to get waveform intensity caps, status %#lx\n", status );
    else if (phy_usages.UsagePage == HID_USAGE_PAGE_GENERIC && phy_usages.Usage == HID_USAGE_GENERIC_Z)
    {
        TRACE( "Found left rumble caps, report %u collection %u\n", value_caps.ReportID, value_caps.LinkCollection );
        provider->haptics_report = value_caps.ReportID;
        provider->haptics_left_caps = value_caps;
    }
    else if (phy_usages.UsagePage == HID_USAGE_PAGE_GENERIC && phy_usages.Usage == HID_USAGE_GENERIC_RZ)
    {
        TRACE( "Found right rumble caps, report %u collection %u\n", value_caps.ReportID, value_caps.LinkCollection );
        provider->haptics_report = value_caps.ReportID;
        provider->haptics_right_caps = value_caps;
    }
    else if (waveform == HID_USAGE_HAPTICS_WAVEFORM_RUMBLE)
    {
        TRACE( "Found rumble caps, report %u collection %u\n", value_caps.ReportID, value_caps.LinkCollection );
        provider->haptics_report = value_caps.ReportID;
        provider->haptics_rumble_caps = value_caps;
    }
    else if (waveform == HID_USAGE_HAPTICS_WAVEFORM_BUZZ)
    {
        TRACE( "Found buzz caps, report %u collection %u\n", value_caps.ReportID, value_caps.LinkCollection );
        provider->haptics_report = value_caps.ReportID;
        provider->haptics_buzz_caps = value_caps;
    }
    else FIXME( "Unsupported waveform type %#lx\n", waveform );
}

static void open_haptics_device( struct provider *provider )
{
    HIDP_LINK_COLLECTION_NODE *collections;
    PHIDP_PREPARSED_DATA preparsed = NULL;
    ULONG i, size, coll_count = 0;
    USHORT count, caps_count = 0;
    HIDP_VALUE_CAPS caps[8];
    NTSTATUS status;
    HANDLE device;

    device = CreateFileW( provider->device_path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                          NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED | FILE_FLAG_NO_BUFFERING, 0 );
    if (device == INVALID_HANDLE_VALUE) return;

    if (!HidD_GetPreparsedData( device, &preparsed )) goto failed;
    if (HidP_GetCaps( preparsed, &provider->caps ) != HIDP_STATUS_SUCCESS) goto failed;

    size = max( provider->caps.OutputReportByteLength, provider->caps.FeatureReportByteLength );
    if (!(provider->report_buf = malloc( size ))) goto failed;

    coll_count = provider->caps.NumberLinkCollectionNodes;
    if (!(collections = malloc( sizeof(*collections) * coll_count ))) goto failed;

    status = HidP_GetLinkCollectionNodes( collections, &coll_count, preparsed );
    if (status != HIDP_STATUS_SUCCESS) WARN( "HidP_GetLinkCollectionNodes returned %#lx\n", status );
    else for (i = 0; i < coll_count; ++i)
    {
        if (collections[i].LinkUsagePage != HID_USAGE_PAGE_HAPTICS) continue;
        if (collections[i].LinkUsage == HID_USAGE_HAPTICS_WAVEFORM_LIST)
        {
            count = ARRAY_SIZE(caps) - caps_count;
            status = HidP_GetSpecificValueCaps( HidP_Feature, HID_USAGE_PAGE_ORDINAL, i, 0,
                                                caps + caps_count, &count, preparsed );
            if (status == HIDP_STATUS_SUCCESS) caps_count += count;
        }
    }
    for (i = 0; i < caps_count; ++i) check_haptics_caps( provider, device, preparsed, collections, caps + i );
    free( collections );

    provider->preparsed = preparsed;
    provider->device = device;
    return;

failed:
    free( provider->report_buf );
    provider->report_buf = NULL;
    HidD_FreePreparsedData( preparsed );
    CloseHandle( device );
}

void provider_create( const WCHAR *device_path )
{
    IDirectInputDevice8W *dinput_device;
    IGameControllerProvider *provider;
    struct provider *impl, *entry;
    GUID guid = device_path_guid;
    IDirectInput8W *dinput;
    BOOL found = FALSE;
    const WCHAR *tmp;
    HRESULT hr;

    if (wcsnicmp( device_path, L"\\\\?\\HID#", 8 )) return;
    if ((tmp = wcschr( device_path + 8, '#' )) && !wcsnicmp( tmp - 6, L"&IG_", 4 )) return;

    TRACE( "device_path %s\n", debugstr_w( device_path ) );

    *(const WCHAR **)&guid = device_path;
    if (FAILED(DirectInput8Create( windows_gaming_input, DIRECTINPUT_VERSION, &IID_IDirectInput8W,
                                   (void **)&dinput, NULL ))) return;
    hr = IDirectInput8_CreateDevice( dinput, &guid, &dinput_device, NULL );
    IDirectInput8_Release( dinput );
    if (FAILED(hr)) return;

    if (FAILED(hr = IDirectInputDevice8_SetCooperativeLevel( dinput_device, 0, DISCL_BACKGROUND | DISCL_NONEXCLUSIVE ))) goto done;
    if (FAILED(hr = IDirectInputDevice8_SetDataFormat( dinput_device, &c_dfDIJoystick2 ))) goto done;
    if (FAILED(hr = IDirectInputDevice8_Acquire( dinput_device ))) goto done;

    if (!(impl = calloc( 1, sizeof(*impl) ))) goto done;
    impl->IWineGameControllerProvider_iface.lpVtbl = &provider_vtbl;
    impl->IGameControllerProvider_iface.lpVtbl = &provider_IGameControllerProvider_vtbl;
    impl->IAgileObject_iface.lpVtbl = &provider_IAgileObject_vtbl;
    IDirectInputDevice_AddRef( dinput_device );
    impl->dinput_device = dinput_device;
    impl->refcount = 1;

    wcscpy( impl->device_path, device_path );
    list_init( &impl->entry );
    open_haptics_device( impl );

    provider = &impl->IGameControllerProvider_iface;
    TRACE( "created WineGameControllerProvider %p\n", provider );

    EnterCriticalSection( &provider_cs );
    LIST_FOR_EACH_ENTRY( entry, &provider_list, struct provider, entry )
        if ((found = !wcsicmp( entry->device_path, device_path ))) break;
    if (!found) list_add_tail( &provider_list, &impl->entry );
    LeaveCriticalSection( &provider_cs );

    if (found) IGameControllerProvider_Release( provider );
    else manager_on_provider_created( provider );
done:
    IDirectInputDevice_Release( dinput_device );
}

void provider_remove( const WCHAR *device_path )
{
    IGameControllerProvider *provider;
    struct provider *entry;
    BOOL found = FALSE;

    TRACE( "device_path %s\n", debugstr_w( device_path ) );

    EnterCriticalSection( &provider_cs );
    LIST_FOR_EACH_ENTRY( entry, &provider_list, struct provider, entry )
        if ((found = !wcsicmp( entry->device_path, device_path ))) break;
    if (found) list_remove( &entry->entry );
    LeaveCriticalSection( &provider_cs );

    if (!found) WARN( "provider not found for device %s\n", debugstr_w( device_path ) );
    else
    {
        provider = &entry->IGameControllerProvider_iface;
        manager_on_provider_removed( provider );
        IGameControllerProvider_Release( provider );
    }
}
