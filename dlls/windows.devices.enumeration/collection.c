/* DeviceInformationCollection implementation
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

#include "private.h"
#include "windows.foundation.collections.h"

#include <wine/debug.h>

WINE_DEFAULT_DEBUG_CHANNEL(enumeration);

struct vectorview_DeviceInformation
{
    IVectorView_DeviceInformation IVectorView_DeviceInformation_iface;

    IDeviceInformation **devices;
    SIZE_T len;

    LONG ref;
};

static inline struct vectorview_DeviceInformation *
impl_from_IVectorView_DeviceInformation( IVectorView_DeviceInformation *iface )
{
    return CONTAINING_RECORD( iface, struct vectorview_DeviceInformation, IVectorView_DeviceInformation_iface );
}

static HRESULT STDMETHODCALLTYPE vectorview_DeviceInformation_QueryInterface(
    IVectorView_DeviceInformation *iface, REFIID iid, void **out )
{
    TRACE( "(%p, %s, %p)\n", iface, debugstr_guid( iid ), out );

    if (IsEqualGUID( iid, &IID_IUnknown ) ||
        IsEqualGUID( iid, &IID_IInspectable ) ||
        IsEqualGUID( iid, &IID_IAgileObject ) ||
        IsEqualGUID( iid, &IID_IVectorView_DeviceInformation ))
    {
        IUnknown_AddRef( iface );
        *out = iface;
        return S_OK;
    }

    FIXME( "%s not implemented, returning E_NOINTERFACE.\n", debugstr_guid( iid ) );
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE vectorview_DeviceInformation_AddRef( IVectorView_DeviceInformation *iface )
{
    struct vectorview_DeviceInformation *impl;

    TRACE( "(%p)\n", iface );

    impl = impl_from_IVectorView_DeviceInformation( iface );
    return InterlockedIncrement( &impl->ref );
}

static ULONG STDMETHODCALLTYPE vectorview_DeviceInformation_Release( IVectorView_DeviceInformation *iface )
{
    struct vectorview_DeviceInformation *impl;
    ULONG ref;

    TRACE( "(%p)\n", iface );

    impl = impl_from_IVectorView_DeviceInformation( iface );
    ref = InterlockedDecrement( &impl->ref );
    if (!ref)
    {
        while (impl->len--)
            IDeviceInformation_Release( impl->devices[impl->len] );
        free( impl->devices );
        free( impl );
    }
    return ref;
}

static HRESULT STDMETHODCALLTYPE vectorview_DeviceInformation_GetIids( IVectorView_DeviceInformation *iface,
                                                                       ULONG *iid_count, IID **iids )
{
    FIXME( "(%p, %p, %p) stub!\n", iface, iid_count, iids );
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE vectorview_DeviceInformation_GetRuntimeClassName( IVectorView_DeviceInformation *iface,
                                                                                   HSTRING *class_name )
{
    const static WCHAR name[] = L"Windows.Foundation.Collections.IVectorView`1<Windows.Devices.Enumeration.DeviceInformation>";
    TRACE( "(%p, %p)\n", iface, class_name );
    return WindowsCreateString( name, ARRAY_SIZE( name ), class_name );
}

static HRESULT STDMETHODCALLTYPE vectorview_DeviceInformation_GetTrustLevel( IVectorView_DeviceInformation *iface,
                                                                             TrustLevel *trust_level )
{
    FIXME( "(%p, %p) stub!\n", iface, trust_level);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE vectorview_DeviceInformation_GetAt( IVectorView_DeviceInformation *iface, UINT32 index,
                                                                     IDeviceInformation **value )
{
    struct vectorview_DeviceInformation *impl;

    TRACE( "(%p, %u, %p)\n", iface, index, value );

    impl = impl_from_IVectorView_DeviceInformation( iface );
    *value = NULL;
    if (index >= impl->len)
        return E_BOUNDS;
    *value = impl->devices[index];
    IDeviceInformation_AddRef( *value );
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE vectorview_DeviceInformation_get_Size( IVectorView_DeviceInformation *iface,
                                                                        UINT32 *value )
{
    struct vectorview_DeviceInformation *impl;

    TRACE( "(%p, %p)\n", iface, value );

    impl = impl_from_IVectorView_DeviceInformation( iface );
    *value = impl->len;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE vectorview_DeviceInformation_IndexOf( IVectorView_DeviceInformation *iface,
                                                                       IDeviceInformation *elem, UINT32 *index,
                                                                       boolean *found )
{
    FIXME( "(%p, %p, %p, %p) stub!\n", iface, elem, index, found );
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE vectorview_DeviceInformation_GetMany( IVectorView_DeviceInformation *iface,
                                                                       UINT32 start, UINT32 size,
                                                                       IDeviceInformation **items, UINT32 *copied )
{
    FIXME( "(%p, %u, %u, %p, %p) stub!\n", iface, start, size, items, copied );
    return E_NOTIMPL;
}

const static IVectorView_DeviceInformationVtbl vectorview_DeviceInformation_vtbl =
{
    /* IUnknown */
    vectorview_DeviceInformation_QueryInterface,
    vectorview_DeviceInformation_AddRef,
    vectorview_DeviceInformation_Release,
    /* IInspectable */
    vectorview_DeviceInformation_GetIids,
    vectorview_DeviceInformation_GetRuntimeClassName,
    vectorview_DeviceInformation_GetTrustLevel,
    /* IVectorView<DeviceInformation> */
    vectorview_DeviceInformation_GetAt,
    vectorview_DeviceInformation_get_Size,
    vectorview_DeviceInformation_IndexOf,
    vectorview_DeviceInformation_GetMany
};

HRESULT vectorview_deviceinformation_create( IDeviceInformation **devices, SIZE_T len,
                                             IVectorView_DeviceInformation **view )
{
    struct vectorview_DeviceInformation *impl;

    impl = calloc( 1, sizeof( *impl ) );
    if (!impl)
        return E_OUTOFMEMORY;

    impl->IVectorView_DeviceInformation_iface.lpVtbl = &vectorview_DeviceInformation_vtbl;
    impl->devices = devices;
    impl->len = len;
    impl->ref = 1;
    *view = &impl->IVectorView_DeviceInformation_iface;
    return S_OK;
}
