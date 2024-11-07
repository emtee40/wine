/*
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

#define COBJMACROS
#include <initguid.h>
#include <structuredquery.h>

#include <wine/debug.h>

WINE_DEFAULT_DEBUG_CHANNEL( structquery );

struct class_factory
{
    IClassFactory iface;
    LONG ref;
};

static inline struct class_factory *impl_from_IClassFactory( IClassFactory *iface )
{
    return CONTAINING_RECORD( iface, struct class_factory, iface );
}

static HRESULT WINAPI factory_QueryInterface( IClassFactory *iface, REFIID iid, void **out )
{
    TRACE( "(%p, %s, %p)\n", iface, debugstr_guid( iid ), out );
    *out = NULL;

    if (IsEqualGUID( &IID_IUnknown, iid ) ||
        IsEqualGUID( &IID_IClassFactory, iid ))
    {
        *out = iface;
        IClassFactory_AddRef( iface );
        return S_OK;
    }

    FIXME( "Interface not implemented, returning E_NOINTERFACE.\n" );
    return E_NOINTERFACE;
}

static ULONG WINAPI factory_AddRef( IClassFactory *iface )
{
    struct class_factory *impl = impl_from_IClassFactory( iface );
    TRACE( "(%p)\n", iface );
    return InterlockedIncrement( &impl->ref );
}

static ULONG WINAPI factory_Release( IClassFactory *iface )
{
    struct class_factory *impl = impl_from_IClassFactory( iface );
    ULONG ref;

    TRACE( "(%p)\n", iface );
    ref = InterlockedDecrement( &impl->ref );
    if (!ref)
        free( impl );
    return ref;
}

static HRESULT WINAPI factory_CreateInstance( IClassFactory *iface, IUnknown *outer, REFIID iid,
                                              void **out )
{
    FIXME( "(%p, %p, %s, %p) stub!\n", iface, outer, debugstr_guid( iid ), out );
    return E_NOTIMPL;
}

static HRESULT WINAPI factory_LockServer( IClassFactory *iface, BOOL lock )
{
    TRACE( "(%p, %d\n)", iface, lock );
    return S_OK;
}

const static IClassFactoryVtbl factory_vtbl =
{
    /* IUnknown */
    factory_QueryInterface,
    factory_AddRef,
    factory_Release,
    /* IClassFactory */
    factory_CreateInstance,
    factory_LockServer
};

static HRESULT factory_create( REFIID iid, void **obj )
{
    HRESULT hr;
    struct class_factory *impl;


    impl = calloc( 1, sizeof( *impl ) );
    if (!impl)
        return E_OUTOFMEMORY;
    impl->iface.lpVtbl = &factory_vtbl;
    impl->ref = 1;

    hr = IClassFactory_QueryInterface( &impl->iface, iid, obj );
    IClassFactory_Release( &impl->iface );

    return hr;
}

HRESULT WINAPI DllGetClassObject( REFCLSID clsid, REFIID iid, void **out )
{
    TRACE( "(%s, %s, %p)\n", debugstr_guid( clsid ), debugstr_guid( iid ), out );

    if (!clsid || !iid || !out)
        return E_INVALIDARG;

    *out = NULL;

    if (IsEqualCLSID( clsid, &CLSID_QueryParser ))
        return factory_create( iid, out );

    FIXME("Class not implemented, returning CLASS_E_CLASSNOTAVAILABLE.\n");
    return CLASS_E_CLASSNOTAVAILABLE;
}
