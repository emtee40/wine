/* CryptoWinRT Implementation
 *
 * Copyright 2022 Bernhard Kölbl for CodeWeavers
 * Copyright 2022 Rémi Bernon for CodeWeavers
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

#include "roapi.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(crypto);

/* A type-pruning variant of IAsyncOperationCompletedHandler<T> */
struct async_completed
{
    IAsyncActionCompletedHandler IAsyncActionCompletedHandler_iface;
    IInspectable *inner_handler;
    IInspectable *inner_action;
    LONG ref;
};

static inline struct async_completed *impl_from_IAsyncActionCompletedHandler( IAsyncActionCompletedHandler *iface )
{
    return CONTAINING_RECORD( iface, struct async_completed, IAsyncActionCompletedHandler_iface );
}

static HRESULT WINAPI async_completed_QueryInterface( IAsyncActionCompletedHandler *iface, REFIID iid, void **out )
{
    struct async_completed *impl = impl_from_IAsyncActionCompletedHandler( iface );

    TRACE( "iface %p, iid %s, out %p.\n", iface, debugstr_guid( iid ), out );

    if (IsEqualGUID( iid, &IID_IUnknown ) ||
        IsEqualGUID( iid, &IID_IInspectable ) ||
        IsEqualGUID( iid, &IID_IAsyncActionCompletedHandler ))
    {
        *out = iface;
        IUnknown_AddRef((IUnknown *)*out);
        return S_OK;
    }

    return IInspectable_QueryInterface( impl->inner_handler, iid, out );
}

static ULONG WINAPI async_completed_AddRef( IAsyncActionCompletedHandler *iface )
{
    struct async_completed *impl = impl_from_IAsyncActionCompletedHandler( iface );
    ULONG ref = InterlockedIncrement( &impl->ref );
    TRACE( "iface %p, ref %lu.\n", iface, ref );
    return ref;
}

static ULONG WINAPI async_completed_Release( IAsyncActionCompletedHandler *iface )
{
    struct async_completed *impl = impl_from_IAsyncActionCompletedHandler( iface );
    ULONG ref = InterlockedDecrement( &impl->ref );
    TRACE( "iface %p, ref %lu.\n", iface, ref );

    if (!ref)
    {
        IInspectable_Release( impl->inner_handler );
        IInspectable_Release( impl->inner_action );
        free( impl );
    }

    return ref;
}

static HRESULT WINAPI async_completed_Invoke( IAsyncActionCompletedHandler *iface, IAsyncAction *info,
                                              AsyncStatus status )
{
    struct async_completed *impl = impl_from_IAsyncActionCompletedHandler( iface );
    IAsyncActionCompletedHandler *handler = (IAsyncActionCompletedHandler *)impl->inner_handler;
    IAsyncAction *action = (IAsyncAction *)impl->inner_action;

    return IAsyncActionCompletedHandler_Invoke( handler, action, status );
}

static const IAsyncActionCompletedHandlerVtbl async_completed_vtbl =
{
    async_completed_QueryInterface,
    async_completed_AddRef,
    async_completed_Release,
    async_completed_Invoke,
};

static HRESULT async_completed_create( IInspectable *inner_action, IInspectable *inner_handler, IAsyncActionCompletedHandler **handler )
{
    struct async_completed *impl;

    impl = calloc( 1, sizeof( *impl ) );
    if (!impl)
        return E_NOINTERFACE;

    impl->IAsyncActionCompletedHandler_iface.lpVtbl = &async_completed_vtbl;
    impl->inner_action = inner_action;
    impl->inner_handler = inner_handler;
    IInspectable_AddRef( impl->inner_action );
    IInspectable_AddRef( impl->inner_handler );
    impl->ref = 1;

    *handler = &impl->IAsyncActionCompletedHandler_iface;
    return S_OK;
}

struct async_operation_base
{
    IWorkItemHandler *work_item;
    IAsyncAction *inner_action;
    PROPVARIANT result;
    LONG ref;
};

static HRESULT async_operation_put_Completed( struct async_operation_base *base, IInspectable *action, void *handler )
{
    IAsyncActionCompletedHandler *wrapper;
    HRESULT hr;

    hr = async_completed_create( (IInspectable *)action, (IInspectable *)handler, &wrapper );
    if (FAILED( hr ))
        return hr;
    hr = IAsyncAction_put_Completed( base->inner_action, wrapper );
    IAsyncActionCompletedHandler_Release( wrapper );
    return hr;
}

static HRESULT async_operation_get_Completed( struct async_operation_base *base, REFIID iid, void **handler )
{
    IAsyncActionCompletedHandler *wrapper;
    HRESULT hr;

    *handler = NULL;
    hr = IAsyncAction_get_Completed( base->inner_action, &wrapper );
    TRACE("hr = %#lx, inner: %p, wrapper: %p\n", hr, base->inner_action, wrapper);
    if (FAILED( hr ) || !wrapper)
        return hr;

    hr = IAsyncActionCompletedHandler_QueryInterface( wrapper, iid, (void **)handler );
    IAsyncActionCompletedHandler_Release( wrapper );
    return hr;
}

struct work_item
{
    IWorkItemHandler IWorkItemHandler_iface;
    async_operation_callback callback;
    PROPVARIANT *result;

    IUnknown *invoker;
    IUnknown *param;
    LONG ref;
};

static inline struct work_item *impl_from_IWorkItemHandler( IWorkItemHandler *iface )
{
    return CONTAINING_RECORD( iface, struct work_item, IWorkItemHandler_iface );
}

static HRESULT WINAPI work_item_QueryInterface( IWorkItemHandler *iface, REFIID iid, void **out )
{
    TRACE( "iface %p, iid %s, out %p.\n", iface, debugstr_guid( iid ), out );

    if (IsEqualGUID( iid, &IID_IUnknown ) ||
        IsEqualGUID( iid, &IID_IInspectable ) ||
        IsEqualGUID( iid, &IID_IWorkItemHandler ))
    {
        *out = iface;
        IUnknown_AddRef( (IUnknown *)*out );
        return S_OK;
    }

    *out = NULL;
    FIXME( "%s not implemented, returning E_NOINTERFACE.\n", debugstr_guid( iid ) );
    return E_NOINTERFACE;
}

static ULONG WINAPI work_item_AddRef( IWorkItemHandler *iface )
{
    struct work_item *impl = impl_from_IWorkItemHandler( iface );
    ULONG ref = InterlockedIncrement( &impl->ref );
    TRACE( "iface %p, ref %lu.\n", iface, ref );
    return ref;
}

static ULONG WINAPI work_item_Release( IWorkItemHandler *iface )
{
    struct work_item *impl = impl_from_IWorkItemHandler( iface );
    ULONG ref = InterlockedDecrement( &impl->ref );
    TRACE( "iface %p, ref %lu.\n", iface, ref );

    if (!ref)
    {
        if (impl->invoker)
            IUnknown_Release( impl->invoker );
        if (impl->param)
            IUnknown_Release( impl->param );
        free( impl );
    }
    return ref;
}

static HRESULT WINAPI work_item_Invoke( IWorkItemHandler *iface, IAsyncAction *action )
{
    struct work_item *impl = impl_from_IWorkItemHandler( iface );
    IAsyncInfo *info;
    AsyncStatus status;
    HRESULT hr;

    TRACE( "iface %p, action %p.\n", iface, action );

    hr = IAsyncAction_QueryInterface( action, &IID_IAsyncInfo, (void **)&info );
    if (FAILED( hr ))
        return hr;

    hr = IAsyncInfo_get_Status( info, &status );
    IAsyncInfo_Release( info );
    if (FAILED( hr ))
        return hr;

    return status != Canceled ? impl->callback( impl->invoker, impl->param, impl->result ) : S_OK;
}

static const IWorkItemHandlerVtbl work_item_vtbl =
{
    work_item_QueryInterface,
    work_item_AddRef,
    work_item_Release,
    work_item_Invoke,
};

static HRESULT work_item_create( IUnknown *invoker, IUnknown *param, async_operation_callback callback,
                                 PROPVARIANT *result, IWorkItemHandler **handler )
{
    struct work_item *impl;

    impl = calloc( 1, sizeof( *impl ) );
    if (!impl)
        return E_OUTOFMEMORY;

    impl->IWorkItemHandler_iface.lpVtbl = &work_item_vtbl;
    impl->callback = callback;
    impl->result = result;
    impl->invoker = invoker;
    impl->param = param;
    if (invoker)
        IUnknown_AddRef(invoker);
    if (param)
        IUnknown_AddRef(param);
    impl->ref = 1;

    *handler = &impl->IWorkItemHandler_iface;
    return S_OK;
}

struct async_bool
{
    IAsyncOperation_boolean IAsyncOperation_boolean_iface;
    struct async_operation_base base;
};

static inline struct async_bool *impl_from_IAsyncOperation_boolean( IAsyncOperation_boolean *iface )
{
    return CONTAINING_RECORD( iface, struct async_bool, IAsyncOperation_boolean_iface );
}

static HRESULT WINAPI async_bool_QueryInterface( IAsyncOperation_boolean *iface, REFIID iid, void **out )
{
    struct async_bool *impl = impl_from_IAsyncOperation_boolean( iface );

    TRACE( "iface %p, iid %s, out %p.\n", iface, debugstr_guid( iid ), out );

    if (IsEqualGUID( iid, &IID_IUnknown ) ||
        IsEqualGUID( iid, &IID_IInspectable ) ||
        IsEqualGUID( iid, &IID_IAgileObject ) ||
        IsEqualGUID( iid, &IID_IAsyncOperation_boolean ))
    {
        IInspectable_AddRef( (*out = &impl->IAsyncOperation_boolean_iface) );
        return S_OK;
    }

    return IAsyncAction_QueryInterface( impl->base.inner_action, iid, out );
}

static ULONG WINAPI async_bool_AddRef( IAsyncOperation_boolean *iface )
{
    struct async_bool *impl = impl_from_IAsyncOperation_boolean( iface );
    ULONG ref = InterlockedIncrement( &impl->base.ref );
    TRACE( "iface %p, ref %lu.\n", iface, ref );
    return ref;
}

static ULONG WINAPI async_bool_Release( IAsyncOperation_boolean *iface )
{
    struct async_bool *impl = impl_from_IAsyncOperation_boolean( iface );
    ULONG ref = InterlockedDecrement( &impl->base.ref );
    TRACE( "iface %p, ref %lu.\n", iface, ref );

    if (!ref)
    {
        IWorkItemHandler_Release(impl->base.work_item);
        IAsyncAction_Release( impl->base.inner_action );
        free( impl );
    }

    return ref;
}

static HRESULT WINAPI async_bool_GetIids( IAsyncOperation_boolean *iface, ULONG *iid_count, IID **iids )
{
    FIXME( "iface %p, iid_count %p, iids %p stub!\n", iface, iid_count, iids );
    return E_NOTIMPL;
}

static HRESULT WINAPI async_bool_GetRuntimeClassName( IAsyncOperation_boolean *iface, HSTRING *class_name )
{
    return WindowsCreateString( L"Windows.Foundation.IAsyncOperation`1<Boolean>",
                                ARRAY_SIZE(L"Windows.Foundation.IAsyncOperation`1<Boolean>"),
                                class_name );
}

static HRESULT WINAPI async_bool_GetTrustLevel( IAsyncOperation_boolean *iface, TrustLevel *trust_level )
{
    FIXME( "iface %p, trust_level %p stub!\n", iface, trust_level );
    return E_NOTIMPL;
}

static HRESULT WINAPI async_bool_put_Completed( IAsyncOperation_boolean *iface, IAsyncOperationCompletedHandler_boolean *bool_handler )
{
    struct async_bool *impl = impl_from_IAsyncOperation_boolean( iface );

    TRACE( "iface %p, handler %p.\n", iface, bool_handler );

    return async_operation_put_Completed( &impl->base, (IInspectable *)iface, bool_handler );
}

static HRESULT WINAPI async_bool_get_Completed( IAsyncOperation_boolean *iface, IAsyncOperationCompletedHandler_boolean **bool_handler )
{
    struct async_bool *impl = impl_from_IAsyncOperation_boolean( iface );

    TRACE( "iface %p, handler %p.\n", iface, bool_handler );

    return async_operation_get_Completed( &impl->base, &IID_IAsyncOperationCompletedHandler_boolean, (void **)bool_handler );
}

static HRESULT WINAPI async_bool_GetResults( IAsyncOperation_boolean *iface, BOOLEAN *results )
{
    struct async_bool *impl = impl_from_IAsyncOperation_boolean( iface );
    PROPVARIANT result = {.vt = VT_BOOL};
    HRESULT hr;

    TRACE( "iface %p, results %p.\n", iface, results );

    hr = IAsyncAction_GetResults( impl->base.inner_action );
    if (hr == S_OK)
    {
        *results = impl->base.result.boolVal;
        PropVariantClear( &result );
    }

    return hr;
}

static const struct IAsyncOperation_booleanVtbl async_bool_vtbl =
{
    /* IUnknown methods */
    async_bool_QueryInterface,
    async_bool_AddRef,
    async_bool_Release,
    /* IInspectable methods */
    async_bool_GetIids,
    async_bool_GetRuntimeClassName,
    async_bool_GetTrustLevel,
    /* IAsyncOperation<boolean> */
    async_bool_put_Completed,
    async_bool_get_Completed,
    async_bool_GetResults,
};

static IThreadPoolStatics *threadpool_statics;
static INIT_ONCE threadpool_statics_init = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK init_threadpool_statics( INIT_ONCE *once, void *param, void **ctx )
{
    HSTRING str;
    HRESULT hr;

    hr = WindowsCreateString( RuntimeClass_Windows_System_Threading_ThreadPool,
                              wcslen( RuntimeClass_Windows_System_Threading_ThreadPool ), &str );
    if (FAILED( hr ))
        return FALSE;

    hr = RoGetActivationFactory( str, &IID_IThreadPoolStatics, (void **)&threadpool_statics );
    WindowsDeleteString( str );
    return SUCCEEDED( hr );
}

HRESULT async_operation_boolean_create( IUnknown *invoker, IUnknown *param, async_operation_callback callback,
                                        IAsyncOperation_boolean **out )
{
    struct async_bool *impl;
    HRESULT hr;

    *out = NULL;
    if (!InitOnceExecuteOnce( &threadpool_statics_init, init_threadpool_statics, NULL, NULL ))
        return E_FAIL;

    if (!(impl = calloc( 1, sizeof(*impl) ))) return E_OUTOFMEMORY;
    impl->IAsyncOperation_boolean_iface.lpVtbl = &async_bool_vtbl;

    hr = work_item_create( invoker, param, callback, &impl->base.result, &impl->base.work_item );
    if (FAILED( hr ))
    {
        free( impl );
        return hr;
    }
    impl->base.ref = 1;

    hr = IThreadPoolStatics_RunAsync( threadpool_statics, impl->base.work_item, &impl->base.inner_action );
    if (FAILED( hr ))
    {
        IWorkItemHandler_Release( impl->base.work_item );
        free( impl );
        return hr;
    }
    *out = &impl->IAsyncOperation_boolean_iface;
    TRACE( "created IAsyncOperation_boolean %p\n", *out );
    return S_OK;
}
