/*
 * Copyright 2022 Nikolay Sivov for CodeWeavers
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

#include <stdarg.h>
#include <assert.h>

#define COBJMACROS
#include "windef.h"
#include "winbase.h"
#include "winstring.h"
#include "wine/debug.h"
#include "objbase.h"

#include "initguid.h"
#include "activation.h"

#define WIDL_using_Windows_Foundation
#define WIDL_using_Windows_Foundation_Collections
#include "windows.foundation.h"
#define WIDL_using_Windows_System_Threading
#include "windows.system.threading.h"

WINE_DEFAULT_DEBUG_CHANNEL(threadpool);

#define Closed 4

struct threadpool_factory
{
    IActivationFactory IActivationFactory_iface;
    IThreadPoolStatics IThreadPoolStatics_iface;
    LONG refcount;
};

struct async_action
{
    IAsyncAction IAsyncAction_iface;
    IAsyncInfo IAsyncInfo_iface;

    UINT32 id;
    HRESULT hr;
    TP_WORK *work;
    IWorkItemHandler *work_item_handler;

    CRITICAL_SECTION cs;
    AsyncStatus status;
    LONG refcount;
};

static inline struct threadpool_factory *impl_from_IActivationFactory(IActivationFactory *iface)
{
    return CONTAINING_RECORD(iface, struct threadpool_factory, IActivationFactory_iface);
}

static inline struct threadpool_factory *impl_from_IThreadPoolStatics(IThreadPoolStatics *iface)
{
    return CONTAINING_RECORD(iface, struct threadpool_factory, IThreadPoolStatics_iface);
}

static inline struct async_action *impl_from_IAsyncAction(IAsyncAction *iface)
{
    return CONTAINING_RECORD(iface, struct async_action, IAsyncAction_iface);
}

static inline struct async_action *impl_from_IAsyncInfo(IAsyncInfo *iface)
{
    return CONTAINING_RECORD(iface, struct async_action, IAsyncInfo_iface);
}

static HRESULT STDMETHODCALLTYPE async_action_QueryInterface(IAsyncAction *iface, REFIID iid, void **out)
{
    struct async_action *action = impl_from_IAsyncAction(iface);

    TRACE("iface %p, iid %s, out %p.\n", iface, debugstr_guid(iid), out);

    if (IsEqualIID(iid, &IID_IAsyncAction)
            || IsEqualIID(iid, &IID_IInspectable)
            || IsEqualIID(iid, &IID_IUnknown))
    {
        *out = iface;
    }
    else if (IsEqualIID(iid, &IID_IAsyncInfo))
    {
        *out = &action->IAsyncInfo_iface;
    }
    else
    {
        *out = NULL;
        WARN("Unsupported interface %s.\n", debugstr_guid(iid));
        return E_NOINTERFACE;
    }

    IUnknown_AddRef((IUnknown *)*out);
    return S_OK;
}

static ULONG STDMETHODCALLTYPE async_action_AddRef(IAsyncAction *iface)
{
    struct async_action *action = impl_from_IAsyncAction(iface);
    ULONG refcount = InterlockedIncrement(&action->refcount);

    TRACE("iface %p, refcount %lu.\n", iface, refcount);

    return refcount;
}

static ULONG STDMETHODCALLTYPE async_action_Release(IAsyncAction *iface)
{
    struct async_action *action = impl_from_IAsyncAction(iface);
    ULONG refcount = InterlockedDecrement(&action->refcount);

    TRACE("iface %p, refcount %lu.\n", iface, refcount);

    if (!refcount)
    {
        IAsyncInfo_Close(&action->IAsyncInfo_iface);
        IWorkItemHandler_Release(action->work_item_handler);
        action->cs.DebugInfo->Spare[0] = 0;
        DeleteCriticalSection(&action->cs);
        free(action);
    }

    return refcount;
}

static HRESULT STDMETHODCALLTYPE async_action_GetIids(
        IAsyncAction *iface, ULONG *iid_count, IID **iids)
{
    FIXME("iface %p, iid_count %p, iids %p stub!\n", iface, iid_count, iids);

    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE async_action_GetRuntimeClassName(
        IAsyncAction *iface, HSTRING *class_name)
{
    FIXME("iface %p, class_name %p stub!\n", iface, class_name);

    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE async_action_GetTrustLevel(
        IAsyncAction *iface, TrustLevel *trust_level)
{
    FIXME("iface %p, trust_level %p stub!\n", iface, trust_level);

    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE async_action_put_Completed(IAsyncAction *iface, IAsyncActionCompletedHandler *handler)
{
    FIXME("iface %p, handler %p stub!\n", iface, handler);

    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE async_action_get_Completed(IAsyncAction *iface, IAsyncActionCompletedHandler **handler)
{
    FIXME("iface %p, handler %p stub!\n", iface, handler);

    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE async_action_GetResults(IAsyncAction *iface)
{
    struct async_action *action;
    HRESULT hr = E_ILLEGAL_METHOD_CALL;

    TRACE("iface %p\n", iface);

    action = impl_from_IAsyncAction(iface);
    EnterCriticalSection(&action->cs);
    if (action->status == Completed || action->status == Error)
        hr = S_OK;
    LeaveCriticalSection(&action->cs);

    return hr;
}

static const IAsyncActionVtbl async_action_vtbl =
{
    async_action_QueryInterface,
    async_action_AddRef,
    async_action_Release,
    async_action_GetIids,
    async_action_GetRuntimeClassName,
    async_action_GetTrustLevel,
    async_action_put_Completed,
    async_action_get_Completed,
    async_action_GetResults,
};

static HRESULT STDMETHODCALLTYPE async_info_QueryInterface(IAsyncInfo *iface, REFIID iid, void **out)
{
    struct async_action *action = impl_from_IAsyncInfo(iface);
    return IAsyncAction_QueryInterface(&action->IAsyncAction_iface, iid, out);
}

static ULONG STDMETHODCALLTYPE async_info_AddRef(IAsyncInfo *iface)
{
    struct async_action *action = impl_from_IAsyncInfo(iface);
    return IAsyncAction_AddRef(&action->IAsyncAction_iface);
}

static ULONG STDMETHODCALLTYPE async_info_Release(IAsyncInfo *iface)
{
    struct async_action *action = impl_from_IAsyncInfo(iface);
    return IAsyncAction_Release(&action->IAsyncAction_iface);
}

static HRESULT STDMETHODCALLTYPE async_info_GetIids(IAsyncInfo *iface, ULONG *iid_count, IID **iids)
{
    struct async_action *action = impl_from_IAsyncInfo(iface);
    return IAsyncAction_GetIids(&action->IAsyncAction_iface, iid_count, iids);
}

static HRESULT STDMETHODCALLTYPE async_info_GetRuntimeClassName(IAsyncInfo *iface, HSTRING *class_name)
{
    struct async_action *action = impl_from_IAsyncInfo(iface);
    return IAsyncAction_GetRuntimeClassName(&action->IAsyncAction_iface, class_name);
}

static HRESULT STDMETHODCALLTYPE async_info_GetTrustLevel(IAsyncInfo *iface, TrustLevel *trust_level)
{
    struct async_action *action = impl_from_IAsyncInfo(iface);
    return IAsyncAction_GetTrustLevel(&action->IAsyncAction_iface, trust_level);
}

static HRESULT STDMETHODCALLTYPE async_info_get_Id(IAsyncInfo *iface, UINT32 *id)
{
    struct async_action *action = impl_from_IAsyncInfo(iface);
    HRESULT hr = S_OK;

    TRACE("iface %p, id %p\n", iface, id);

    EnterCriticalSection(&action->cs);
    if (action->status == Closed)
        hr = E_ILLEGAL_METHOD_CALL;
    else
        *id = action->id;
    LeaveCriticalSection(&action->cs);

    return hr;
}

static HRESULT STDMETHODCALLTYPE async_info_get_Status(IAsyncInfo *iface, AsyncStatus *status)
{
    struct async_action *action = impl_from_IAsyncInfo(iface);
    HRESULT hr = S_OK;

    TRACE("iface %p, status %p\n", iface, status);

    EnterCriticalSection(&action->cs);
    if (action->status == Closed)
        hr = E_ILLEGAL_METHOD_CALL;
    *status = action->status;
    LeaveCriticalSection(&action->cs);

    return hr;
}

static HRESULT STDMETHODCALLTYPE async_info_get_ErrorCode(IAsyncInfo *iface, HRESULT *error_code)
{
    struct async_action *action = impl_from_IAsyncInfo(iface);
    HRESULT hr = S_OK;

    TRACE("iface %p, error_code %p\n", iface, error_code);

    EnterCriticalSection(&action->cs);
    if (action->status == Closed)
        *error_code = hr = E_ILLEGAL_METHOD_CALL;
    else
        *error_code = action->hr;
    LeaveCriticalSection(&action->cs);

    return hr;
}

static HRESULT STDMETHODCALLTYPE async_info_Cancel(IAsyncInfo *iface)
{
    struct async_action *action = impl_from_IAsyncInfo(iface);
    HRESULT hr = S_OK;

    TRACE("iface %p\n", iface);

    EnterCriticalSection(&action->cs);
    if (action->status == Closed)
        hr = E_ILLEGAL_METHOD_CALL;
    else if (action->status == Started)
        action->status = Canceled;
    LeaveCriticalSection(&action->cs);

    return hr;
}

static HRESULT STDMETHODCALLTYPE async_info_Close(IAsyncInfo *iface)
{
    struct async_action *action = impl_from_IAsyncInfo( iface );
    HRESULT hr = S_OK;

    TRACE("iface %p\n", iface);

    EnterCriticalSection(&action->cs);
    if (action->status == Started)
        hr = E_ILLEGAL_STATE_CHANGE;
    else if (action->status != Closed)
    {
        if (action->work)
            CloseThreadpoolWork( action->work );
        action->work = NULL;
        action->status = Closed;
    }
    LeaveCriticalSection(&action->cs);

    return hr;
}

static const IAsyncInfoVtbl async_info_vtbl =
{
    async_info_QueryInterface,
    async_info_AddRef,
    async_info_Release,
    async_info_GetIids,
    async_info_GetRuntimeClassName,
    async_info_GetTrustLevel,
    async_info_get_Id,
    async_info_get_Status,
    async_info_get_ErrorCode,
    async_info_Cancel,
    async_info_Close,
};


static void async_action_invoke_and_release(IAsyncAction *action_iface)
{
    struct async_action *action = impl_from_IAsyncAction(action_iface);
    HRESULT hr;

    hr = IWorkItemHandler_Invoke(action->work_item_handler, action_iface);

    EnterCriticalSection(&action->cs);
    action->hr = hr;
    if (action->status != Closed)
        action->status = FAILED(hr) ? Error : Completed;
    LeaveCriticalSection(&action->cs);
    IAsyncAction_Release(action_iface);
}

static void CALLBACK async_action_tp_callback(TP_CALLBACK_INSTANCE *inst, void *action_iface, TP_WORK *work)
{
    async_action_invoke_and_release(action_iface);
}

static DWORD CALLBACK async_action_sliced_proc(void *action_iface)
{
    async_action_invoke_and_release(action_iface);
    return 0;
}

static HRESULT async_action_create_and_start(TP_CALLBACK_ENVIRON *environment, WorkItemPriority priority,
                                             IWorkItemHandler *work_item, IAsyncAction **ret)
{
    struct async_action *object;
    static LONG async_action_id = 0;
    HANDLE thread = NULL;

    *ret = NULL;

    if (!(object = calloc(1, sizeof(*object))))
        return E_OUTOFMEMORY;

    object->IAsyncAction_iface.lpVtbl = &async_action_vtbl;
    object->IAsyncInfo_iface.lpVtbl = &async_info_vtbl;
    if (environment)
    {
        object->work = CreateThreadpoolWork(async_action_tp_callback, &object->IAsyncAction_iface, environment);
        if (!object->work)
        {
            ERR("Failed to create a thread pool work item: %lu.\n", GetLastError());
            free(object);
            return HRESULT_FROM_WIN32(GetLastError());
        }
    }
    else
    {
        thread = CreateThread(NULL, 0, async_action_sliced_proc, &object->IAsyncAction_iface, CREATE_SUSPENDED,
                              NULL);
        if (!thread)
        {
            ERR("Failed to create a thread: %lu\n", GetLastError());
            free(object);
            return HRESULT_FROM_WIN32(GetLastError());
        }
        if (priority != WorkItemPriority_Normal)
            SetThreadPriority(thread, priority == WorkItemPriority_High ? THREAD_PRIORITY_HIGHEST
                              : THREAD_PRIORITY_LOWEST);
    }
    object->id = InterlockedIncrement(&async_action_id);
    object->work_item_handler = work_item;
    IWorkItemHandler_AddRef(work_item);
    object->status = Started;
    InitializeCriticalSectionEx(&object->cs, 0, RTL_CRITICAL_SECTION_FLAG_FORCE_DEBUG_INFO);
    object->cs.DebugInfo->Spare[0] = (DWORD_PTR)(__FILE__": async_action.cs");
    object->refcount = 2;

    if (object->work)
        SubmitThreadpoolWork(object->work);
    else
    {
        ResumeThread(thread);
        CloseHandle(thread);
    }
    *ret = &object->IAsyncAction_iface;

    return S_OK;
}

struct thread_pool
{
    INIT_ONCE init_once;
    TP_CALLBACK_ENVIRON environment;
};

static struct thread_pool pools[3];

static BOOL CALLBACK pool_init_once(INIT_ONCE *init_once, void *param, void **context)
{
    struct thread_pool *pool = param;

    memset(&pool->environment, 0, sizeof(pool->environment));
    pool->environment.Version = 1;

    if (!(pool->environment.Pool = CreateThreadpool(NULL))) return FALSE;

    SetThreadpoolThreadMaximum(pool->environment.Pool, 10);

    return TRUE;
}

static HRESULT run_async(IWorkItemHandler *handler, WorkItemPriority priority, WorkItemOptions options,
        IAsyncAction **action)
{
    TP_CALLBACK_ENVIRON *environment = NULL;

    *action = NULL;

    if (!handler)
        return E_INVALIDARG;

    if (priority < WorkItemPriority_Low || priority > WorkItemPriority_High)
        return E_INVALIDARG;

    if (options != WorkItemOptions_TimeSliced)
    {
        struct thread_pool *pool = &pools[priority + 1];
        if (!InitOnceExecuteOnce(&pool->init_once, pool_init_once, pool, NULL))
            return E_FAIL;
        environment = &pools[priority + 1].environment;
    }

    return async_action_create_and_start(environment, priority, handler, action);
}

static HRESULT STDMETHODCALLTYPE threadpool_factory_QueryInterface(
        IActivationFactory *iface, REFIID iid, void **out)
{
    struct threadpool_factory *factory = impl_from_IActivationFactory(iface);

    TRACE("iface %p, iid %s, out %p.\n", iface, debugstr_guid(iid), out);

    if (IsEqualGUID(iid, &IID_IUnknown) ||
        IsEqualGUID(iid, &IID_IInspectable) ||
        IsEqualGUID(iid, &IID_IAgileObject) ||
        IsEqualGUID(iid, &IID_IActivationFactory))
    {
        IUnknown_AddRef(iface);
        *out = &factory->IActivationFactory_iface;
        return S_OK;
    }

    if (IsEqualGUID(iid, &IID_IThreadPoolStatics))
    {
        IUnknown_AddRef(iface);
        *out = &factory->IThreadPoolStatics_iface;
        return S_OK;
    }

    FIXME("%s not implemented, returning E_NOINTERFACE.\n", debugstr_guid(iid));
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE threadpool_factory_AddRef(IActivationFactory *iface)
{
    struct threadpool_factory *factory = impl_from_IActivationFactory(iface);
    ULONG refcount = InterlockedIncrement(&factory->refcount);

    TRACE("iface %p, refcount %lu.\n", iface, refcount);

    return refcount;
}

static ULONG STDMETHODCALLTYPE threadpool_factory_Release(IActivationFactory *iface)
{
    struct threadpool_factory *factory = impl_from_IActivationFactory(iface);
    ULONG refcount = InterlockedDecrement(&factory->refcount);

    TRACE("iface %p, refcount %lu.\n", iface, refcount);

    return refcount;
}

static HRESULT STDMETHODCALLTYPE threadpool_factory_GetIids(
        IActivationFactory *iface, ULONG *iid_count, IID **iids)
{
    FIXME("iface %p, iid_count %p, iids %p stub!\n", iface, iid_count, iids);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE threadpool_factory_GetRuntimeClassName(
        IActivationFactory *iface, HSTRING *class_name)
{
    FIXME("iface %p, class_name %p stub!\n", iface, class_name);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE threadpool_factory_GetTrustLevel(
        IActivationFactory *iface, TrustLevel *trust_level)
{
    FIXME("iface %p, trust_level %p stub!\n", iface, trust_level);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE threadpool_factory_ActivateInstance(
        IActivationFactory *iface, IInspectable **instance)
{
    FIXME("iface %p, instance %p stub!\n", iface, instance);
    return E_NOTIMPL;
}

static const struct IActivationFactoryVtbl threadpool_factory_vtbl =
{
    threadpool_factory_QueryInterface,
    threadpool_factory_AddRef,
    threadpool_factory_Release,
    /* IInspectable methods */
    threadpool_factory_GetIids,
    threadpool_factory_GetRuntimeClassName,
    threadpool_factory_GetTrustLevel,
    /* IActivationFactory methods */
    threadpool_factory_ActivateInstance,
};

static HRESULT STDMETHODCALLTYPE threadpool_statics_QueryInterface(
        IThreadPoolStatics *iface, REFIID iid, void **object)
{
    struct threadpool_factory *factory = impl_from_IThreadPoolStatics(iface);
    return IActivationFactory_QueryInterface(&factory->IActivationFactory_iface, iid, object);
}

static ULONG STDMETHODCALLTYPE threadpool_statics_AddRef(IThreadPoolStatics *iface)
{
    struct threadpool_factory *factory = impl_from_IThreadPoolStatics(iface);
    return IActivationFactory_AddRef(&factory->IActivationFactory_iface);
}

static ULONG STDMETHODCALLTYPE threadpool_statics_Release(IThreadPoolStatics *iface)
{
    struct threadpool_factory *factory = impl_from_IThreadPoolStatics(iface);
    return IActivationFactory_Release(&factory->IActivationFactory_iface);
}

static HRESULT STDMETHODCALLTYPE threadpool_statics_GetIids(
        IThreadPoolStatics *iface, ULONG *iid_count, IID **iids)
{
    FIXME("iface %p, iid_count %p, iids %p stub!\n", iface, iid_count, iids);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE threadpool_statics_GetRuntimeClassName(
        IThreadPoolStatics *iface, HSTRING *class_name)
{
    FIXME("iface %p, class_name %p stub!\n", iface, class_name);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE threadpool_statics_GetTrustLevel(
        IThreadPoolStatics *iface, TrustLevel *trust_level)
{
    FIXME("iface %p, trust_level %p stub!\n", iface, trust_level);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE threadpool_statics_RunAsync(
        IThreadPoolStatics *iface, IWorkItemHandler *handler, IAsyncAction **operation)
{
    TRACE("iface %p, handler %p, operation %p.\n", iface, handler, operation);

    return run_async(handler, WorkItemPriority_Normal, WorkItemOptions_None, operation);
}

static HRESULT STDMETHODCALLTYPE threadpool_statics_RunWithPriorityAsync(
        IThreadPoolStatics *iface, IWorkItemHandler *handler, WorkItemPriority priority, IAsyncAction **operation)
{
    TRACE("iface %p, handler %p, priority %d, operation %p.\n", iface, handler, priority, operation);

    return run_async(handler, priority, WorkItemOptions_None, operation);
}

static HRESULT STDMETHODCALLTYPE threadpool_statics_RunWithPriorityAndOptionsAsync(
        IThreadPoolStatics *iface, IWorkItemHandler *handler, WorkItemPriority priority,
        WorkItemOptions options, IAsyncAction **operation)
{
    TRACE("iface %p, handler %p, priority %d, options %d, operation %p.\n", iface, handler, priority, options, operation);

    return run_async(handler, priority, options, operation);
}

static const struct IThreadPoolStaticsVtbl threadpool_statics_vtbl =
{
    threadpool_statics_QueryInterface,
    threadpool_statics_AddRef,
    threadpool_statics_Release,
    /* IInspectable methods */
    threadpool_statics_GetIids,
    threadpool_statics_GetRuntimeClassName,
    threadpool_statics_GetTrustLevel,
    /* IThreadPoolStatics methods */
    threadpool_statics_RunAsync,
    threadpool_statics_RunWithPriorityAsync,
    threadpool_statics_RunWithPriorityAndOptionsAsync,
};

static struct threadpool_factory threadpool_factory =
{
    .IActivationFactory_iface.lpVtbl = &threadpool_factory_vtbl,
    .IThreadPoolStatics_iface.lpVtbl = &threadpool_statics_vtbl,
    .refcount = 1,
};

HRESULT WINAPI DllGetClassObject(REFCLSID clsid, REFIID riid, void **out)
{
    FIXME("clsid %s, riid %s, out %p stub!\n", debugstr_guid(clsid), debugstr_guid(riid), out);
    return CLASS_E_CLASSNOTAVAILABLE;
}

HRESULT WINAPI DllGetActivationFactory(HSTRING classid, IActivationFactory **factory)
{
    const WCHAR *name = WindowsGetStringRawBuffer(classid, NULL);

    TRACE("classid %s, factory %p.\n", debugstr_hstring(classid), factory);

    *factory = NULL;

    if (!wcscmp(name, RuntimeClass_Windows_System_Threading_ThreadPool))
    {
        *factory = &threadpool_factory.IActivationFactory_iface;
        IUnknown_AddRef(*factory);
    }

    if (*factory) return S_OK;
    return CLASS_E_CLASSNOTAVAILABLE;
}
